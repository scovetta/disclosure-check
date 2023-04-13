#!/usr/bin/env python
"""
Main entrypoint for the OpenSSF Vulnerability Disclosure Mechanism Detector.
"""

import argparse
import logging
import os
import re
import sys
from functools import lru_cache
from urllib.parse import urlparse

import requests
import rich.console
import yaml
from github import Github
from packageurl import PackageURL

logging.basicConfig(format="%(asctime)s %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

console = rich.console.Console(highlight=False)
VERSION = "0.1.1"


class Check:
    notes = []
    results = {}
    related_purls = set()
    contacts = []

    def __init__(self, purl: PackageURL):
        if not purl:
            raise ValueError("purl is not a valid PackageURL.")

        self.github_token = os.environ.get("GITHUB_TOKEN")
        if not self.github_token:
            logger.warning(
                "Missing GITHUB_TOKEN. Important functionality will not work unless this environment variable is defined."
            )
        else:
            gh = Github(self.github_token)
            rate_limit = gh.get_rate_limit()
            logger.debug("GitHub Rate Limits: %s, %s", rate_limit, rate_limit.search)
            if rate_limit.search.remaining == 0 or rate_limit.core.remaining == 0:
                console.printf(
                    "[bold red]RATE LIMIT[/bold red] You have exceeded your GitHub API rate limit. Please try again later."
                )
                sys.exit(1)

        check_func = getattr(self, f"analyze_{purl.type}", None)
        if not check_func:
            logger.warning(
                "PackageURL type=%s is not currently supported. Pull requests welcome.",
                purl.type,
            )

        check_func(purl)
        self.analyze_tidelift(purl)

        for related_purl in self.related_purls.copy():
            if related_purl.type == "github":
                self.analyze_github(related_purl)
                self.analyze_tidelift(related_purl)

        self.report_results_console(purl)

    def report_results_console(self, purl: PackageURL):
        """Report results"""

        console.print(
            f"[bold yellow]OpenSSF - [/bold yellow][bold green]Detected Vulnerability Reporting Mechanisms v{VERSION}[/bold green]"
        )
        console.print("------------------------------------------------------------")
        console.print(f"[bold green]Package URL: [/bold green][yellow]{purl}[/yellow]")

        # Resources
        console.print("[bold green]Related Projects:[/bold green]")
        if self.related_purls:
            for related_purl in self.related_purls:
                console.print(f"  [magenta]*[/magenta] {related_purl}")
        else:
            console.print("  [cyan]No repositories found.[/cyan]")

        # Results
        console.print("[bold green]Results:[/bold green]")

        # GitHub Private Vulnerability Reporting
        if any((k.get("type") == "github_pvr" for k in self.contacts)):
            console.print(
                "  [[yellow]✓[/yellow]] Private vulnerability reporting is enabled for this repository."
            )
        else:
            console.print(
                "  [[red]✗[/red]] Private vulnerability reporting is [bold red]NOT[/bold red] enabled for this repository."
            )

        # Tidelift
        if any((k.get("type") == "tidelift" for k in self.contacts)):
            console.print(
                "  [[yellow]✓[/yellow]] Tidelift accepts vulnerability reports for this repository (security@tidelift.com)"
            )
        else:
            console.print(
                "  [[red]✗[/red]] Tidelift does [bold red]NOT[/bold red] accept vulnerability reports for this repository."
            )

        # E-Mail Contacts
        console.print("[bold green]Potential Contacts:[/bold green]")
        contact_seen = set()
        if self.contacts:
            for contact in self.contacts:
                c = None
                if "name" in contact:
                    if "email" in contact:
                        c = f'{contact["name"]} <{contact["email"]}>'
                elif "email" in contact:
                    c = contact["email"]
                if c:
                    if c in contact_seen:
                        continue
                    contact_seen.add(c)
                    console.print(f"  [magenta]*[/magenta] {c}")
        if not contact_seen:
            console.print("  [cyan]Sorry, no contacts could be found.[/cyan]")

        # Notes
        console.print("[bold green]Other Notes:[/bold green]")
        if self.notes:
            for note in self.notes:
                console.print(f"  [bold yellow]*[/bold yellow] {note}")
        else:
            console.print("  [cyan]No other notes.[/cyan]")

        # print(json.dumps(self.results, indent=2))

    @lru_cache(maxsize=None)
    def analyze_github(self, purl: PackageURL) -> None:
        """Identifies available disclosure mechanisms for a GitHub repository."""
        logger.debug("Checking GitHub repository: %s", purl)
        if not purl:
            logging.debug("Invalid PackageURL")
            return

        if not self.github_token:
            logger.warning(
                "Unable to analyze GitHub repository without a GITHUB_TOKEN."
            )
            return

        gh = Github(self.github_token)
        self.related_purls.add(purl)

        try:
            repo_obj = gh.get_repo(f"{purl.namespace}/{purl.name}")
        except:
            logger.warning(
                f"Unable to access GitHub repository: {purl.namespace}/{purl.name}"
            )
            return

        _org = repo_obj.owner.login
        _repo = repo_obj.name
        if _org != purl.namespace or _repo != purl.name:
            self.notes.append(
                f"Repository was moved from {purl.namespace}/{purl.name} to {_org}/{_repo}."
            )
            self.related_purls.add(
                PackageURL(type="github", namespace=_org, name=_repo)
            )

        # We probably don't want to report issues to a forked repository.
        if repo_obj.fork:
            self.notes.append(f"Repository {_org}/{_repo} is a fork.")

        if repo_obj.archived:
            self.notes.append(f"Repository {_org}/{_repo} has been archived.")

        # Check for private vulnerability reporting
        url = f"https://github.com/{_org}/{_repo}/security/advisories"
        res = requests.get(url, timeout=30)
        if "Report a vulnerability" in res.text:
            self.contacts.append({"priority": 100, "type": "github_pvr", "source": url})
            logger.info("Private vulnerability reporting is enabled.")

        # Check for a contact in a "security.md" in a well-known place (avoid the API call to code search)
        # for filename in ['SECURITY.md', 'security.md', 'Security.md', '.github/security.md', 'docs/security.md']:
        #    self.check_github_security_md(_org, _repo, filename=filename)

        # See if the repo supports Security Insights
        self.check_github_security_insights(
            PackageURL(type="github", namespace=_org, name=_repo)
        )

        # Try searching for security.md files and related
        logger.debug(
            "Executing GitHub code search to find SECURITY.md or similar files."
        )
        files = gh.search_code(
            f"repo:{_org}/{_repo} path:/(^|\/)(readme|security)(\.(md|rst|txt))?$/i"
        )
        num_files_left = 30
        for file in files:
            num_files_left -= 1
            if num_files_left == 0:
                break
            logger.debug("Searching content of [%s]", file.name)
            content = file.decoded_content.decode("utf-8")
            matches = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", content))
            for match in matches:
                self.contacts.append(
                    {
                        "priority": 70,
                        "type": "email",
                        "source": file.url,
                        "email": match,
                    }
                )

    @lru_cache(maxsize=None)
    def analyze_tidelift(self, purl: PackageURL):
        """Check a PackageURL to see if it contains reference to Tidelift"""
        if not purl:
            logger.warning("Missing PackageURL.")
            return

        if purl.namespace:
            suffix = purl.namespace.replace("@", ".") + "-" + purl.name
        else:
            suffix = purl.name

        url = "https://tidelift.com/subscription/pkg/{purl.type}-{suffix}"
        res = requests.get(url)
        if res.ok:
            self.contacts.append(
                {
                    "confidence": 100,
                    "type": "tidelift",
                    "contact": "security@tidelift.com",
                    "evidence": [url],
                }
            )

        if purl.type == "github":
            logger.info("Searching for Tidelift references in the GitHub repository.")
            if not self.github_token:
                logger.warning(
                    "Unable to search GitHub for a Tidelift subscription without a GITHUB_TOKEN"
                )
                return

            gh = Github(self.github_token)
            repo_obj = gh.get_repo(
                f"{purl.namespace}/{purl.name}"
            )  # Handle renames, since code search 422s out
            query = f"repo:{repo_obj.owner.login}/{repo_obj.name} (security@tidelift.com OR tidelift.com/security)"
            logger.debug("Searching for [%s]", query)
            files = gh.search_code(query)
            if files:
                self.contacts.append(
                    {
                        "confidence": 50,
                        "type": "tidelift",
                        "contact": "security@tidelift.com",
                        "evidence": [f.name for f in files],
                    }
                )

    @lru_cache(maxsize=None)
    def check_github_security_insights(self, purl: PackageURL):
        """Check a Security Insights spec for a security contact."""
        if not purl:
            logger.warning("Missing PackageURL.")
            return

        if purl.type != "github":
            logger.info(
                "Only GitHub PackageURL types are enabled for a Security Insights check."
            )
            return

        logger.debug("Checking for a Security Insights specification.")
        url = f"https://raw.githubusercontent.com/{purl.namespace}/{purl.name}/master/SECURITY-INSIGHTS.yml"
        res = requests.get(url)
        if res.ok:
            logger.debug("Found a Security Insights specification.")
            data = yaml.safe_load(res.text)
            security_contacts = data.get("security-contacts")
            for security_contact in security_contacts:
                if security_contact.get("type") != "email":
                    continue
                email = security_contact.get("value")
                if not email:
                    continue
                self.contacts.append(
                    {"priority": 100, "type": "email", "source": url, "email": email}
                )

    # def check_github_security_md(self, org, repo, branch='master', filename='SECURITY.md'):
    #     found_match = False
    #     res = requests.get(f"https://raw.githubusercontent.com/{org}/{repo}/{branch}/{filename}")
    #     if res.status_code == 200:
    #         matches = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', res.text))
    #         for match in matches:
    #             self.contacts.append({
    #                 'priority': 100,
    #                 'type': 'email',
    #                 'source': '{filename} in repository.',
    #                 'email': match
    #             })
    #             found_match = True

    #         if 'tidelift.com' in res.text:
    #             self.tidelift_enabled = 'true'
    #             found_match = True

    #     return found_match

    @lru_cache(maxsize=None)
    def analyze_pypi(self, purl: PackageURL):
        """Checks pypi.org for contact information for a package."""
        logger.debug("Checking PyPI project: %s", purl)
        if purl is None:
            logger.debug("Invalid PackageURL.")
            return

        if purl.type != "pypi":
            logger.debug("Invalid PackageURL type.")
            return

        res = requests.get(f"https://pypi.org/pypi/{purl.name}/json", timeout=30)
        if res.ok:
            data = res.json()
            if not data:
                return

            data = data.get("info")  # We only care about the 'info' dictionary
            if not data:
                return

            logger.debug("Processing project metadata.")

            for prefix in ["author", "maintainer"]:
                name = data.get(prefix)
                email = data.get(f"{prefix}_email")
                if email:
                    logger.debug("Found an e-mail address (%s)", email)
                    self.contacts.append(
                        {
                            "priority": 100,
                            "type": "email",
                            "source": f"pypi registry ({prefix})",
                            "name": name,
                            "email": email,
                        }
                    )

            urls = [
                self.clean_url(data.get("package_url")),
                self.clean_url(data.get("project_url")),
                self.clean_url(data.get("project_urls", {}).get("Homepage")),
                self.clean_url(data.get("project_urls", {}).get("Source")),
                self.clean_url(data.get("project_urls", {}).get("Tracker")),
            ]

            for url in set(urls):
                if not url:
                    continue
                logger.debug("Found a URL (%s)", url)
                matches = re.match(r".*github\.com/([^/]+)/([^/]+)", url, re.IGNORECASE)
                if matches:
                    self.related_purls.add(
                        PackageURL.from_string(
                            "pkg:github/" + matches.group(1) + "/" + matches.group(2)
                        )
                    )
                else:
                    logger.debug("URL was not a GitHub URL, ignoring.")

    @lru_cache(maxsize=None)
    def analyze_npm(self, purl: PackageURL):
        """Checks the npm registry for contact information for a package."""
        logger.debug("Checking npm project: %s", purl)
        if purl is None:
            logger.debug("Invalid PackageURL.")
            return

        if purl.namespace:
            package_name = f"{purl.namespace}/{purl.name}"
        else:
            package_name = purl.name

        res = requests.get(f"https://registry.npmjs.org/{package_name}", timeout=30)
        if res.ok:
            data = res.json()
            author_name = data.get("author", {}).get("name", "").strip()
            author_email = data.get("author", {}).get("email", "").strip()
            if author_email:
                self.contacts.append(
                    {
                        "priority": 100,
                        "type": "email",
                        "source": "npm registry (author)",
                        "name": author_name,
                        "email": author_email,
                    }
                )

            for match in re.findall(r"\s(@[\w-]+)", author_name):
                self.contacts.append(
                    {
                        "priority": 100,
                        "type": "email",
                        "source": "npm registry (author/Twitter)",
                        "twitter": match,
                    }
                )

            latest_tag = data.get("dist-tags", {}).get("latest")
            if latest_tag:
                latest = data.get("versions", {}).get(latest_tag, {})
                npm_name = latest.get("_npmUser", {}).get("name", "").strip()
                npm_email = latest.get("_npmUser", {}).get("email", "").strip()
                if npm_email:
                    self.contacts.append(
                        {
                            "priority": 100,
                            "type": "email",
                            "source": "npm registry (_npmUser)",
                            "name": npm_name,
                            "email": npm_email,
                        }
                    )

                for maintainer in latest.get("maintainers", []):
                    maintainer_name = maintainer.get("name", "")
                    maintainer_email = maintainer.get("email", "")
                    if maintainer_email:
                        self.contacts.append(
                            {
                                "priority": 100,
                                "type": "email",
                                "source": "npm registry ($latest.maintainer)",
                                "name": maintainer_name,
                                "email": maintainer_email,
                            }
                        )

            urls = [
                self.clean_url(data.get("bugs", {}).get("url")),
                self.clean_url(data.get("repository", {}).get("url")),
                self.clean_url(data.get("homepage")),
            ]
            for url in set(urls):
                if not url:
                    continue
                logger.debug("Found a URL (%s)", url)
                matches = re.match(r".*github\.com/([^/]+)/([^/]+)", url, re.IGNORECASE)
                if matches:
                    self.related_purls.add(
                        PackageURL.from_string(
                            "pkg:github/" + matches.group(1) + "/" + matches.group(2)
                        )
                    )
                else:
                    logger.debug("URL was not a GitHub URL, ignoring.")

    @lru_cache(maxsize=None)
    def clean_url(self, url):
        if not url:
            return None
        if "github.com" not in url:
            return None

        if url.startswith("git+"):
            url = url[4:]
        if url.endswith(".git"):
            url = url[:-4]
        if "github.com" in url and url.endswith("/issues"):
            url = url[:-7]
        if url.startswith("ssh://git@"):
            url = "https://" + url[10:]
        parsed = urlparse(url)
        return "https://github.com" + parsed.path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="OpenSSF Vulnerability Disclosure Mechanism Detector"
    )
    parser.add_argument(
        "package_url", help="Package URL for the project/package you want to analyze."
    )
    parser.add_argument("--verbose", help="Show extra logging.", action="store_true")
    args = parser.parse_args()
    try:
        purl = PackageURL.from_string(args.package_url)
    except:
        logger.fatal(
            "Invalid PackageURL provided. For example, pkg:npm/left-pad or pkg:github/madler/zlib."
        )

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    Check(purl)
