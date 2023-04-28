import logging
import os
import re
from functools import lru_cache

import requests
from github import Github
from packageurl import PackageURL

from disclosurecheck.metadata.securityinsights import analyze_securityinsights
from disclosurecheck.utils import find_contacts, normalize_packageurl

from .. import Context
from ..utils import clean_url

logger = logging.getLogger(__name__)

NUGET_WEBSITE = "https://www.nuget.org"

COMMON_SECURITY_MD_PATHS = set([
	".github/security.adoc",
	".github/security.markdown",
	".github/security.rst",
    ".github/security.md",
    ".github/SECURITY.md",
	"doc/security.rst",
    "doc/security.md",
	"docs/security.adoc",
	"docs/security.markdown",
	"docs/security.md",
	"docs/security.rst",
	"security.adoc",
	"security.markdown",
	"security.rst",
    "security.md",
    "Security.md",
    "SECURITY.md",
    "%name%.gemspec"
])

MAX_CONTENT_SEARCH_FILES = 30


@lru_cache
def get_github_token():
    """Initialize the GitHub token and check to see if we're near our rate limit."""
    token_value = os.environ.get("GITHUB_TOKEN")
    if not token_value:
        logger.error("You do not have a GITHUB_TOKEN defined. Functionality will be limited.")
        return None

    gh = Github(token_value)
    rate_limit = gh.get_rate_limit()
    logger.debug(
        "GitHub Rate Limits: core remaining=%d, search remaining=%d",
        rate_limit.core.remaining,
        rate_limit.search.remaining,
    )
    if rate_limit.search.remaining == 0 or rate_limit.core.remaining == 0:
        logger.error("You have exceeded your GitHub API rate limit. Functionality will be limited.")
        return None

    return token_value

@lru_cache
def analyze(purl: PackageURL, context: Context) -> None:
    """Identifies available disclosure mechanisms for a GitHub repository."""
    logger.debug("Checking GitHub repository: %s", purl)
    if not purl:
        logging.debug("Invalid PackageURL")
        return

    github_token = get_github_token()
    if not github_token:
        logger.warning("Unable to analyze GitHub repository without a GITHUB_TOKEN.")
        return

    gh = Github(github_token)
    context.related_purls.add(normalize_packageurl(purl))

    try:
        repo_obj = gh.get_repo(f"{purl.namespace}/{purl.name}")
    except:
        logger.warning(f"Unable to access GitHub repository: {purl.namespace}/{purl.name}")
        return

    # We probably don't want to report issues to a forked repository.
    if repo_obj.fork:
        context.notes.add(f"Repository [bold blue]{purl.namespace}/{purl.name}[/bold blue] is a fork.")

    if repo_obj.archived:
        context.notes.add(f"Repository [bold blue]{purl.namespace}/{purl.name}[/bold blue] has been archived.")

    _org = repo_obj.owner.login
    _repo = repo_obj.name
    if _org.lower() != purl.namespace.lower() or _repo.lower() != purl.name.lower():
        context.notes.add(
            f"Repository was moved from [bold blue]{purl.namespace}/{purl.name}[/bold blue] to [bold blue]{_org}/{_repo}[/bold blue]."
        )
        context.related_purls.add(PackageURL(type="github", namespace=_org, name=_repo))
        logger.debug(f"Will resume analysis at {_org}/{_repo}.")
        return

    # Check for private vulnerability reporting
    url = f"https://github.com/{_org}/{_repo}/security/advisories"
    res = requests.get(url, timeout=30)
    if "Report a vulnerability" in res.text:
        context.contacts.append(
            {
                "priority": 100,
                "type": "github_pvr",
                "url": f"https://github.com/{_org}/{_repo}/security/advisories/new",
                "source": url,
            }
        )
        logger.info("Private vulnerability reporting is enabled.")

    # Check for a contact in a "security.md" in a well-known place (avoid the API call to code search)
    org_purl = PackageURL(type="github", namespace=purl.namespace, name=".github")
    for filename in COMMON_SECURITY_MD_PATHS:
        if '%name%' in filename:
            filename = filename.replace('%name%', purl.name)

        check_github_security_md(purl, filename, context)
        check_github_security_md(org_purl, filename, context)

    # See if the repo supports Security Insights
    analyze_securityinsights(purl, context)

    # Try searching for security.md files and related
    logger.debug("Executing GitHub code search to find SECURITY.md or similar files.")
    files = gh.search_code(f"repo:{_org}/{_repo} path:/(^|\/)(readme|security)(\.(md|rst|txt))?$/i")

    num_files_left = MAX_CONTENT_SEARCH_FILES
    for file in files:
        num_files_left -= 1
        if num_files_left == 0:
            break
        logger.debug("Searching content of [%s]", file.name)
        content = file.decoded_content.decode("utf-8")
        matches = set(re.findall(r"[\w.+-]+(@|\[at\])[\w-]+\.[\w.-]+", content))
        for match in matches:
            context.contacts.append(
                {
                    "priority": 40,
                    "type": "email",
                    "source": file.url,
                    "email": match,
                }
            )
    if num_files_left == MAX_CONTENT_SEARCH_FILES:
        logger.debug("No results found in GitHub code search.")

    # Try top committers
    # logger.debug("Searching for top committers.")
    # top_committers = repo_obj.get_contributors(order="desc", anon="true")
    # TODO


def check_github_security_md(purl: PackageURL, filename: str, context: Context):
    """Checks a "SECURITY.md" file for a security contact."""
    logger.debug("Checking GitHub [%s]: %s", filename, purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    if purl.type != "github":
        logger.debug("Sorry, only GitHub is supported.")
        return

    org = purl.namespace
    repo = purl.name

    url = f"https://raw.githubusercontent.com/{org}/{repo}/master/{filename}"
    res = requests.get(url, timeout=30)
    if res.ok:
        find_contacts(url, res.text, context)
    else:
        logger.warning("Error loading URL [%s]: %s", url, res.status_code)
