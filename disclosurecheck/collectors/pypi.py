import logging
import re
from functools import lru_cache

import requests
from packageurl import PackageURL

from disclosurecheck.util.normalize import normalize_packageurl
from disclosurecheck.util.searchers import extract_emails
from disclosurecheck.util.context import Context
from ..util.searchers import sanitize_github_url

logger = logging.getLogger(__name__)

PYPI_REGISTRY = "https://pypi.org"


@lru_cache
def analyze(purl: PackageURL, context: Context) -> None:
    """Checks pypi.org for contact information for a package."""
    logger.debug("Checking PyPI project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    if purl.type != "pypi":
        logger.debug("Invalid PackageURL type.")
        return

    if purl.namespace:
        logger.warning("Unexpected namespace for PackageURL: %s", purl)

    res = requests.get(f"{PYPI_REGISTRY}/pypi/{purl.name}/json", timeout=30)
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
                for _email in extract_emails(email):
                    logger.debug("Found an e-mail address (%s)", _email)
                    context.add_contact(
                        {
                            "priority": 20,
                            "type": "email",
                            "source": f"pypi registry ({prefix})",
                            "name": name,
                            "value": _email,
                        }
                    )

        # All of the places a GitHub URL could hide within PyPI package metadata
        urls = [
            sanitize_github_url(data.get("package_url")),
            sanitize_github_url(data.get("project_url")),
            sanitize_github_url(data.get("project_urls", {}).get("Homepage")),
            sanitize_github_url(data.get("project_urls", {}).get("Bug Tracker")),
            sanitize_github_url(data.get("project_urls", {}).get("CI")),
            sanitize_github_url(data.get("project_urls", {}).get("Source")),
            sanitize_github_url(data.get("project_urls", {}).get("Source Code")),
            sanitize_github_url(data.get("project_urls", {}).get("Tracker")),
        ]

        # Search for GitHub URLs
        for url in set(urls):
            if not url:
                continue
            logger.debug("Found a URL (%s)", url)
            matches = re.match(r".*github\.com/([^/]+)/([^/]+)?", url, re.IGNORECASE)
            if matches:
                context.related_purls.append(
                    normalize_packageurl(
                        PackageURL.from_string("pkg:github/" + matches.group(1) + "/" + matches.group(2))
                    )
                )
            else:
                logger.debug("URL was not a GitHub URL, ignoring.")
