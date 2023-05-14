import logging
import re
from functools import lru_cache

import requests
from packageurl import PackageURL

from disclosurecheck.util.context import Context
from disclosurecheck.util.normalize import normalize_packageurl, sanitize_github_url

logger = logging.getLogger(__name__)

NUGET_WEBSITE = "https://www.nuget.org"


@lru_cache
def analyze(purl: PackageURL, context: Context):
    logger.debug("Checking NuGet project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    url = f"{NUGET_WEBSITE}/packages/{purl.name}"
    urls = []
    res = requests.get(url, timeout=30)
    if res.ok:
        for line in res.text.splitlines():
            if any([t in line for t in ["outbound-repository-url", "outbound-project-url"]]):
                matches = re.match(r'.*href="([^"]+)"', line)
                if matches:
                    urls.append(sanitize_github_url(matches.group(1)))

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
    else:
        logger.warning("Error loading NuGet page for %s, error code=%d", purl, res.status_code)

    # In addition, all NuGet packages have a way to contact the author (web page)
    logger.debug("Package was NuGet, so adding the NuGet package contact page.")
    context.add_contact(
        {
            "priority": 40,
            "type": "url",
            "value": f"https://www.nuget.org/packages/{purl.name}/ContactOwners",
            "source": "https://learn.microsoft.com/en-us/nuget/nuget-org/nuget-org-faq#what-are-the-default-license-terms-if-a-package-doesn-t-provide-specific-license-information",
        }
    )
