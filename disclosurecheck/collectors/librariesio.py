import logging
import re
from functools import lru_cache

import requests
from packageurl import PackageURL

from disclosurecheck.util.context import Context
from ..util.normalize import normalize_packageurl, sanitize_github_url

logger = logging.getLogger(__name__)


@lru_cache
def analyze_librariesio(purl: PackageURL, context: Context):
    logger.debug("Checking project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    if purl.type == 'gem':
        purl = purl._replace(type='rubygems')

    if purl.namespace:
        if purl.type == "maven":
            package_name = f"{purl.namespace}:{purl.name}"
        else:
            package_name = f"{purl.namespace}/{purl.name}"
    else:
        package_name = purl.name

    url = f"https://libraries.io/api/{purl.type}/{package_name}"
    logger.debug("Loading URL: [%s]", url)

    res = requests.get(url, timeout=30)  # TODO Add API Token
    if res.ok:
        data = res.json()

        urls = [sanitize_github_url(data.get("repository_url"))]
        for url in set(urls):
            if not url:
                continue
            logger.debug("Found a URL (%s)", url)
            matches = re.match(r".*github\.com/([^/]+)/([^/]+)(\.git)?", url, re.IGNORECASE)
            if matches:
                context.related_purls.append(
                    normalize_packageurl(
                        PackageURL.from_string("pkg:github/" + matches.group(1) + "/" + matches.group(2))
                    )
                )
            else:
                logger.debug("URL was not a GitHub URL, ignoring.")
    else:
        logger.warning("Error loading data from libraries.io, status code: %d", res.status_code)
        return
