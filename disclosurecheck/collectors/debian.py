from bs4 import BeautifulSoup as bs4
import re
from functools import lru_cache
import logging

import requests
from packageurl import PackageURL

from disclosurecheck.util.normalize import normalize_packageurl
from disclosurecheck.util.searchers import extract_emails
from disclosurecheck.util.context import Context
from ..util.searchers import sanitize_github_url

logger = logging.getLogger(__name__)

DEBIAN_REGISTRY = "https://packages.debian.org"


@lru_cache
def analyze(purl: PackageURL, context: Context) -> None:
    """Checks pypi.org for contact information for a package."""
    logger.debug("Checking Debian project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    if purl.type != "debian":
        logger.debug("Invalid PackageURL type.")
        return

    if purl.namespace:
        logger.warning("Unexpected namespace for PackageURL: %s", purl)

    if isinstance(purl.qualifiers, dict) and 'distro_version' in purl.qualifiers:
        distro_version = purl.qualifiers.get('distro_version')
    else:
        distro_version = 'stable'

    url = f"{DEBIAN_REGISTRY}/{distro_version}/{purl.name}"

    logger.debug("Loading url: %s", url)
    res = requests.get(url, timeout=30)

    if res.ok:
        logger.debug("Processing project metadata.")
        bs = bs4(res.text, 'html.parser')
        for header in bs.find_all('h3'):
            if header.text in ['Maintainer:', 'Maintainers:']:
                for maintainer in header.find_next_sibling('ul').find_all('li'):
                    for anchor in maintainer.find_all('a'):
                        if anchor.get('href', '').startswith('mailto:'):
                            email = anchor.get('href')[7:]
                            logger.debug("Found an e-mail address: %s", email)
                            context.contacts.append(
                                {
                                    "priority": 20,
                                    "type": "email",
                                    "source": f"Debian registry (maintainer)",
                                    "name": anchor.text,
                                    "value": email,
                                }
                            )


