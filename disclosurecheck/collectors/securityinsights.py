import logging
import re
from functools import lru_cache

import requests
import yaml
from packageurl import PackageURL

from disclosurecheck.util.context import Context
from ..util.normalize import sanitize_github_url

logger = logging.getLogger(__name__)


@lru_cache
def analyze_securityinsights(purl: PackageURL, context: Context) -> None:
    """Check a Security Insights spec for a security contact."""
    if not purl:
        logger.warning("Missing PackageURL.")
        return

    if purl.type != "github":
        logger.info("Only GitHub PackageURL types are enabled for a Security Insights check.")
        return

    logger.debug("Checking for a Security Insights specification.")
    url = f"https://raw.githubusercontent.com/{purl.namespace}/{purl.name}/master/SECURITY-INSIGHTS.yml"
    res = requests.get(url, timeout=30)

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
            context.add_contact({"priority": 0, "type": "email", "source": url, "value": email})
    else:
        logger.warning("Error loading URL [%s]: %s", url, res.status_code)
