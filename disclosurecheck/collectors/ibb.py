import logging
import re
from functools import lru_cache
import csv
import requests
from packageurl import PackageURL
from packageurl.contrib.url2purl import url2purl
from disclosurecheck.util.context import Context
from ..util.normalize import normalize_packageurl, sanitize_github_url
from urlextract import URLExtract
from urllib.parse import urlparse
import requests_cache
from datetime import timedelta

logger = logging.getLogger(__name__)


def get_ibb_scopes():
    logger.debug("Retrieving IBB scopes")
    session = requests_cache.CachedSession("disclosurecheck_cache", expire_after=timedelta(days=7))
    res = session.get("https://hackerone.com/teams/ibb/assets/download_csv.csv", timeout=30)
    scope_items = []
    if res.ok:
        for row in csv.reader(res.text.splitlines(), delimiter=","):
            url = urlparse(row[0].strip())
            instruction_urls = set(URLExtract().find_urls(row[2]))
            instruction_emails = set(URLExtract(extract_email=True).find_urls(row[2])) - instruction_urls

            if url.netloc == "github.com":
                if url.path.count("/") == 1:
                    url_re = re.escape(f"pkg:github{url.path.lower()}/") + ".+"
                else:
                    url_re = re.escape(f"pkg:github{url.path.lower()}")
            else:
                url_re = re.escape(row[0].strip())

            scope_items.append(
                {
                    "regex": url_re,
                    "instruction_urls": instruction_urls,
                    "instruction_emails": instruction_emails,
                }
            )
    return scope_items


@lru_cache
def analyze_ibb(purl: PackageURL, context: Context):
    logger.debug("Checking project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    scope_items = get_ibb_scopes()
    logger.debug("Checking for %d IBB scope items", len(scope_items))

    for scope_item in scope_items:
        if re.match(scope_item["regex"], str(purl), re.IGNORECASE):
            context.add_contact(
                {
                    "priority": 5,
                    "type": "url",
                    "value": "https://hackerone.com/ibb",
                    "source": "Internet Bug Bounty",
                }
            )

            for url in scope_item["instruction_urls"]:
                context.add_contact(
                    {
                        "priority": 10,
                        "type": "url",
                        "value": url,
                        "source": "https://hackerone.com/ibb/policy_scopes",
                    }
                )

            for email in scope_item["instruction_emails"]:
                context.add_contact(
                    {
                        "priority": 10,
                        "type": "email",
                        "value": email,
                        "source": "https://hackerone.com/ibb/policy_scopes",
                    }
                )
