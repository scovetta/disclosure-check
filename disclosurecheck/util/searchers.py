import logging
import re
from functools import lru_cache
from urllib.parse import urlparse

from packageurl import PackageURL
from urlextract import URLExtract
from validators.email import email as validate_email

from disclosurecheck.util.context import Context

from .normalize import sanitize_github_url

logger = logging.getLogger(__name__)


def find_contacts(url: str, text: str, context: Context):
    """Finds contacts in a string of text."""
    found_contacts = set()

    # E-mail addresses with names
    matches = set(re.findall(r"([a-z ]+) <([\w.+-]+(?:@|\[at\])[\w-]+\.[\w.-]+)>", text, re.IGNORECASE))
    for match in matches:
        email = match[1].replace("[at]", "@").strip()
        if email not in found_contacts:
            found_contacts.add(email)
            context.contacts.append(
                {
                    "priority": 25,
                    "type": "email",
                    "source": url,
                    "name": match[0].strip(),
                    "value": email,
                }
            )

    # Bare e-mail addresses
    matches = set(re.findall(r"[\w.+-]+(?:@|\[at\])[\w-]+\.[\w.-]+", text))
    for match in matches:
        match = match.replace("[at]", "@")
        if match not in found_contacts:
            found_contacts.add(match)
            context.contacts.append({"priority": 35, "type": "email", "source": url, "value": match})

    if "tidelift.com" in text:
        context.contacts.append(
            {
                "priority": 5,
                "type": "tidelift",
                "value": "security@tidelift.com",
                "source": sanitize_github_url(url),
            }
        )

    # Look for any URL in the file
    for _url in set(URLExtract().find_urls(text)):
        if _url.startswith("http"):
            priority = 70
            if re.match(r".*github(usercontent)?\.com/([^/]+)/\.github/.*", url, re.IGNORECASE):
                priority = 50

            if any(s in _url for s in ["security", "vulnerability", "reporting"]):
                priority = 10

            if re.match(r".*/github\.com/([^/]+)$", _url, re.IGNORECASE):
                logger.debug("Found a bare GitHub profile, ignoring.")

            elif re.match(r".*github\.com/.*/tags[/)\]\.]*$", _url):
                logger.debug("Found a tags page, ignoring.")

            elif re.match(r".*/security/advisories/new$", _url):
                context.contacts.append(
                    {
                        "priority": 0,
                        "type": "github_pvr",
                        "value": _url,
                        "source": url,
                    }
                )

            elif _url == "https://tidelift.com/security":
                context.contacts.append(
                    {
                        "priority": 5,
                        "type": "tidelift",
                        "value": "security@tidelift.com",
                        "source": url,
                    }
                )

            else:
                context.contacts.append(
                    {
                        "priority": priority,
                        "type": "url",
                        "value": _url,
                        "source": url,
                    }
                )


def extract_emails(text):
    """Extracts emails from a string of text."""
    extractor = URLExtract(extract_email=True)
    for email in extractor.find_urls(text):
        if validate_email(email):
            yield email
