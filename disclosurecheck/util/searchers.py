import re
from functools import lru_cache
from urllib.parse import urlparse

from packageurl import PackageURL
from urlextract import URLExtract

from disclosurecheck.util.context import Context

from .normalize import sanitize_github_url


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
                    "priority": 65,
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
            context.contacts.append(
                {"priority": 65, "type": "email", "source": url, "value": match}
            )

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
                priority = 5

            if _url == "https://tidelift.com/security":
                context.contacts.append(
                    {
                        "priority": 5,
                        "type": "tidelift",
                        "value": "security@tidelift.com",
                        "source": sanitize_github_url(url),
                    }
                )
            else:
                context.contacts.append(
                    {
                        "priority": priority,
                        "type": "url",
                        "value": sanitize_github_url(_url),
                        "source": url,
                    }
                )
