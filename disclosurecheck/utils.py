from __future__ import annotations
import re
from functools import lru_cache
from urllib.parse import urlparse

from packageurl import PackageURL
from urlextract import URLExtract
from typing import Dict, List

from disclosurecheck import Context


@lru_cache
def clean_url(url):
    if not url:
        return None

    if url.startswith("github.com/"):
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except Exception as msg:
        return None

    if parsed.hostname in ["raw.github.com", "raw.githubusercontent.com", "www.github.com"]:
        parsed = parsed._replace(netloc="github.com")

    if parsed.hostname != "github.com":
        return None

    path_parts = parsed.path.split("/")
    if len(path_parts) >= 3:
        new_path = "/".join(path_parts[1:3])
        parsed = parsed._replace(path=new_path)

    # Remove .git from the end
    if parsed.path.endswith(".git/"):
        parsed = parsed._replace(path=parsed.path[:-5])
    elif parsed.path.endswith(".git"):
        parsed = parsed._replace(path=parsed.path[:-4])

    parsed = parsed._replace(scheme="https", netloc=parsed.hostname, params="", query="", fragment="")

    return parsed.geturl()


def clean_contacts(contacts: List[Dict]):
    for contact in contacts:
        name = contact.get("name")
        email = contact.get("email")

        if email is not None and name in [None, "", "None", "null", "NULL"]:
            matches = re.match(r"^(.*)<([\w.+-]+@[\w-]+\.[\w.-]+)>\s*$", email)
            if matches:
                name = matches.group(1).strip()
                email = matches.group(2).strip()

        if name is not None and email in [None, "", "None", "null", "NULL"]:
            matches = re.match(r"^(.*)<([\w.+-]+@[\w-]+\.[\w.-]+)>\s*$", name)
            if matches:
                name = matches.group(1).strip()
                email = matches.group(2).strip()

        if name:
            contact["name"] = name
        if email:
            contact["email"] = email


def clean_url(url: str) -> str | None:
    if not url:
        return None

    if url.startswith("github.com/"):
        url = f"https://{url}"

    if url.endswith("."):
        url = url[:-1]

    return url


def normalize_packageurl(purl: PackageURL) -> PackageURL:
    if not purl:
        return None

    if purl.type == "github" and purl.name.endswith(".git"):
        purl = purl._replace(name=purl.name[:-4])

    purl = purl._replace(subpath=None)

    return purl


def find_contacts(url: str, text: str, context: Context):
    """Finds contacts in a string of text."""
    matches = set(re.findall(r"[\w.+-]+(?:@|\[at\])[\w-]+\.[\w.-]+", text))
    for match in matches:
        match = match.replace("[at]", "@")
        context.contacts.append({"priority": 65, "type": "email", "source": clean_url(url), "email": match})

    if "tidelift.com" in text:
        context.contacts.append(
            {
                "priority": 95,
                "type": "tidelift",
                "contact": "security@tidelift.com",
                "source": clean_url(url),
            }
        )

    # Look for any URL in the file
    for _url in set(URLExtract().find_urls(text)):
        if _url.startswith("http"):
            priority = 30
            if re.match(r".*github(usercontent)?\.com/([^/]+)/\.github/.*", url, re.IGNORECASE):
                priority = 95

            if _url == 'https://tidelift.com/security':
                context.contacts.append(
                    {
                        "priority": 95,
                        "type": "tidelift",
                        "contact": "security@tidelift.com",
                        "source": clean_url(url),
                    }
                )
            else:
                context.contacts.append(
                    {"priority": priority, "type": "url", "url": clean_url(_url), "source": clean_url(url)}
                )
