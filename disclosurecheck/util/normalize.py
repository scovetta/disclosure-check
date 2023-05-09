from __future__ import annotations
import re
from functools import lru_cache
from urllib.parse import urlparse

from packageurl import PackageURL
from urlextract import URLExtract
from typing import Dict, List

from disclosurecheck.util.context import Context


@lru_cache
def sanitize_github_url(url):
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

    # TODO: This is definitely a bug
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
        email = contact.get("value")

        if email not in [None, ""] and name in [None, "", "None", "null", "NULL"]:
            matches = re.match(r"^(.*)<([\w.+-]+@[\w-]+\.[\w.-]+)>\s*$", email)
            if matches:
                name = matches.group(1).strip()
                email = matches.group(2).strip()

        if name not in [None, ""] and email in [None, "", "None", "null", "NULL"]:
            matches = re.match(r"^(.*)<([\w.+-]+@[\w-]+\.[\w.-]+)>\s*$", name)
            if matches:
                name = matches.group(1).strip()
                email = matches.group(2).strip()

        if name:
            contact["name"] = name
        if email:
            contact["value"] = email

        if '@googlegroups.com' in email:
            contact["priority"] = 99


def normalize_packageurl(purl: PackageURL) -> PackageURL:
    if not purl:
        return None

    if purl.type == "github" and purl.name.endswith(".git"):
        purl = purl._replace(name=purl.name[:-4])

    purl = purl._replace(subpath=None)

    return purl
