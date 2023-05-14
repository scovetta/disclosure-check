import logging
import re
from functools import lru_cache

import requests
from packageurl import PackageURL

from disclosurecheck.util.context import Context
from ..util.normalize import normalize_packageurl, sanitize_github_url

logger = logging.getLogger(__name__)

NPM_REGISTRY = "https://registry.npmjs.org"


@lru_cache
def analyze(purl: PackageURL, context: Context) -> None:
    """Checks the npm registry for contact information for a package."""
    logger.debug("Checking npm project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return

    if purl.namespace:
        package_name = f"{purl.namespace}/{purl.name}"
    else:
        package_name = purl.name

    res = requests.get(f"{NPM_REGISTRY}/{package_name}", timeout=30)
    if res.ok:
        data = res.json()
        author_name = data.get("author", {}).get("name", "").strip()
        author_email = data.get("author", {}).get("email", "").strip()
        if author_email:
            context.add_contact(
                {
                    "priority": 50,
                    "type": "email",
                    "source": "npm registry (author)",
                    "name": author_name,
                    "value": author_email,
                }
            )

        for match in re.findall(r"\s(@[\w-]+)", author_name):
            context.add_contact(
                {
                    "priority": 70,
                    "type": "social",
                    "source": "npm registry (author/Twitter)",
                    "value": f"twitter:{match}",
                }
            )

        latest_tag = data.get("dist-tags", {}).get("latest")
        if latest_tag:
            latest = data.get("versions", {}).get(latest_tag, {})
            npm_name = latest.get("_npmUser", {}).get("name", "").strip()
            npm_email = latest.get("_npmUser", {}).get("email", "").strip()
            if npm_email:
                context.add_contact(
                    {
                        "priority": 45,
                        "type": "email",
                        "source": "npm registry (_npmUser)",
                        "name": npm_name,
                        "value": npm_email,
                    }
                )

            for maintainer in latest.get("maintainers", []):
                maintainer_name = maintainer.get("name", "")
                maintainer_email = maintainer.get("email", "")
                if maintainer_email:
                    context.add_contact(
                        {
                            "priority": 45,
                            "type": "email",
                            "source": "npm registry (latest.maintainer)",
                            "name": maintainer_name,
                            "value": maintainer_email,
                        }
                    )

        # All of the places a GitHub URL could hide in npm metadata
        urls = [
            sanitize_github_url(data.get("bugs", {}).get("url")),
            sanitize_github_url(data.get("repository", {}).get("url")),
            sanitize_github_url(data.get("homepage")),
        ]

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
