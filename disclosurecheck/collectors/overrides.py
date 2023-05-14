import sys
import json
import os
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

@lru_cache
def check_for_overrides(purl: PackageURL, context: Context) -> bool:
    """Checks to see if an override file exists, and if so, processes it.
    If an override was processed, return should be True, otherwise False.
    """
    logger.debug("Checking project: %s", purl)
    if purl is None:
        logger.debug("Invalid PackageURL.")
        return False

    file_paths = []


    path = os.path.join(os.path.dirname(__file__), '..', 'overrides', purl.type)

    # $type/_.json
    file_paths.append(os.path.join(path, '_.json'))

    if purl.namespace:
        # $type/$namespace.json
        file_paths.append(os.path.join(path, purl.namespace + '.json'))
        path = os.path.join(path, purl.namespace)
    path = os.path.join(path, purl.name)

    if purl.version:
        # $type/$namespace/$name/$version.json
        file_paths.append(os.path.join(path, purl.version) + '.json')

    # $type/$namespace/$name.json
    file_paths.append(path + '.json')

    for path in file_paths:
        logger.debug("Looking for override file: %s", os.path.abspath(path))
        if not os.path.abspath(path).startswith(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'overrides'))):
            logger.warning("Attempted to load override file outside of overrides directory: %s", path)
            return False

        if os.path.exists(path):
            logger.debug("File exists, loading.")
            with open(path, 'r') as f:
                override_data = json.load(f)

            for target_regex in override_data.get('match_regex', []):
                logger.debug("Checking target regex: %s", target_regex)
                if re.match(target_regex, str(purl), re.IGNORECASE):
                    logger.debug("Was a match!")

                    if override_data.get('action') == 'replace':
                        logger.debug("Clearing existing contacts since action was replace.")
                        context.contacts.clear()

                    context.contacts.extend(override_data.get('contacts', []))
                    context.notes.extend(override_data.get('notes', []))
                    context.related_purls.extend(override_data.get('related_purls', []))

                    return True
