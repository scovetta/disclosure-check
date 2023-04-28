import argparse
import logging
from typing import Any, List, MutableSet, Dict

import requests_cache
from packageurl import PackageURL

requests_cache.install_cache("disclosurecheck_cache", backend="memory", allowable_codes=[200, 404])

logger = logging.getLogger(__name__)


def check():
    logging.basicConfig(format="%(asctime)s %(levelname)s - %(message)s")
    logger.setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(prog="OpenSSF Vulnerability Disclosure Mechanism Detector")
    parser.add_argument("package_url", help="Package URL for the project/package you want to analyze.")
    parser.add_argument("--verbose", help="Show extra logging.", action="store_true")
    parser.add_argument("--json", help="Output as JSON.", action="store_true")
    args = parser.parse_args()
    try:
        purl = PackageURL.from_string(args.package_url)
    except:
        logger.fatal("Invalid PackageURL provided. For example, pkg:npm/left-pad or pkg:github/madler/zlib.")

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    from .check import DisclosureCheck

    DisclosureCheck(purl, output_json=args.json)


class Context:
    notes: MutableSet[str] = set()
    related_purls: MutableSet[PackageURL] = set()
    contacts: List[Dict[str, Any]] = []
