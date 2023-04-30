import logging
import os
import re
import shutil
import subprocess
import tempfile
from functools import lru_cache

from packageurl import PackageURL

from disclosurecheck.util.searchers import find_contacts
from disclosurecheck.util.normalize import normalize_packageurl, sanitize_github_url

from disclosurecheck.util.context import Context

logger = logging.getLogger(__name__)


@lru_cache
def analyze_packagecontent(purl: PackageURL, context: Context) -> None:
    """Checks the RubyGems registry for contact information for a package."""
    logger.debug("Checking RubyGems project: %s", purl)

    temp_dir = tempfile.mkdtemp(prefix="dc-")
    res = subprocess.run(["oss-download", "-e", "-x", temp_dir, str(purl)], capture_output=True)
    if res.returncode == 0:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                filename = os.path.join(root, file)
                analyze_file(filename, context)

        shutil.rmtree(temp_dir, ignore_errors=True)
    else:
        logger.warning("Error downloading package. Is OSS Gadget installed?")


def analyze_file(filename: str, context: Context) -> None:
    SEARCH_FILES = [
        re.compile(r".*\.gemspec$", re.IGNORECASE),
        re.compile(r".*/security\.", re.IGNORECASE),
        re.compile(r".*\.cabal$", re.IGNORECASE),
        re.compile(r".*/DESCRIPTION$", re.IGNORECASE)
    ]

    if any([regex.match(filename) for regex in SEARCH_FILES]):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
            find_contacts(os.path.basename(filename), content, context)
        except Exception as msg:
            logger.warning("Error reading file [%s]: %s", filename, msg)
