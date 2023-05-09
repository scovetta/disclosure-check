import logging
import os
import re
import shutil
import subprocess
import tempfile
from functools import lru_cache

from packageurl import PackageURL

from disclosurecheck.util.context import Context
from disclosurecheck.util.normalize import (normalize_packageurl,
                                            sanitize_github_url)
from disclosurecheck.util.searchers import find_contacts

logger = logging.getLogger(__name__)


@lru_cache
def analyze_packagecontent(purl: PackageURL, context: Context) -> None:
    """Checks the package content for indicators of a reporting mechanism."""
    logger.debug("Checking package content for project: %s", purl)
    temp_dir = tempfile.mkdtemp(prefix="dc-")
    temp_env = os.environ.copy()
    temp_env["GIT_TERMINAL_PROMPT"] = "0"

    try:
        res = subprocess.run(["oss-download", "-e", "-x", temp_dir, str(purl)], capture_output=True, env=temp_env)
    except Exception as msg:
        logger.error(f"Error running oss-download, is it installed?: %s", msg)
        return

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
        re.compile(r".*/DESCRIPTION$", re.IGNORECASE),
    ]

    if any([regex.match(filename) for regex in SEARCH_FILES]):
        try:
            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            find_contacts(os.path.basename(filename), content, context)
        except Exception as msg:
            logger.warning("Error reading file [%s]: %s", filename, msg)
