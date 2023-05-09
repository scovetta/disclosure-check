#!/usr/bin/env python
"""
Main entrypoint for the OpenSSF Vulnerability Disclosure Mechanism Detector.
"""
import requests_cache
import argparse
import sys
import logging
import copy
import importlib
from rich.logging import RichHandler
import json
from functools import lru_cache
from typing import Any, List
from urllib.parse import urlparse

import pkg_resources
import rich.console
from packageurl import PackageURL

from disclosurecheck import collectors
from disclosurecheck.collectors.github import analyze as analyze_github
from disclosurecheck.collectors.librariesio import analyze_librariesio
from disclosurecheck.collectors.packagecontent import analyze_packagecontent
from disclosurecheck.collectors.overrides import check_for_overrides
from disclosurecheck.collectors.ibb import analyze_ibb
from disclosurecheck.collectors.tidelift import analyze_tidelift
from disclosurecheck.util.normalize import clean_contacts, sanitize_github_url
from disclosurecheck.util.context import Context
from disclosurecheck.collectors.fallback import add_fallback_mechanisms

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

console = rich.console.Console(highlight=False)
VERSION = pkg_resources.get_distribution("disclosurecheck").version


class DisclosureCheck:
    context = None  # type: Context
    purl = None  # type: PackageURL

    def __init__(self, purl: PackageURL):
        if not purl:
            raise ValueError(f"purl [{purl}] is not a valid PackageURL.")

        self.context = Context(purl)
        self.purl = purl

    def execute(self):
        # Get the analyzer function based on the PackageURL type
        logger.debug("Starting execution for %s", self.purl)
        try:
            importlib.import_module(f"disclosurecheck.collectors.{self.purl.type}")
            if hasattr(collectors, self.purl.type):
                analysis_class = getattr(collectors, self.purl.type)
                logger.debug("Analyzing class %s", analysis_class.__name__)
                try:
                    analysis_class.analyze(self.purl, self.context)
                except Exception as msg:
                    logger.warning("Error analyzing using class %s: %s", analysis_class.__name__, msg)
            else:
                logger.debug(
                    "No analyzer found for PackageURL type %s. Will use generic analyzers.", self.purl.type
                )
        except Exception as msg:
            logger.warning("Error importing module for PackageURL type %s: %s", self.purl.type, msg)

        # Run package-agnostic analyzers
        for analyzer in [analyze_librariesio, analyze_tidelift, analyze_packagecontent, analyze_ibb]:
            try:
                analyzer(self.purl, self.context)
            except Exception as msg:
                logger.warning("Error analyzing %s using %s: %s", self.purl, analyzer.__name__, msg)

        # Add fallback mechanisms
        add_fallback_mechanisms(self.context)

        # For related packages (e.g. forks, repositories, etc.), analyze them
        _related_purls_copy = copy.copy(self.context.related_purls)
        for related_purl in _related_purls_copy:
            if related_purl.type == "github":
                analyze_github(related_purl, self.context)
                analyze_tidelift(related_purl, self.context)

        # Catch any additional related package URLs
        additional_purls = set(self.context.related_purls) - set(_related_purls_copy)
        for additional_purl in additional_purls:
            logger.debug("Found an additional PackageURL: %s", additional_purl)
            if additional_purl.type == "github":
                analyze_github(additional_purl, self.context)
                analyze_tidelift(additional_purl, self.context)

        # Any overrides
        for purl in self.context.related_purls:
            check_for_overrides(purl, self.context)

        check_for_overrides(self.purl, self.context)

        # Clean up the contacts and sort the final objects
        clean_contacts(self.context.contacts)
        self.context.sort()

    def get_results_json(self) -> str:
        return json.dumps(self.context.to_dict(), indent=2)

    def print_results_console(self) -> None:
        """Report results"""
        # Header
        console.print("[bold green]Package URL:[/bold green]", end="")
        console.print(f"[bold white][[/bold white] [bold yellow]{self.purl}[/bold yellow] ", end="")
        console.print("[bold white]][/bold white]")

        # Resources
        console.print("[bold green]Related Projects:[/bold green]")
        if self.context.related_purls:
            for related_purl in set(map(lambda s: str(s), self.context.related_purls)):
                console.print(f"  [bold yellow]*[/bold yellow] {related_purl}")
        else:
            console.print("  [cyan]No repositories found.[/cyan]")

        # Contacts
        console.print("[bold green]Preferred Contacts:[/bold green]")
        contact_seen = set()

        if self.context.contacts:
            for contact in self.context.contacts:
                priority = contact.get("priority")
                if priority < 20:
                    priority = "High"
                elif priority < 60:
                    priority = "Medium"
                elif priority < 100:
                    priority = "Low"
                elif priority == 100:
                    priority = "Generic"
                else:
                    priority = "Unknown"

                _type = contact.get("type")
                c = ""
                if _type == "email":
                    if "name" in contact and contact["name"]:
                        if "value" in contact:
                            c = f'{contact["name"]} <{contact["value"]}>'
                    elif "value" in contact:
                        c = contact["value"]

                elif _type == "github_pvr":
                    c = f"GitHub Private Vulnerability Reporting <{contact['value']}>"

                elif _type == "nuget_contact":
                    c = f"NuGet 'Contact Owner' Link <{contact['value']}"

                elif _type == "tidelift":
                    c = "Tidelift Security <security@tidelift.com>"

                elif _type == "url" and "value" in contact:
                    c = contact.get("value")

                elif _type == "social":
                    c = contact.get("value")

                else:
                    logger.warning("Unknown type: %s", _type)

                if c and c not in contact_seen:
                    contact_seen.add(c)
                    c = f"({priority}) {c}"
                    console.print(f"  [bold yellow]*[/bold yellow] {c}")

        if not contact_seen:
            console.print("  [cyan]Sorry, no contacts could be found.[/cyan]")

        # Notes
        if self.context.notes:
            console.print("[bold green]Other Notes:[/bold green]")
            for note in self.context.notes:
                console.print(f"  [bold yellow]*[/bold yellow] {note}")


def start():
    logging.basicConfig(format="%(message)s", handlers=[RichHandler()])
    logger = logging.getLogger("disclosurecheck")
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
        sys.exit(1)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Enable an in-memory cache, only if we're running as a script
    requests_cache.install_cache("disclosurecheck_cache", backend="memory", allowable_codes=[200, 404])

    dc = DisclosureCheck(purl)
    if not args.json:
        # fmt: off
        console.print("[red]OpenSSF Presents...")
        console.print("[bold blue]██▄   ▄█    ▄▄▄▄▄   ▄█▄    █    ████▄    ▄▄▄▄▄   ▄   █▄▄▄▄ ▄███▄       ▄█▄     ▄  █ ▄███▄   ▄█▄    █  █▀ ")
        console.print("[bold blue]█  █  ██   █     ▀▄ █▀ ▀▄  █    █   █   █     ▀▄  █  █  ▄▀ █▀   ▀      █▀ ▀▄  █   █ █▀   ▀  █▀ ▀▄  █▄█   ")
        console.print("[bold blue]█   █ ██ ▄  ▀▀▀▀▄   █   ▀  █    █   █ ▄  ▀▀▀▀▄ █   █ █▀▀▌  ██▄▄        █   ▀  ██▀▀█ ██▄▄    █   ▀  █▀▄   ")
        console.print("[bold blue]█  █  ▐█  ▀▄▄▄▄▀    █▄  ▄▀ ███▄ ▀████  ▀▄▄▄▄▀  █   █ █  █  █▄   ▄▀     █▄  ▄▀ █   █ █▄   ▄▀ █▄  ▄▀ █  █  ")
        console.print("[bold blue]███▀   ▐            ▀███▀      ▀               █▄ ▄█   █   ▀███▀       ▀███▀     █  ▀███▀   ▀███▀    █   ")
        console.print(f"[black]OpenSSF Disclosure Check v{VERSION}[black][bold blue]                 ▀▀▀   ▀                         ▀                   ▀    ")
        # fmt: on

    try:
        dc.execute()
    except:
        console.print_exception(show_locals=True)

    if args.json:
        print(dc.get_results_json())
    else:
        dc.print_results_console()

if __name__ == "__main__":
    start()
