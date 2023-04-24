#!/usr/bin/env python
"""
Main entrypoint for the OpenSSF Vulnerability Disclosure Mechanism Detector.
"""
import copy
import importlib
import json
from functools import lru_cache
from typing import Any, List
from urllib.parse import urlparse

import pkg_resources
import rich.console
from packageurl import PackageURL

from disclosurecheck import packagemanagers
from disclosurecheck.metadata.librariesio import analyze_librariesio
from disclosurecheck.metadata.tidelift import analyze_tidelift
from disclosurecheck.packagemanagers.github import analyze as analyze_github
from disclosurecheck.utils import clean_contacts, clean_url

from . import Context, logger

console = rich.console.Console(highlight=False)
VERSION = pkg_resources.get_distribution('disclosurecheck').version


class DisclosureCheck:
    context = None  # type: Context

    def __init__(self, purl: PackageURL, output_json: bool = False):
        if not purl:
            raise ValueError(f"purl [{purl}] is not a valid PackageURL.")

        self.context = Context()

        # Get the analyzer function based on the PackageURL type
        try:
            importlib.import_module(f"disclosurecheck.packagemanagers.{purl.type}")
            if hasattr(packagemanagers, purl.type):
                analysis_class = getattr(packagemanagers, purl.type)
                logger.debug("Analyzing class %s", analysis_class.__name__)
                try:
                    analysis_class.analyze(purl, self.context)
                except Exception as msg:
                    logger.warning("Error analyzing using class %s: %s", analysis_class.__name__, msg)
            else:
                logger.debug(
                    "No analyzer found for PackageURL type %s. Will use generic analyzers.", purl.type
                )
        except Exception as msg:
            logger.warning("Error importing module for PackageURL type %s: %s", purl.type, msg)

        # Analyze using the libraries.io API
        for analyzer in [analyze_librariesio, analyze_tidelift]:
            try:
                analyzer(purl, self.context)
            except Exception as msg:
                logger.warning("Error analyzing %s using %s: %s", purl, analyzer.__name__, msg)

        # For related packages (e.g. forks, repositories, etc.), analyze them
        _related_purls_copy = copy.copy(self.context.related_purls)
        for related_purl in _related_purls_copy:
            if related_purl.type == "github":
                analyze_github(related_purl, self.context)
                analyze_tidelift(related_purl, self.context)

        # Catch any additional related package URLs
        additional_purls = self.context.related_purls - _related_purls_copy
        for additional_purl in additional_purls:
            logger.debug("Found an additional PackageURL: %s", additional_purl)
            if additional_purl.type == "github":
                analyze_github(additional_purl, self.context)
                analyze_tidelift(additional_purl, self.context)

        # Clean up the contacts
        clean_contacts(self.context.contacts)

        # Report the results
        if output_json:
            data = {
                "contact": self.context.contacts,
                "notes": list(self.context.notes),
                "related_purls": list(map(lambda s: str(s), self.context.related_purls)),
            }
            print(json.dumps(data, indent=2))
        else:
            self.report_results_console(purl)

    def report_results_console(self, purl: PackageURL):
        """Report results"""

        # Header
        console.print(f"[bold white on blue]OpenSSF Disclosure Check v{VERSION}[/bold white on blue]")
        console.print("[bold green]Package URL:[/bold green]", end="")
        console.print(f"[bold white][[/bold white] [bold yellow]{purl}[/bold yellow] ", end="")
        console.print("[bold white]][/bold white]")

        # Resources
        console.print("[bold green]Related Projects:[/bold green]")
        if self.context.related_purls:
            for related_purl in self.context.related_purls:
                console.print(f"  [bold yellow]*[/bold yellow] {related_purl}")
        else:
            console.print("  [cyan]No repositories found.[/cyan]")

        # Contacts
        console.print("[bold green]Preferred Contacts:[/bold green]")
        contact_seen = set()
        if self.context.contacts:
            sorted_contacts = sorted(self.context.contacts, key=lambda c: c.get('priority', 0), reverse=True)
            for contact in sorted_contacts:
                priority = contact.get("priority", "???")
                _type = contact.get("type")
                c = ''
                if _type == "email":
                    if "name" in contact:
                        if "email" in contact:
                            c = f'{contact["name"]} <{contact["email"]}>'
                    elif "email" in contact:
                        c = contact["email"]

                elif _type == "github_pvr":
                    c = f"GitHub Private Vulnerability Reporting <{contact['url']}>"

                elif _type == "nuget_contact":
                    c = f"NuGet 'Contact Owner' Link <{contact['url']}"

                elif _type == 'tidelift':
                    c = "Tidelift Security <security@tidelift.com>"

                elif _type == "url" and "url" in contact:
                    c = contact.get("url")

                elif _type == 'social':
                    c = contact.get('value')

                else:
                    logger.warning("Unknown type: %s", _type)

                if c and c not in contact_seen:
                    contact_seen.add(c)
                    c = f"( {priority}% ) {c}"
                    console.print(f"  [bold yellow]*[/bold yellow] {c}")

        if not contact_seen:
            console.print("  [cyan]Sorry, no contacts could be found.[/cyan]")

        # Notes
        if self.context.notes:
            console.print("[bold green]Other Notes:[/bold green]")
            for note in self.context.notes:
                console.print(f"  [bold yellow]*[/bold yellow] {note}")
