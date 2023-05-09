import re
from copy import deepcopy
from typing import Any, List, MutableSet, Dict
from packageurl import PackageURL
from operator import itemgetter

class Context:
    package_url: PackageURL
    notes: List[str]
    related_purls: List[PackageURL]
    contacts: List[Dict[str, Any]]

    def __init__(self, package_url: PackageURL):
        if not isinstance(package_url, PackageURL):
            raise ValueError(f"package_url [{package_url}] is not a valid PackageURL.")

        self.package_url = package_url
        self.notes = []
        self.contacts = []
        self.related_purls = []

    def sort(self):
        self.contacts = [dict(t) for t in {tuple(d.items()) for d in self.contacts}]
        self.contacts = sorted(self.contacts, key=itemgetter('priority', 'type', 'value'))
        self.notes = sorted(set(self.notes))
        self.related_purls = sorted(set(self.related_purls))

        return self

    def clean_note(self, note: str) -> str:
        if note:
            return re.sub(r"\[[^\]]*\]", "", note).replace("  ", " ")
        else:
            return note

    def to_dict(self):
        return {
            "package_url": str(self.package_url),
            "contacts": self.contacts,
            "related_purls": list(sorted(set(str(s) for s in self.related_purls if str(s) != str(self.package_url)))),
            "notes": sorted(map(self.clean_note, self.notes))
        }