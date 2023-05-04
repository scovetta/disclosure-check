from copy import deepcopy
from typing import Any, List, MutableSet, Dict
from packageurl import PackageURL
from operator import itemgetter

class Context:
    notes: List[str]
    related_purls: List[PackageURL]
    contacts: List[Dict[str, Any]]

    def __init__(self):
        self.notes = []
        self.contacts = []
        self.related_purls = []

    def sort(self):
        self.contacts = [dict(t) for t in {tuple(d.items()) for d in self.contacts}]
        self.contacts = sorted(self.contacts, key=itemgetter('priority', 'type', 'value'))
        self.notes = sorted(set(self.notes))
        self.related_purls = sorted(set(self.related_purls))

        return self

    def to_dict(self):
        return {
            "notes": self.notes,
            "contacts": self.contacts,
            "related_purls": list(sorted(set(str(s) for s in self.related_purls)))
        }