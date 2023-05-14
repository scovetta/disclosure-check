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

    def add_contact(self, new_contact: Dict[str, Any]) -> None:
        """
        Adds a new contact in a smart way, consolidating contacts when they have the same type and value,
        taking the highest priority of the two, and meging the source and name fields.
        """
        for contact in self.contacts:
            # Consolidates contacts when they have the same type and value.
            if (contact['type'] == new_contact['type'] and contact['value'] == new_contact['value']):
                # Merge contacts
                if 'priority' in contact:
                    contact['priority'] = max(contact['priority'], new_contact['priority'])
                elif 'priority' in new_contact:
                    contact['priority'] = new_contact['priority']

                for key in (set(contact.keys()) | set(new_contact.keys())) - set(['type', 'value', 'priority']):
                    if key in contact:
                        if key in new_contact:
                            new_value = sorted(set(contact[key].split(',') + new_contact[key].split(',')))
                            contact[key] = ','.join(new_value)
                    else:
                        contact[key] = new_contact[key]

                return

        # If we didn't find an existing contact, add a new one
        self.contacts.append(new_contact)
