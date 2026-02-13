import json

from pathlib import Path

from constants import BASE_DIR

class ContactStorage:
    def __init__(self):
        self.file_path: Path = Path(BASE_DIR) / "contacts.json"

        # Ensure file exists
        if not self.file_path.exists():
            self._save_contacts([])

        self.contacts: list = self._load_contacts()

    def _load_contacts(self) -> list:
        try:
            with open(self.file_path, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_contacts(self, contacts_list):
        with open(self.file_path, "w") as f:
            json.dump(contacts_list, f, indent=4)

    def add_contact(self, name: str, ip: str, port: int, fingerprint: str):
        new_contact = {
            "name": name,
            "ip": ip,
            "port": port,
            "fingerprint": fingerprint
        }

        self.contacts.append(new_contact)
        self._save_contacts(self.contacts)

    def remove_contact(self, index: int):
        if 0 <= index < len(self.contacts):
            self.contacts.pop(index)
            self._save_contacts(self.contacts)

    def edit_contact(self, index: int, field: str, new_value: str | int):
        if 0 <= index < len(self.contacts):
            self.contacts[index][field] = new_value
            self._save_contacts(self.contacts)

    def check_if_contact_exists(self, fingerprint: str) -> tuple[bool, str]:
        for contact in self.contacts:
            if contact.get("fingerprint") == fingerprint:
                return True, contact.get("name", "Unknown")

        return False, "Unknown"
