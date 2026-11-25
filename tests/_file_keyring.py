"""A keyring backend in a JSON file, so tests never touch the real keychain.

Selected with PYTHON_KEYRING_BACKEND=_file_keyring.FileKeyring (tests/ on
PYTHONPATH) and PILFER_TEST_KEYRING=<path>. A file rather than memory because
the client script under test runs in its own process, started by Ansible.
"""

import json
import os
from pathlib import Path

from keyring.backend import KeyringBackend
from keyring.errors import KeyringLocked, PasswordDeleteError

LOCKED = "locked"


class FileKeyring(KeyringBackend):
    priority = 1

    @property
    def _path(self) -> Path:
        return Path(os.environ["PILFER_TEST_KEYRING"])

    def _load(self) -> dict:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text())
        # A keyring the test marked locked, as the macOS login keychain is in an SSH session.
        if data.get(LOCKED):
            raise KeyringLocked("test keyring is locked")
        return data

    def get_password(self, service, username):
        return self._load().get(f"{service}/{username}")

    def set_password(self, service, username, password):
        data = self._load()
        data[f"{service}/{username}"] = password
        self._path.write_text(json.dumps(data))

    def delete_password(self, service, username):
        data = self._load()
        if data.pop(f"{service}/{username}", None) is None:
            raise PasswordDeleteError(service)
        self._path.write_text(json.dumps(data))
