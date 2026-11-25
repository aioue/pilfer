"""A keyring backend in a JSON file, so tests never touch the real keychain.

Selected with PYTHON_KEYRING_BACKEND=_file_keyring.FileKeyring (tests/ on
PYTHONPATH) and PILFER_TEST_KEYRING=<path>. A file rather than memory because
the client script under test runs in its own process, started by Ansible.
keyring ships no file backend (keyrings.alt has one, but is another
dependency); its fail and null backends cover the error paths.
"""

import json
import os
from pathlib import Path

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class FileKeyring(KeyringBackend):
    priority = 1

    @property
    def _path(self) -> Path:
        return Path(os.environ["PILFER_TEST_KEYRING"])

    def _load(self) -> dict:
        return json.loads(self._path.read_text()) if self._path.exists() else {}

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
