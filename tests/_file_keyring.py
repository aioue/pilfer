"""A keyring backend in a JSON file, so tests never touch the real keychain.

Two ways to pick the file. In-process tests pass it: FileKeyring(path). A client
script under test runs in its own process, started by Ansible, so there the
backend is selected with PYTHON_KEYRING_BACKEND=_file_keyring.FileKeyring
(tests/ on PYTHONPATH) and the file with PILFER_TEST_KEYRING=<path>. keyring
ships no file backend (keyrings.alt has one, but is another dependency); its
fail and null backends cover the error paths.

Entries are keyed by entry(service, username); tests use it to build the
expected file contents.
"""

import json
import os
from pathlib import Path

from keyring.backend import KeyringBackend


def entry(service: str, username: str) -> str:
    return f"{service}/{username}"


class FileKeyring(KeyringBackend):
    priority = 1

    def __init__(self, path=None):
        super().__init__()
        self._file = path

    @property
    def _path(self) -> Path:
        return Path(self._file) if self._file else Path(os.environ["PILFER_TEST_KEYRING"])

    def _load(self) -> dict:
        return json.loads(self._path.read_text()) if self._path.exists() else {}

    def get_password(self, service, username):
        return self._load().get(entry(service, username))

    def set_password(self, service, username, password):
        data = self._load()
        data[entry(service, username)] = password
        self._path.write_text(json.dumps(data))
