"""Keep the developer's Ansible config out of the tests.

pilfer loads vault secrets from Ansible's config: ANSIBLE_CONFIG, ./ansible.cfg,
~/.ansible.cfg and the ANSIBLE_VAULT_* variables. ansible.constants reads them
once, on first import, so a vault_password_file or vault_identity_list on the
machine running the suite would be loaded by every test. Each test module
imports this before anything imports ansible. Subprocesses inherit it.
"""

import atexit
import os
import tempfile

for _name in list(os.environ):
    if _name.startswith("ANSIBLE_VAULT") or _name in ("ANSIBLE_ASK_VAULT_PASS", "ANSIBLE_CONFIG"):
        del os.environ[_name]

_handle, EMPTY_ANSIBLE_CFG = tempfile.mkstemp(prefix="pilfer-test-", suffix=".cfg")
with os.fdopen(_handle, "w") as _cfg:
    _cfg.write("[defaults]\n")
atexit.register(os.remove, EMPTY_ANSIBLE_CFG)
os.environ["ANSIBLE_CONFIG"] = EMPTY_ANSIBLE_CFG
