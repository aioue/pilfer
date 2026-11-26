# Pilfer tests

`run_tests.py` runs every `test_*.py` module in this directory. CI runs only
that script, so a new test class runs there without being registered anywhere.

```bash
cd tests
python run_tests.py </dev/null
```

Close stdin when you run the suite in the background: a rekey run without
`--yes` waits at its confirmation prompt. The suite's own subprocesses already
close it.

Run one class or one test:

```bash
python -m unittest test_pilfer_unified.TestSessionSafety
python -m unittest test_pilfer_unified.TestPilferCLI.test_line_endings_preserved
```

## Layout

- `test_pilfer_unified.py`: open, close and rekey, whole-file and inline.
  `ProjectDirTest` gives each test its own temporary project directory as cwd,
  with a `vault_pass` file and `self.vault`. `run_pilfer()` runs `pilfer.py` in
  a subprocess.
- `test_inline_randomized.py`: generated secrets, edits and editor saves
  through open and close, checked against what YAML reads from the edited
  file. Fixed seeds; `PILFER_RANDOM_CASES=5000` runs more.
- `test_vault_sources.py`: password scripts, `-client` scripts, Ansible's config,
  several vault ids, and rekey and rotation with those sources. Runs pilfer in
  a subprocess, because Ansible reads its config at import.
- `_ansible_isolation.py`: imported first by every test module. Points
  `ANSIBLE_CONFIG` at an empty file so the machine's own Ansible config stays out.
- `test_keyring_client.py`: `pilfer-vault-keyring-client`, run as Ansible runs
  it and through `ansible-vault` and pilfer. The keyring is
  `_file_keyring.FileKeyring`, a JSON file per test, or keyring's own fail and
  null backends, so the real keychain is never touched. Needs the `keyring`
  extra (`pip install -e '.[keyring]'`).
- `_file_keyring.py`: a keyring backend that keeps passwords in a JSON file.
  In-process tests pass `FileKeyring(path)`. The client under test runs in its
  own process and selects it with `PYTHON_KEYRING_BACKEND` and
  `PILFER_TEST_KEYRING`. Backend variants in the tests subclass it.
- `test_vault_set.py`: `pilfer set` and `set_keys`. Results are read back
  through the `ansible-vault` CLI, not through pilfer.

## Requirements

- Python 3.12+
- `ansible-core` 2.21+, for `VaultLib`, and `ansible-vault` on `PATH`
- `keyring` 25+ (`pip install -e '.[keyring]'`) for `test_keyring_client.py`
