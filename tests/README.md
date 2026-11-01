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
- `test_vault_set.py`: `pilfer set` and `set_keys`. Results are read back
  through the `ansible-vault` CLI, not through pilfer.

## Requirements

- Python 3.10+
- `ansible-core`, for `VaultLib`, and `ansible-vault` on `PATH`
