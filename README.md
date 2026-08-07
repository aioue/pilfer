# pilfer

**Decrypt *all* ansible vault files in a project in-place recursively for viewing/editing, then re-encrypt them all at once when you're done.**

Optionally decrypt/re-encrypt all [encrypted variables](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_encrypting_content.html) in-place, or re-key an entire tree after a password exposure.

## Quick start

Requires **Python 3.10+** and **Ansible**.

```bash
pipx install pilfer
cd your-ansible-project
pilfer open
# edit or search plaintext
pilfer close
```

Unchanged files are restored to their original ciphertext automatically.

## Install

```bash
pipx install pilfer   # recommended
pip install pilfer    # or direct pip
```

See [Installation](#installation) for standalone script, source install, and `ansible.cfg` setup.

---

[![CI](https://github.com/aioue/pilfer/actions/workflows/ci.yml/badge.svg)](https://github.com/aioue/pilfer/actions/workflows/ci.yml)
[![Test Suite](https://github.com/aioue/pilfer/actions/workflows/test.yml/badge.svg)](https://github.com/aioue/pilfer/actions/workflows/test.yml)
[![CodeQL](https://github.com/aioue/pilfer/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/aioue/pilfer/actions/workflows/github-code-scanning/codeql)
[![Dependabot enabled](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](https://github.com/aioue/pilfer/network/updates)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Features

- **Python 3.10+** - Typed modern Python; CI covers 3.10–3.13
- **ansible.cfg integration** - Automatically reads `vault_password_file` from your ansible.cfg
- **Change detection** - Only re-encrypts files that were actually modified (using SHA256)
- **Safe operation** - Preserves original encrypted content for unchanged files
- **No third-party dependencies** - Uses Ansible's official vault implementation directly
- **Binary data preservation** - Preserves exact line endings and formatting (critical for certificates)
- **Inline `encrypt_string` support** - Opt-in via `pilfer open --include-encrypted-vars`; decrypts YAML `!vault` scalars in place (with `# pilfer:vault:N` markers); `close` always re-encrypts whatever the session opened
- **Fail-closed sessions** - Refuses double-`open`, keeps session state if `close` partially fails, non-zero exit codes on errors

## Usage
```
pilfer [open|close|rekey] [-p VAULT_PASSWORD_FILE] [--include-encrypted-vars] [--allow-removals]
```

### Basic Usage

**Option 1: From a clone (no pipx)**
- Clone this repository (or install editable: `pip install -e .`)
- From your Ansible project directory, run `python /path/to/pilfer/pilfer.py open`
- Edit/search plaintext as needed
- Run `python /path/to/pilfer/pilfer.py close` to re-encrypt any changed files
- `pilfer.py` is a thin entry point; the implementation lives in the `pilfer/` package

**Option 2: Installed via pipx (Recommended)**
- Install pilfer via pipx: `pipx install pilfer`
- Run `pilfer open` to decrypt all vaulted files recursively
- Edit/search plaintext as needed
- Run `pilfer close` to re-encrypt any changed files

Any unchanged files will be returned to their original state.

Re-key an entire tree (inline `!vault` included by default): `pilfer rekey --old-vault-password-file OLD --new-vault-password-file NEW --dry-run`.

### Inline encrypted variables (`encrypt_string` / `!vault`)

Whole-file vaults are opened by default. Inline `!vault` scalars are **opt-in**:

```bash
# Open whole-file vaults AND inline encrypt_string values
pilfer open --include-encrypted-vars

# Edit values in place. pilfer rewrites each !vault block like:
#   db_password: "the-secret"  # pilfer:vault:0
#
# Do NOT remove the `# pilfer:vault:N` comment - close uses it to find
# and re-encrypt each value. Do NOT commit while those markers are present
# (plaintext secrets + session metadata would land in git).

pilfer close   # no flag needed; re-encrypts everything this session opened
```

`close` always re-encrypts session entries (whole-file and inline). The
`--include-encrypted-vars` flag is only meaningful on `open`.

If you delete an entire opened variable line (key + value + marker), `close`
refuses by default (ambiguous delete vs accident). Confirm with:

```bash
pilfer close --allow-removals
```

which then prints:

```text
🔍 Detected removal of 1 encrypted vars:
  - db_password
```

Do not strip only the `# pilfer:vault:N` comment while leaving the key - close
will refuse so plaintext is not stranded. Renaming the key and dropping the
marker is also refused if the secret value is still present in the file
(including in comments).


### Vault Password File Detection

The script automatically detects your vault password file in this order:

1. **Command line argument**: `-p /path/to/vault/file`
2. **ansible.cfg**: Reads `vault_password_file` from `[defaults]` section
3. **Common locations**:
   - `~/.ansible-vault/.vault-file`
   - `../../vault_password_file`
   - `.vault_password`
   - `vault_password_file`

### Examples

**Using the installed version:**
```bash
# Use ansible.cfg vault_password_file setting (recommended)
pilfer open

# Specify custom vault password file
pilfer open -p ~/.my-vault-password

# Also decrypt inline !vault / encrypt_string values
pilfer open --include-encrypted-vars

# Close and re-encrypt modified files (and any opened inline vars)
pilfer close
```

**Using the standalone script:**
```bash
# Use ansible.cfg vault_password_file setting (recommended)
python pilfer.py open

# Specify custom vault password file
python pilfer.py open -p ~/.my-vault-password

# Also decrypt inline !vault / encrypt_string values
python pilfer.py open --include-encrypted-vars

# Close and re-encrypt modified files
python pilfer.py close
```

## Installation

### Option 1: Standalone Script (No Installation Required)

Download and use the standalone script directly:

```bash
# Download the standalone script
curl -O https://raw.githubusercontent.com/aioue/pilfer/main/pilfer.py

# Make it executable (required for ./pilfer.py usage)
chmod +x pilfer.py

# Use it directly
./pilfer.py open
# OR
python pilfer.py open
```

### Option 2: Install via pipx (Recommended for Regular Use)

**Python 3.10+** is required. Install pilfer using pipx for isolated CLI tool management:

```bash
# Install pilfer via pipx (recommended)
pipx install pilfer

# Verify installation
pilfer --help
```

### Alternative Installation Methods

If you prefer other installation methods:

```bash
# Install from source (in development mode)
git clone https://github.com/aioue/pilfer.git
cd pilfer
pip install -e .

# Direct pip installation (not recommended for CLI tools)
pip install pilfer
```

### Requirements

Pilfer requires **Ansible** to be available. If not already installed:

```bash
# Using pipx (recommended for CLI tools)
pipx install ansible

# Using pip
pip install ansible

# System package manager
# Ubuntu/Debian:
sudo apt update && sudo apt install ansible

# RHEL/CentOS/Fedora:
sudo dnf install ansible

# macOS:
brew install ansible
```

### ansible.cfg Setup (Recommended)

Add to your `ansible.cfg`:
```ini
[defaults]
vault_password_file = ~/.ansible-vault/.vault-file
```

This eliminates the need to manually configure vault password paths.

## Development and Publishing

### For Developers

To set up for development:

```bash
# Clone the repository
git clone https://github.com/aioue/pilfer.git
cd pilfer

# Install in development mode
pip install -e .

# Make changes and test
pilfer --help
```

### Publishing to PyPI

**Recommended:** use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`) so auto-generated release notes stay readable. Bump the version in `pyproject.toml`, `pilfer/__init__.py`, and `pilfer.py`, then commit, push, and tag:

```bash
# Bump version in pyproject.toml, pilfer/__init__.py, and pilfer.py first
git commit -am "chore(release): X.Y.Z"
git push origin master
git tag vX.Y.Z
git push origin vX.Y.Z

# Optional: preview notes locally before tagging
./scripts/release-notes.sh
```

The [Release workflow](.github/workflows/release.yml) validates versions, runs tests, creates a GitHub release (summary + auto-generated notes since the previous tag), and publishes to PyPI via trusted publishing. See [.github/workflows/README.md](.github/workflows/README.md) for one-time PyPI setup.

**Manual fallback** (TestPyPI or local publish):

```bash
pip install build twine
chmod +x build_and_publish.sh
./build_and_publish.sh test   # TestPyPI
./build_and_publish.sh prod   # production PyPI
```

The build script will:
1. Clean previous builds
2. Build the package using modern Python packaging
3. Upload to PyPI/TestPyPI using twine
4. Provide installation instructions

## Rotating the vault password

`pilfer close` is **not** password rotation - it refuses a different password than
the one used for `open` (anti re-key). To rotate every vault target in the tree
(including inline `!vault` spans):

```bash
# Plan / decrypt-check only
pilfer rekey \
  --old-vault-password-file ~/.ansible-vault/.vault-file \
  --new-vault-password-file /tmp/new-vault-pass \
  --dry-run

# Re-key ciphertext (prompts: type REKEY). Inline spans included by default.
pilfer rekey \
  --old-vault-password-file ~/.ansible-vault/.vault-file \
  --new-vault-password-file /tmp/new-vault-pass

# After 100% success, optionally archive the old password file and install the new
# one at the old path (chmod 600):
pilfer rekey ... --rotate-password-file
```

Refuse to rekey while a pilfer session is open. Nested git checkouts are skipped
(run `pilfer rekey` from those directories separately). Prefer `--dry-run` first.
A mid-run failure can leave a split-password tree; **re-run the same `rekey`
command to resume** (files already on the new password are skipped).
`--rotate-password-file` is refused with `--no-include-encrypted-vars`, and also
when nested git checkouts were skipped, so the live password file is not rotated
while ciphertext remains on the old password. Stale `.pilfer-rekey-*` staging
files are ignored as vault targets and removed only after confirmed mutating
rekey (never on `--dry-run`).

## Safety

Pilfer **fails closed**: if it cannot prove a secret is safely re-encrypted or
intentionally removed, it keeps the session and `.vault/` backups and exits
non-zero. It does not invent fixes for ambiguous edits.

### Failure modes this protects against

- Silent re-key on `close` with a different password than `open`
- Double-`open` destroying encrypted backups under `.vault/`
- Orphan plaintext after deleting `vaultedFileList.json` (markers, `.vault/`, or `*.pilfer-open` sidecars still block re-open)
- Stranded plaintext after stripping markers, renaming keys, or relocating secrets (including into comments)
- Crash mid-decrypt leaving unmarked plaintext (open sidecars are written before plaintext)

### Surprising-by-design behaviors

- **Interrupted close retries:** whole-file targets only count as already done when
  working bytes match the open backup, or the file is vault ciphertext decryptable
  with the session password (not an arbitrary foreign vault blob).
- **`close` is progressive** - files that succeed are encrypted and dropped from the session; failures stay plaintext until you fix and retry. Not an all-or-nothing transaction.
- **Intentional var removal** requires `pilfer close --allow-removals`.
- **Short secrets** can block close if the same bytes appear elsewhere in the file (docs/comments) - fail closed.
- **Nested git checkouts** are skipped; run pilfer from those roots if needed.
- **Legacy unbound sessions** can `close` only if the password decrypts the session backups (then pilfer binds a v2 fingerprint); otherwise remove the session list and re-`open`.
- **Incomplete open** (session list written, crash before decrypt) is cleared on the next `open` only when listed paths still look like vault ciphertext and there are no backups/sidecars - so you are not told to `close` ciphertext. If the session list remains but files are already plaintext (artifacts deleted), `open` still refuses.
- **`*.pilfer-open` sidecars** sit beside opened files (whole-file opens have no `# pilfer:vault:` markers).

### Gitignore

```gitignore
vaultedFileList.json
.vault/
**/*.pilfer-open
```

### Pre-commit hook (suggested)

Block commits while a session is open:

```bash
# .git/hooks/pre-commit (chmod +x)
if [ -e vaultedFileList.json ] || [ -d .vault ] \
  || find . -name '*.pilfer-open' -print -quit 2>/dev/null | grep -q .; then
  echo "pilfer session open (vaultedFileList.json / .vault / *.pilfer-open); run pilfer close first"
  exit 1
fi
# Optional: also refuse # pilfer:vault: markers from --include-encrypted-vars
if git grep -n '# pilfer:vault:' -- '*.yml' '*.yaml' >/dev/null 2>&1; then
  echo "files still contain # pilfer:vault: markers; run pilfer close first"
  exit 1
fi
```

### Recovery

- Session present (`vaultedFileList.json`) → fix the reported issue → `pilfer close` again.
- Session deleted but markers / `.vault` / `*.pilfer-open` remain → restore `vaultedFileList.json` from backup if you have it and `close`, or manually re-encrypt / restore secrets before `open`.

## License

This project is licensed under the GNU General Public License v3 or later (GPLv3+). See [`PILFER_LICENSE.txt`](PILFER_LICENSE.txt) for the complete license text, or the [official GNU website](https://www.gnu.org/licenses/gpl-3.0.txt).

The package declares `GPL-3.0-or-later` in metadata; the license file is named `PILFER_LICENSE.txt` to avoid setuptools auto-detection clashes during builds.

## Credits

Borrows heavily from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).
