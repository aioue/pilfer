# pilfer

[![CI](https://github.com/aioue/pilfer/workflows/CI/badge.svg)](https://github.com/aioue/pilfer/actions)
[![Test Suite](https://github.com/aioue/pilfer/workflows/Test%20Suite/badge.svg)](https://github.com/aioue/pilfer/actions)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Decrypt *all* ansible vault files in a project recursively for search/editing, then re-encrypt them all at once when you're done.

Borrows heavily from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).

**Updated for Python 3 compatibility with modern features and ansible.cfg integration.**

Tested with Ansible v2.18.x and Python 3.12.x

## Features

- **Python 3 compatible** - Modernized for current Python versions
- **ansible.cfg integration** - Automatically reads `vault_password_file` from your ansible.cfg
- **Change detection** - Only re-encrypts files that were actually modified (using SHA256)
- **Safe operation** - Preserves original encrypted content for unchanged files
- **No third-party dependencies** - Uses Ansible's official vault implementation directly
- **Binary data preservation** - Preserves exact line endings and formatting (critical for certificates)

## Usage
```
pilfer [open|close] [-p VAULT_PASSWORD_FILE]
```

### Basic Usage

**Option 1: Standalone Script (No Installation)**
- Download `pilfer.py` and place it in your Ansible project directory
- Run `python pilfer.py open` to decrypt all vaulted files recursively
- Edit/search plaintext as needed
- Run `python pilfer.py close` to re-encrypt any changed files

**Option 2: Installed via pipx (Recommended)**
- Install pilfer via pipx: `pipx install pilfer`
- Run `pilfer open` to decrypt all vaulted files recursively
- Edit/search plaintext as needed
- Run `pilfer close` to re-encrypt any changed files

Any unchanged files will be returned to their original state.

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

# Close and re-encrypt modified files
pilfer close
```

**Using the standalone script:**
```bash
# Use ansible.cfg vault_password_file setting (recommended)
python pilfer.py open

# Specify custom vault password file
python pilfer.py open -p ~/.my-vault-password

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

**Python 3.6+** is required. Install pilfer using pipx for isolated CLI tool management:

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

Prerequisites:
```bash
# Install build tools
pip install build twine

# Configure PyPI credentials
# ~/.pypirc or use environment variables
```

Build and publish:
```bash
# Make the script executable
chmod +x build_and_publish.sh

# Publish to TestPyPI first
./build_and_publish.sh test

# After testing, publish to production PyPI
./build_and_publish.sh prod
```

The build script will:
1. Clean previous builds
2. Build the package using modern Python packaging
3. Upload to PyPI/TestPyPI using twine
4. Provide installation instructions

## License

This project is licensed under the GNU General Public License v3 or later (GPLv3+). See the [LICENSE](../LICENSE) file for the complete license text from the [official GNU website](https://www.gnu.org/licenses/gpl-3.0.txt).

### Packaging Note

Due to a compatibility issue between modern setuptools (which supports SPDX license expressions) and PyPI's current metadata validation (which doesn't yet support the new format), the license file is renamed to `PILFER_LICENSE.txt` during packaging to avoid auto-detection issues. This is a temporary workaround until PyPI updates its metadata validation to support the newer standards.

This package heavily borrows from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).
