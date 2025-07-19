# pilfer
Decrypt *all* ansible vault files in a project recursively for search/editing, then re-encrypt them all at once when you're done.

Borrows heavily from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).

**Updated for Python 3 compatibility with modern features and ansible.cfg integration.**

Tested with Ansible v2.5+ and Python 3.6+

## Features

- **Python 3 compatible** - Modernized for current Python versions
- **ansible.cfg integration** - Automatically reads `vault_password_file` from your ansible.cfg
- **Smart fallback** - Searches common locations for vault password files
- **Change detection** - Only re-encrypts files that were actually modified (using SHA256)
- **Safe operation** - Preserves original encrypted content for unchanged files
- **Error handling** - Robust error handling with meaningful messages

## Usage
```
./bulk-decrypt-vault.py [open|close] [-p VAULT_PASSWORD_FILE]
```

### Basic Usage
- Download `bulk-decrypt-vault.py` and place it at the root of your Ansible directories
- Run `./bulk-decrypt-vault.py open` to decrypt all vaulted files recursively
- Edit/search plaintext as needed
- Run `./bulk-decrypt-vault.py close` to re-encrypt any changed files

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

```bash
# Use ansible.cfg vault_password_file setting (recommended)
./bulk-decrypt-vault.py open

# Specify custom vault password file
./bulk-decrypt-vault.py open -p ~/.my-vault-password

# Close and re-encrypt modified files
./bulk-decrypt-vault.py close
```

## Installation

### Requirements

**Python 3.6+** with the ansible-vault library:

```bash
# Standard installation
pip install ansible-vault

# In containerized/restricted environments
pip install ansible-vault --break-system-packages

# Using pipx (recommended for CLI tools)
pipx inject ansible ansible-vault
```

### ansible.cfg Setup (Recommended)

Add to your `ansible.cfg`:
```ini
[defaults]
vault_password_file = ~/.ansible-vault/.vault-file
```

This eliminates the need to manually configure vault password paths.
