# pilfer
Decrypt all ansible vault files recursively for search/editing, then re-encrypt them.

Borrows heavily from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).

## Usage
```
./bulk-decrypt-vault.py [open|close]
```

- Place in the root of your Ansible directories, run `open` to decrypt all vaulted files

- Edit/search plaintext as needed

- Run `close` to re-encrypt any changed files

## Requirements

```
pip install ansible ansible-vault pathlib
```
