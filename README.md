# pilfer
Decrypt all ansible vault files recursively for search/editing, then re-encrypt them.

Borrows heavily from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).

Tested with Ansible v2.5+

## Usage
```
./bulk-decrypt-vault.py [open|close]
```

- Download `bulk-decrypt-vault.py` and place it at the root of your Ansible directories

- Edit the `VAULT_PASSWORD_PATH` in `bulk-decrypt-vault.py` [to match your vault file destination](https://github.com/aioue/pilfer/blob/master/bulk-decrypt-vault.py#L40)

- Run `./bulk-decrypt-vault.py open` to decrypt all vaulted files recursively

- Edit/search plaintext as needed

- Run `./bulk-decrypt-vault.py open` to re-encrypt any changed files

  Any unchanged files will returned to their original state.

## Requirements

```
pip install ansible ansible-vault pathlib
```
