# pilfer
Decrypt all ansible vault files recursively for search/editing, then re-encrypt them.

## Usage
```
./bulk-decrypt-vault.py [open|close]
```

- Place in the root of your Ansible directories, run `open` to decrypt all vaulted files

- Edit/search plaintext as needed

- Run `close` to re-encrypt any changed files

## Requirements

Ansible `2.0+`
`ansible-vault` python package
`pathlib` python package
