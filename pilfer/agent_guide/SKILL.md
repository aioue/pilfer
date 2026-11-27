---
name: pilfer
description: Find, update and rotate Ansible Vault secrets in a project that has pilfer installed, without printing or writing plaintext. Use when asked to edit, look up or change a vault value.
---

# pilfer

pilfer edits Ansible Vault files. Use it for every vault task. Do not run `pilfer open`, `pilfer close`, `ansible-vault view`, `ansible-vault decrypt` or `ansible-vault edit`: they put plaintext on disk or in your output.

Never read a decrypted file, print a value or put one in a command line, a file you write or your own reply.

## Find a key

```bash
pilfer find-keys db_password
pilfer find-keys '*token*'
pilfer find-keys -l '*token*'
pilfer find-keys --json '*token*'
```

`find-keys` prints file paths and key names, never values. Quote globs so the shell leaves them alone.

- A pattern matches the whole key name; `*` and `?` are wildcards.
- `-E` takes regular expressions, `-i` ignores case, `--path` matches the full path such as `aws.prod.secret_key`.
- With no pattern it lists every key.
- `-l` prints only file names.
- `--json` prints one object per line: `file`, `key`, `path`, `kind`, `open`, `vault_id` (`default` for a file with no vault label).
- Keys that are inline `!vault` strings are skipped unless you pass `--include-encrypted-vars`.
- Exit status: 0 a key matched, 1 none matched, 2 an error.

## Change a value

Pipe the new value on stdin from a password manager or a generator.

```bash
bw get password NAME | pilfer update db_password
openssl rand -base64 32 | pilfer set group_vars/all/vault.yml db_password
```

- `pilfer update KEY` finds the file that holds KEY and replaces the value.
- `pilfer set FILE KEY` adds or replaces a key in one whole-file vault. Missing mappings along the path are created.
- Add `--dry-run` first. It reads no value, writes nothing and prints `would update` or `would add`.
- Writing the value that is already stored prints `unchanged` and leaves the file alone, so repeating a write is safe.
- Piped input loses one trailing newline.
- Do not pass the value as an argument: it shows in `ps` and shell history. If the user gives you a value in chat, ask them to pipe it themselves.

Key paths use Jinja syntax: `db_password`, `a.b.c`, `users[0].password`, `a['dotted.key']`.

`update` errors:

- The key is in several files: it lists them. Repeat with `--file FILE`.
- The key does not exist: `update` never creates one. Run `pilfer set FILE KEY`.
- The key exists only as an inline `!vault` value: add `--include-encrypted-vars`.
- The file is open in a session: see below.

## Sessions

`pilfer status` says whether a session holds plaintext on disk. `--json` prints `open`, `incomplete` and `files`. It needs no password and prints no values.

If a session is open, tell the user. Do not run `pilfer close` unless they ask. `set` and `update` refuse files that are open.

## Vault password

There is no terminal. `-J` and `--vault-id LABEL@prompt` fail at once instead of waiting.

- Use `-p FILE` or `--vault-id LABEL@FILE`.
- Without either, pilfer uses `vault_password_file` or `vault_identity_list` from `ansible.cfg` or the `ANSIBLE_VAULT_*` variables.
- If no password file exists, ask the user for one. Do not guess a path or write a password to disk.

## Rotate the vault password

`pilfer rekey` changes the password of every vault file in the tree. Run `pilfer rekey --dry-run --old-vault-password-file OLD --new-vault-password-file NEW` and show the user the plan. A real run needs `--yes` because the confirmation prompt needs a terminal. Run it only when the user asks.

To rotate a single secret, use `pilfer update`.

## Other commands

```bash
pilfer --help
pilfer COMMAND --help
```
