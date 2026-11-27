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

- A pattern matches the whole key name; `*` and `?` are wildcards and `[` is literal (`--path 'users[0].*'` matches `users[0].name`). Use `-E` for character classes.
- `-E` takes regular expressions that match anywhere in the name (anchor with `^...$`), `-i` ignores case, `--path` matches the full path such as `aws.prod.secret_key`.
- With no pattern it lists every key.
- `-l` prints only file names. It cannot be combined with `--json`.
- `--json` prints one object per line: `file`; `key`, the last name; `path`, the names and list indexes from the file root; `kind`, `file` or `inline`; `open`, true when read from an open session; `vault_id`, `default` for no label.
- Text output escapes characters Python treats as non-printable; `--json` uses JSON escapes.
- Keys that are inline `!vault` strings are skipped unless you pass `--include-encrypted-vars`.
- Exit status: 0 a key matched, 1 none matched, 2 an error. An unreadable possible vault file, or a directory that could not be listed, is an error (exit 2); unreadable non-vault files only warn (a file over 64 MiB counts as unreadable only if it holds `$ANSIBLE_VAULT;` or a pilfer marker). A vault header is recognised by `$ANSIBLE_VAULT` alone, as Ansible does. It exits 141 if its output pipe closes early.
- A key supplied by several `<<` merge sources is listed once.
- A plaintext file over 1 MiB is unreadable ("too large to parse") if it holds a `!vault` tag in any spelling, a `%TAG` directive or an `__ansible_vault` key, even in prose; a file that only mentions the word vault is not. The check runs only when inline values are included: `rekey` by default, `update` always, `find-keys` and `open` with `--include-encrypted-vars`. `find-keys` and `update` report it; `rekey` refuses.
- With `--include-encrypted-vars`, `find-keys` warns about `!vault` values other than `key: !vault |` blocks: list items, flow values, `|-`, `|+` and `>` blocks, and JSON `__ansible_vault` values; their keys are not searched. `rekey` refuses while any exist, and refuses a whole-file vault whose plaintext holds inline vault values.
- A file Ansible reads but pilfer's YAML parser rejects (often a tab where YAML wants a space) is listed by `find-keys`; `set` and `update` refuse it, and so do `open --include-encrypted-vars` and `close` on an inline file; a whole-file vault with a tab opens and closes normally. Replace the tab with spaces.
- A whole-file vault with a binary file name (`.zip`, `.tar.gz`, `.bin`, `.db`, ...) is not rekeyed: `rekey` refuses while one is in the tree (use `ansible-vault rekey` or move it out), and `find-keys` and `open` warn. Symlinks are not followed, so `rekey` misses a vault reached only through a symlink to outside the tree.

## Change a value

Pipe the new value on stdin from a password manager or a generator.

```bash
bw get password NAME | pilfer update db_password
openssl rand -base64 32 | pilfer set group_vars/all/vault.yml db_password
```

- `pilfer update KEY` finds the file that holds KEY and replaces the value.
- `pilfer set FILE KEY` adds or replaces a key in one whole-file vault. Missing mappings along the path are created.
- Add `--dry-run` first. It never reads stdin, writes nothing and prints `would update` or `would add`. An agent never passes VALUE, so the dry run checks the file and key path only and prints `The value was not checked: stdin was not read.`
- Writing the value that is already stored prints `unchanged` and leaves the file alone, so repeating a write is safe.
- Piped input loses one trailing newline.
- Exit status for `set` and `update`: 0 done or unchanged, 1 refused or failed, 2 usage error.
- Do not pass the value as an argument: pilfer warns, because it shows in `ps` and shell history. If the user gives you a value in chat, ask them to pipe it themselves.

`update` replaces only a single (scalar) value; a mapping or list is refused. `set` and `update` refuse a key shared through a YAML anchor used elsewhere, in whole-file vaults and inline `!vault` files alike, and refuse to add a key to a mapping that has only a `<<` merge or whose last value is an alias; edit those in a `pilfer open` session, which you must not run, so tell the user.

Key paths use Jinja syntax: `db_password`, `a.b.c`, `users[0].password`, `a['dotted.key']`.

`update` errors:

- The key is in several files: it lists them. Repeat with `--file FILE`.
- The key does not exist: `update` never creates one. Run `pilfer set FILE KEY`.
- The key exists only as an inline `!vault` value: add `--include-encrypted-vars`.
- A file could not be read or decrypted, or a directory listed, and might hold the key: `update` refuses and names it. Fix it or pass `--file FILE`.
- The file is open in a session: see below.

## Sessions

`pilfer status` says whether a session holds plaintext on disk. `--json` prints `open`, `incomplete`, `orphaned` and `files`; `open: true` with no files means nothing holds plaintext. A leftover `.vault/` with no session list is reported as an orphaned session. That check looks only at leftover `.vault/` backups, not plaintext sidecars. It needs no password and prints no values.

If a session is open, tell the user. Do not run `pilfer close` unless they ask. `set` and `update` refuse files that are open.

## Vault password

There is no terminal. `-J` and `--vault-id LABEL@prompt` fail at once instead of waiting.

- Use `-p FILE` or `--vault-id LABEL@FILE`.
- Without either, pilfer uses `vault_password_file` or `vault_identity_list` from `ansible.cfg` or the `ANSIBLE_VAULT_*` variables.
- Then it tries `~/.ansible-vault/.vault-file`, `.vault_password`, `vault_password_file` and `../../vault_password_file`, read as plain password files.
- Pilfer loads passwords as `ansible-vault` does, so a `vault_password_file` script named by the project's `ansible.cfg` runs whenever a command needs a password, even with `-p`. Do not run `find-keys`, `update` or `set` in a clone nobody has reviewed. (`status`, `agent-guide` and `completion` load no password.)
- If none exists, ask the user for one. Do not guess a path or write a password to disk.

## Rotate the vault password

`pilfer rekey` changes the password of every vault file in the tree. Run `pilfer rekey --dry-run --old-vault-password-file OLD --new-vault-password-file NEW` and show the user the plan. A real run needs `--yes` because the confirmation prompt needs a terminal. Run it only when the user asks.

To rotate a single secret, use `pilfer update`.

## Other commands

```bash
pilfer --help
pilfer COMMAND --help
```
