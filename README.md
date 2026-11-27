[![CI](https://github.com/aioue/pilfer/actions/workflows/ci.yml/badge.svg)](https://github.com/aioue/pilfer/actions/workflows/ci.yml)
[![Test Suite](https://github.com/aioue/pilfer/actions/workflows/test.yml/badge.svg)](https://github.com/aioue/pilfer/actions/workflows/test.yml)
[![CodeQL](https://github.com/aioue/pilfer/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/aioue/pilfer/actions/workflows/github-code-scanning/codeql)
[![Dependabot enabled](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](https://github.com/aioue/pilfer/network/updates)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# pilfer

**Decrypt *all* ansible vault files in a project in-place recursively for viewing/editing, then re-encrypt them all at once when you're done.**

Optionally decrypt/re-encrypt all [encrypted variables](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_encrypting_content.html) in-place, or re-key an entire tree after a password exposure.

## Output

Example session:

![Example pilfer open and close session](docs/pilfer-session.svg)

<details>
<summary>Plain-text transcript</summary>

```text
$ pilfer open --include-encrypted-vars --quiet
🔓 Searching for and decrypting vault files...
ℹ️  Found 4 vault target(s) (3 whole-file, 1 with inline encrypt_string)
✅ All vault files decrypted. Edit as needed, then run 'pilfer close' to re-encrypt.
$ pilfer close
🔒 Re-encrypting vault files...
ℹ️  Re-encrypting modified file: inventory/group_vars/all/secrets.yml
ℹ️  Re-encrypting modified inline vault string(s) in: inventory/group_vars/all/all.yml (1 changed)
✅ Vault files re-encrypted. 2 modified files have been updated.
```

</details>

## Quick start

Requires **Python 3.12+** and **ansible-core 2.21+**. `pip install pilfer` installs ansible-core.

```bash
pipx install pilfer
cd your-ansible-project
pilfer open
# edit or search plaintext
pilfer close
```

Unchanged files are restored to their original ciphertext automatically.

Add to `ansible.cfg` so you do not need `-p FILE` on every run:

```ini
[defaults]
vault_password_file = ~/.ansible-vault/.vault-file
```

## Features

- **Fail-safe:** & battle tested. Power outages and fat-fingers won't lose data
- **Recursive:** finds whole-file vaults anywhere under the current directory
- **Supports inline `!vault` values:** decrypted in place inside normal YAML
- **Clean diffs:** only modified files are re-encrypted
- **Re-keying:** re-encrypts all your vaults with a new password after a leak
- **Native Ansible:** uses Ansible's own code for operations - no surprises
- **Better than native:** `pilfer set` inserts a key secret into a vault file in one command
- **New in 3.0, keyring client:** keep the vault password in the macOS Keychain or Linux Secret Service
- **Extensible:** works with any client script, e.g. `age` with a YubiKey or Secure Enclave plugin

## Usage

```
pilfer [--version] COMMAND ...

Commands: open | close | status | find-keys | set | update | rekey | completion | agent-guide

pilfer open [--include-encrypted-vars] [-q] [VAULT OPTIONS]
pilfer close [--confirm-delete] [VAULT OPTIONS]
pilfer status [--json]
pilfer find-keys [-E] [-i] [--path] [--include-encrypted-vars] [-l | --json] [PATTERN ...] [VAULT OPTIONS]
pilfer update [--file FILE] [--include-encrypted-vars] [--dry-run] [VAULT OPTIONS] KEY [VALUE]
pilfer rekey [--old-vault-password-file OLD]... [--old-vault-id ID]... (--new-vault-password-file NEW | --new-vault-id ID) [options]
pilfer set [--dry-run] [VAULT OPTIONS] FILE KEY [VALUE]
pilfer completion [--install] [bash | zsh]
pilfer agent-guide

VAULT OPTIONS: [--vault-id ID]... [-p VAULT_PASSWORD_FILE]... [-J]
```

Run `pilfer --help` or `pilfer COMMAND --help` for full options and examples.

### Check for an open session

`pilfer status` says whether a session is open and which files hold plaintext because of it. It needs no vault password, changes nothing and never prints a value.

```
$ pilfer status
Session open: 2 files hold plaintext. Run 'pilfer close' to re-encrypt them.
  group_vars/all/vault.yml  (whole-file)
  inline.yml  (inline)
```

The other messages:

```
No session open.
Session open: no files hold plaintext. Run 'pilfer close' to clear it.
Session open, but incomplete: open was interrupted before it decrypted anything. Run 'pilfer close' to clear it.
```

If `.vault/` holds leftover backups but there is no session list, `status` says so; `--json` then sets `"orphaned": true`. The check looks only at leftover `.vault/` backups, not plaintext sidecars. Running `open` again also clears an incomplete session while the listed files are still ciphertext. `--json` prints one object, `{"open": true, "incomplete": false, "orphaned": false, "files": [{"file": "...", "kind": "file"}]}`, where `kind` is `file` or `inline`. The exit status is 0 unless something went wrong, such as a damaged session list, which exits 2.

### Find which file holds a key

`pilfer find-keys` lists the keys in your vault files and prints the file and key name for each match. It never prints a value, a length or a hash.

```bash
pilfer find-keys db_password          # exact name
pilfer find-keys '*token*'            # glob; quote it so the shell leaves it alone
pilfer find-keys -E '^ha_(url|token)$'
pilfer find-keys --path 'aws.*.secret_key'
pilfer find-keys --json '*token*'     # one JSON object per line
```

Text output looks like this:

```
group_vars/all/vault.yml: ha_token  (open)
inline/app.yml: db_token  (inline)
t.yml: api_token
```

- A pattern matches the whole key name. `*` and `?` are wildcards; `[` is literal, so `--path 'users[0].*'` matches `users[0].name`. `-E` takes regular expressions that match anywhere in the name (anchor with `^...$`). `-i` ignores case. `--path` matches the full path (`aws.prod.secret_key`) instead of the last name.
- With several patterns, a key matches if any one does. With none, every key is listed. `-l` prints only file names and cannot be combined with `--json`.
- Each `--json` line has `file`; `key`, the last name; `path`, the names and list indexes from the file root; `kind`, `file` or `inline`; `open`, true when read from an open session; and `vault_id`, `default` for a file with no label.
- Exit status: 0 when a key matched, 1 when none did, 2 on an error. A vault file it cannot read or decrypt is named on stderr and gives 2, even when other files matched. It exits 141 if its output pipe closes early, as with `| head`; see [Unreadable files](#unreadable-files).
- Text output escapes characters Python treats as non-printable (`\x1b`, U+202E). `--json` uses standard JSON escapes.

A whole-file vault hides its key names from `grep`. `find-keys` decrypts each file in memory, so it shows those names to anyone who has the password. Pilfer has no value search, which would let you guess a secret. Files open in a session are read from their plaintext and tagged `(open)`. Keys whose value is an inline `!vault` string are skipped unless you pass `--include-encrypted-vars`; they are tagged `(inline)`.

### Update a value you cannot place

`pilfer update KEY [VALUE]` replaces an existing key in whichever vault file holds it:

```bash
pilfer update db_password
```

Values are read as for `pilfer set`.

- Update never creates a key; use `pilfer set FILE KEY` for that. It replaces only a single (scalar) value; a mapping or list is refused.
- `set` and `update` refuse a key path that touches a YAML anchor, alias or `<<` merge, in whole-file vaults and inline `!vault` files alike. Edit those in a `pilfer open` session.
- If several files hold the key, it lists them and asks for `--file FILE`.
- A key that exists only as an inline `!vault` value needs `--include-encrypted-vars`. The new value keeps its vault-id label.
- Files open in a session are refused.
- If a file that might hold the key is unreadable (see [Unreadable files](#unreadable-files)), update refuses and names it; pass `--file FILE` to choose one.

Exit status for `set` and `update`: 0 done or unchanged, 1 refused or failed, 2 usage error. `pilfer update --help` lists the rest.

See [Preview a change, and unchanged values](#preview-a-change-and-unchanged-values) for `--dry-run` and what happens when the value is already stored.

### Unreadable files

Pilfer reads every file in the tree to find vaults. A file that cannot be opened is unreadable, and so is a directory that cannot be listed. A file over 64 MiB is unreadable only if its first 64 MiB holds `$ANSIBLE_VAULT;` or a pilfer marker; otherwise it is skipped as not a vault.

- `rekey` refuses to start if any file is unreadable, whatever its name, and lists up to five.
- `open` warns about up to five, then gives a count. If it found no readable vault, it exits 1 with `No readable vault files found`.
- `find-keys` treats a `.yml`, `.yaml` or `.json` file, or one with no extension, as a possible vault, dotfiles with those extensions included. It names an unreadable one and exits 2. Other files, such as `.env`, only warn.
- `update` refuses when a file it could not read or decrypt might hold the key; pass `--file FILE`.
- A whole-file vault whose name has a binary suffix (`.zip`, `.tar.gz`, `.bin`, `.db`, ...) is not rekeyed. `rekey` refuses while one is in the tree, and `find-keys` and `open` warn about it. Use `ansible-vault rekey`, or move it out of the tree.
- Symlinks are not followed, so `rekey` does not see a vault reached only through a symlink to outside the tree.

### Set a single value

Use `pilfer set` to add or replace a key in a whole-file vault without opening a session:

```bash
pilfer set secrets.yml db_password
```

KEY can be a nested path in Jinja syntax: `aws.prod.secret_key`, `users[0].password` or `aws['key.with.dots']`. Pilfer creates missing mappings along the path. It refuses a path whose parent is not a mapping, or whose list index is out of range. `find-keys` and `update` print and accept the same syntax.

Pilfer prompts for the value without echoing it. You can also pipe a value in:

```bash
printf '%s' "$TOKEN" | pilfer set secrets.yml db_password
```

Piped input drops one trailing newline, so `echo` works too. You can pass the value as the final argument, but pilfer then warns on stderr: it shows in `ps` and shell history, and stdin is safer. Put `--` before a value that starts with `-`.

The value stays in memory and is saved as a string, even if it looks like a YAML boolean or number. New keys are appended; replacing an existing scalar preserves any inline comment on its line. Values containing `{{`, `{%` or `{#` are tagged `!unsafe` so Ansible uses them as typed. An existing `!unsafe` tag is kept when the new text would still load as a string. `!unsafe "0123"`, `!unsafe "yes"`, and `!unsafe` dates are stored as plain quoted strings, because Ansible would otherwise retype them.

Pilfer refuses plaintext files, files in an open Pilfer session, and new keys whose top-level name is not a YAML identifier or that YAML reads as a boolean or null, such as `yes`, `on` and `null`. If the operation fails, the original ciphertext remains unchanged. Pilfer replaces the file while preserving its mode; hard links continue to point to the old content.

#### Set values from Python

Scripts that already hold a secret can use the in-process API to keep it out of command arguments:

```python
from pilfer.vault_set import set_keys

set_keys(path, {key: value}, password_file)
```

`password_file` can be a password file or script path, a `pilfer.vault_secrets.VaultSources` (password files, vault ids, prompt), or `None` for Ansible's config. Ansible reads its config once, when it is first imported, so a script gets the `ansible.cfg` of the directory it imported pilfer from. Failures and refusals raise `PilferError`, including an unreadable password file when no other source loads, a failing password script or failed encryption.

To check whether an update can be made before an action you cannot undo, such as minting a token, call `set_keys` with a placeholder value and `check_only=True`. This performs the edit and encryption and writes a temporary ciphertext file beside the vault, but skips the final rename. It can therefore catch problems such as a read-only directory or full disk.

### Preview a change, and unchanged values

`--dry-run` on `set` and `update` runs every check of a real run and stops before writing. It prints `would update KEY in FILE` or `would add KEY in FILE`:

```bash
pilfer set --dry-run secrets.yml db_password
pilfer update --dry-run db_password
```

It never reads stdin, so nothing prompts. A VALUE on the command line is checked too. Without one, pilfer prints `The value was not checked: stdin was not read.` It still needs the vault password for a whole-file vault, and it refuses what a real run refuses: a missing file, an ambiguous or missing key, a bad path, a file open in a session.

When the new value equals the stored one, `set` and `update` print `unchanged KEY in FILE` and exit 0 without rewriting the file (with `--dry-run` too), so git sees no new vault blob and the modification time stays. The comparison happens in memory. A plain value and an `!unsafe` one differ, so switching between them counts as a change.

### Without a terminal

Pilfer does not wait for input it cannot get. With no terminal, any command that would have to ask stops at once with an error that names the alternative:

- `-J` or `--vault-id LABEL@prompt`: use `-p FILE` or `--vault-id LABEL@FILE`. A password is never read from piped input, so a value piped to `set` or `update` cannot be taken for one.
- `set` or `update` with no VALUE and nothing on stdin: pipe the value in, or pass it as the last argument.
- `rekey` without `--yes`: the `REKEY` confirmation needs a terminal. `--new-vault-id prompt` and `--old-vault-id LABEL@prompt` need one too.

Behaviour at a terminal is unchanged. Piping a value to `set` while typing the password at the terminal still works.

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

pilfer opens `key: !vault |` blocks. Ansible also reads `!vault` values other than `key: !vault |` blocks: list items, flow values, `|-`, `|+` and `>` blocks, and JSON `__ansible_vault` values (the format `ansible-inventory` writes); pilfer does not open or rewrite these, so they stay encrypted. `open` and `find-keys` name the files that have them, and `find-keys` says their keys are not searched.

A vault header is recognised by `$ANSIBLE_VAULT` alone, as Ansible does.

`close` always re-encrypts session entries (whole-file and inline). The
`--include-encrypted-vars` flag is only meaningful on `open`.

The opened file is YAML, and `close` reads each value with a YAML parser, so
what you store is what Ansible would read from that line: `'single quotes'`,
`"escapes like \u00e9"`, plain text, a `|` block you write yourself, and a
comment before the marker all mean what they mean in YAML. Every secret opens
as one double-quoted line, multi-line ones with `\n` escapes, because nothing
an editor does on save can change a quoted line. `open` checks that every
value reads back exactly before it writes anything, and leaves a file that
does not parse as YAML encrypted. `close` checks that the re-encrypted file
reads back as the file you edited, every value included, before it writes;
otherwise it refuses and leaves your edits and the session in place. Close a
session with the pilfer release that opened it: inline sessions from before
2.31 are refused rather than read with different rules.

An inline `!vault` value is always a string to Ansible. If you edit
`db_port: "5432"` to `db_port: 5432`, close stores the string `"5432"` and
says so; convert it where it is used, for example `{{ db_port | int }}`.

If you strip only the `# pilfer:vault:N` comment while leaving the secret,
`close` refuses with:

```text
⚠️  inventory/group_vars/all/all.yml — cannot close (marker missing)
  Variable:     db_password
  Problem:      # pilfer:vault:0 marker was removed but the secret is still in the file.

  Fix:          restore the marker comment on the value line, then pilfer close
```

If you delete the whole opened variable line (key + value + marker), `close`
refuses by default (ambiguous delete vs accident):

```text
⚠️  inventory/group_vars/all/all.yml — cannot close (secret line deleted)
  Variable:     db_password  (# pilfer:vault:0)
  Problem:      opened inline secret was removed from the file.

  Confirm delete:  pilfer close --confirm-delete
  Undo:            restore the line, then pilfer close
```

`pilfer close --confirm-delete` then prints:

```text
🔍 Detected removal of 1 encrypted vars:
  - db_password
```

Renaming the key and dropping the marker is also refused if the secret value is
still present in the file (including in comments).

### Vault passwords

Pilfer loads vault passwords with Ansible's own code, the same call `ansible-vault decrypt` makes. Sources load in this order: `vault_identity_list` from Ansible's config, `--vault-id`, `-p`, `vault_password_file` from the config, then the `-J` prompt. The config is found as Ansible finds it: `ANSIBLE_CONFIG`, `./ansible.cfg`, `~/.ansible.cfg`, `/etc/ansible/ansible.cfg`, and the `ANSIBLE_VAULT_*` environment variables override it.

An executable password file is run and its output is the password, as in [storing passwords in third-party tools](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_managing_passwords.html#storing-passwords-in-third-party-tools-with-vault-password-client-scripts). A script named `*-client` is passed `--vault-id`. Each command runs a script once.

```bash
pilfer open --vault-id dev@~/.local/bin/pilfer-vault-keyring-client --vault-id prod@prompt
```

`close` and `pilfer set` encrypt each value with the password that decrypted it, under its existing vault-id label, as `ansible-vault edit` does. A tree on several vault ids opens and closes in one session, and `close` needs every password that `open` used.

Ansible loads the config's `vault_password_file` even when `-p` or `--vault-id` is given, so a wrong `-p` does not fail by itself. `open` and `set` warn when a password you passed decrypts none of the files. `close` refuses a password that decrypts none of the session's backups when it could be a rotation: an unlabelled `-p`, `-J` or default-id source, or a `--vault-id` whose label a backup in the session carries. A labelled `--vault-id` whose label no backup carries gets a warning. Close never changes a file's password; `pilfer rekey` does.

When neither the flags nor Ansible's config name a source, pilfer tries `~/.ansible-vault/.vault-file`, `.vault_password`, `vault_password_file`, and finally `../../vault_password_file`. These are read as plain password files and never run; only a source named by a flag or `ansible.cfg` can be a script.

**Security:** because pilfer loads passwords as `ansible-vault` does, a `vault_password_file` script named by the project's `ansible.cfg` runs whenever a command needs a password, even with `-p`. In a repo you did not write, read `ansible.cfg` first or point `ANSIBLE_CONFIG` at a file you trust.

#### Passwords in the system keyring

`pilfer-vault-keyring-client`, installed with pilfer, is a client script that reads the vault password from the system keyring: the macOS Keychain or Secret Service on Linux. Ansible runs it like any client script, so `ansible-playbook` and `ansible-vault` read the same password. It needs the keyring extra: `pipx install 'pilfer[keyring]'`, or `pipx inject pilfer keyring` for an existing install.

Point the project's `ansible.cfg` at the path `command -v pilfer-vault-keyring-client` prints:

```ini
[defaults]
vault_password_file = ~/.local/bin/pilfer-vault-keyring-client

; Optional. The keyring service defaults to "ansible", the account to your login name.
[vault]
keyname = myproject
username = ops
```

Then, from the project directory so it reads the same `[vault]` settings, store the password:

```bash
pilfer-vault-keyring-client --set
```

A labelled source reads the service named by its label: `--vault-id prod@~/.local/bin/pilfer-vault-keyring-client` reads `prod`, and `--vault-id prod --set` stores it. An unlabelled source such as `vault_password_file` reads `keyname`, and so does a label equal to the default vault id (`default`, or the value of `vault_identity` in ansible.cfg). A missing password exits 2, which Ansible reports as "did not find a secret". `--set` prints the key, user and keyring backend it writes to, and asks before it replaces a stored password.

The macOS login keychain is locked in SSH sessions, so the script fails there. macOS trusts the Python build that ran `--set` and does not ask again. After a Python upgrade macOS asks once when the new build first reads the entry, and `--set` from the new build replaces it: it deletes the old entry with Apple's `security` tool, because macOS refuses the new build's own delete. A venv runs its base interpreter, so every script that build runs can read the password; where that matters, use a Python build you use for nothing else. Secret Service has no per-program access: any program in your session can read the entry.

The script ports [`vault-keyring-client.py`](https://github.com/ansible-community/contrib-scripts/blob/main/vault/vault-keyring-client.py) from ansible-community, which no longer imports on ansible-core 2.21. It also reads `keyname` for an unlabelled source, where the original looked up a service called `default`: store a password the original saved there again with `--set`.

### Shell completion

```bash
pilfer completion --install
```

This writes a completion script for the shell in `$SHELL`; name `bash` or `zsh` to choose. Other shells are refused. `--install` refuses a symlink at the target. Open a new shell to use it. Pilfer never edits your shell's startup files.

- bash: `${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/pilfer`
- zsh: `~/.zfunc/_pilfer`. Add `fpath=(~/.zfunc $fpath)` above `compinit` in `~/.zshrc`.

Without `--install` the script prints to stdout. It completes commands, options and file paths, never key names.

### For AI agents

`pilfer agent-guide` prints a `SKILL.md` that tells a coding agent to find and change secrets with `find-keys`, `update` and `set`, without printing values. Install it where your agent reads skills:

```bash
mkdir -p ~/.agents/skills/pilfer && pilfer agent-guide > ~/.agents/skills/pilfer/SKILL.md
```

Claude Code reads `~/.claude/skills/pilfer/SKILL.md`. Run the command again after upgrading pilfer.

## Rotating the vault password

`pilfer close` is **not** password rotation - it refuses a different password than
the one used for `open` (anti re-key). `pilfer rekey` rotates every vault target in
the current directory and its subdirectories, including inline `!vault` spans:

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

`--rotate-password-file` keeps the old password in `<file>_old` (mode 0600). Delete it, or move it out of the tree, once nothing needs it. It needs a plain password file on each side: not vault-encrypted, not a script. Before it rewrites anything, it also refuses:

- a password file that is a symlink
- an existing `<file>_old`
- a password-file directory that is not writable

The old password loads like `open`: `--old-vault-password-file` and `--old-vault-id`, plus Ansible's config. The new password comes from the single `--new-vault-password-file` or `--new-vault-id` (`--new-vault-id prompt` asks for it). Rekey refuses an old or new password file that is itself a vault in the tree. The new password file can otherwise be vault-encrypted. A new label must be ASCII, with no `;`, control characters or surrounding spaces. Rekey warns about an `--old-*` flag that decrypts nothing. Values keep their vault-id label unless `--new-vault-id` names one. Rekey refuses a tree encrypted with more than one vault password; use `ansible-vault rekey` per vault id for that. It also refuses `!vault` values in a form pilfer cannot rewrite, because they would stay on the old password. These are the unsupported forms listed under [Inline encrypted variables](#inline-encrypted-variables-encrypt_string--vault). It also refuses a whole-file vault whose plaintext holds inline vault values (`!vault` or JSON `__ansible_vault`), which it cannot rotate inside the outer vault: decrypt it with `ansible-vault`, rekey, and re-encrypt, or move the file out of the tree. A whole-file vault with a binary file name is refused too, as listed under [Unreadable files](#unreadable-files).

Ansible runs a password script, so the password lives somewhere else, such as a keyring. Change it there instead. With `pilfer-vault-keyring-client`, rekey to a typed password while the keyring still holds the old one, then store the same password over it:

```bash
pilfer rekey --new-vault-id prompt
pilfer-vault-keyring-client --set    # answer y to replace the old password
```

For a labelled source, name the label on both: `--new-vault-id prod@prompt`, then `--vault-id prod --set`. The files are already on the new password after the rekey, so run `--set` again until it succeeds.

Refuse to rekey while a pilfer session is open. Nested git checkouts are skipped
(run `pilfer rekey` from those directories separately). Prefer `--dry-run` first.
A mid-run failure can leave a split-password tree; **re-run the same `rekey`
command to resume** (files already on the new password are skipped).
`--rotate-password-file` is refused with `--no-include-encrypted-vars`, and also
when nested git checkouts were skipped, so the live password file is not rotated
while ciphertext remains on the old password. Leftover
`.pilfer-rekey-*` temp files are never vault targets.

## Safety

Pilfer **fails closed**: if it cannot prove a secret is safely re-encrypted or
intentionally removed, it keeps the session and `.vault/` backups and exits
non-zero. It does not invent fixes for ambiguous edits.

### Failure modes this protects against

- Silent re-key on `close` with a different password than `open`
- Double-`open` destroying encrypted backups under `.vault/` (a failed `open` removes only the files it wrote, and `close` never deletes a `.vault` file it did not create)
- Orphan plaintext after deleting `vaultedFileList.json` (markers, `.vault/`, or `*.pilfer-open` sidecars still block re-open)
- Stranded plaintext after stripping markers, renaming keys, or relocating secrets (including into comments)
- Crash mid-decrypt leaving unmarked plaintext (open sidecars are written before plaintext)

### Surprising-by-design behaviors

- **Interrupted close retries:** whole-file targets only count as already done when
  working bytes match the open backup, or the file is vault ciphertext decryptable
  with the session password (not an arbitrary foreign vault blob).
- **`close` is progressive** - files that succeed are encrypted and dropped from the session; failures stay plaintext until you fix and retry. Not an all-or-nothing transaction.
- **Intentional var removal** requires `pilfer close --confirm-delete`. So does deleting a whole vault file while it is open.
- **Short secrets** can block close if the same bytes appear elsewhere in the file (docs/comments) - fail closed.
- **Lock wait and ctrl-c:** a second pilfer run in the same tree waits for the first and prints `Waiting for another pilfer run (lock <path>)...`. Ctrl-c exits 130. If a session is still open after an interrupted `open` or `close`, pilfer says to run `pilfer close`. After an interrupted `rekey`, re-run the same command to resume. If `<password file>_old` already exists, the rotation finished.
- **Nested git checkouts** are skipped; run pilfer from those roots if needed.
- **Password check on close:** `close` proves the password by decrypting a `.vault` backup. The session list stores no hash of the password.
- **File modes:** opened plaintext is `0600`. `close` puts back the mode and group the file had at `open`; `rekey` and `set` keep the file's own. The group is kept only when you are a member of it.
- **Incomplete open** (session list written, crash before decrypt) is cleared on the next `open` only when listed paths still look like vault ciphertext and there are no backups/sidecars - so you are not told to `close` ciphertext. If the session list remains but files are already plaintext (artifacts deleted), `open` still refuses. A malformed session list entry is reported as damaged.
- **Leftover temp files** (`.pilfer-rekey-*`, no extension) from a killed run are deleted by the next `open`, `close` or `rekey`, dry runs included. A temp exists only until its rename, so it is never the only copy of anything, and one from a killed `open` holds plaintext.
- **`*.pilfer-open` sidecars** sit beside opened files (whole-file opens have no `# pilfer:vault:` markers).

### Gitignore

```gitignore
vaultedFileList.json
.vault/
**/*.pilfer-open
# Lock file that exists while pilfer works on a vault. Left behind only if pilfer is killed.
**/*.pilfer-lock
# Temp a killed pilfer can leave beside a file. The next open, close or rekey deletes it.
**/.pilfer-rekey-*
# --rotate-password-file leaves the old password here. Add `<your password file>_old`
# if your password file is inside the project.
.vault_password_old
vault_password_file_old
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
- An error about the session list (damaged, unknown kind, bad path) says how to recover: restore the files from the `.vault/` backups or fix `vaultedFileList.json`, then run `pilfer close`.
- Session deleted but markers / `.vault` / `*.pilfer-open` remain → restore `vaultedFileList.json` from backup if you have it and `close`, or manually re-encrypt / restore secrets before `open`.

## License

GPLv3+. See [`PILFER_LICENSE.txt`](PILFER_LICENSE.txt).

## Credits

Borrows heavily from the excellent, but no longer supported [Ansible Toolkit](https://github.com/dellis23/ansible-toolkit).

Maintainers: development setup, releases, and CI details in [`.github/workflows/README.md`](.github/workflows/README.md).
