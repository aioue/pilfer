"""Vault password client script that reads the password from the system keyring.

Installed with pilfer as ``pilfer-vault-keyring-client``; it needs the keyring
extra, ``pip install 'pilfer[keyring]'``.

Ansible runs an executable named ``*-client`` as a vault password client script,
passing ``--vault-id NAME`` when the source has an id, and uses its stdout as the
password. ansible-vault, ansible-playbook and pilfer all load it that way.

Ported from vault-keyring-client.py in ansible-community/contrib-scripts
(GPL-3.0-or-later):

    (c) 2014, Matt Martz <matt@sivel.net>
    (c) 2016, Justin Mayer <https://justinmayer.com/>

Same interface as the original: service is the vault id, else ``[vault] keyname``,
else ``ansible``; ``--set`` stores a password; exit code 2 means none is stored.
Where this differs from the original, the comment at that line says why.
"""

import argparse
import getpass
import sys

import ansible.constants as C
from ansible.errors import AnsibleError

PROG = "pilfer-vault-keyring-client"
# ansible.parsing.vault.ClientScriptVaultSecret.VAULT_ID_UNKNOWN_RC: Ansible
# reports this exit code as "did not find a secret for vault-id=...".
KEYNAME_UNKNOWN_RC = 2
DEFAULT_KEYNAME = "ansible"

# The [vault] options, declared to Ansible's ConfigManager as a plugin declares
# its options, so the file Ansible loaded is read with Ansible's own parsing:
# encoding, quotes, inline comments. The original imported
# ansible.config.manager.get_ini_config_value, which ansible-core 2.21 removed.
_OPTIONS_OWNER = ("vault", "pilfer_keyring_client")
_VAULT_OPTIONS = {
    name: {"type": "str", "default": None, "ini": [{"section": "vault", "key": name}]}
    for name in ("keyname", "username")
}


def vault_settings() -> tuple[str | None, str | None]:
    """(keyname, username) from [vault] in the ansible.cfg Ansible loaded, or None each."""
    C.config.initialize_plugin_configuration_definitions(*_OPTIONS_OWNER, _VAULT_OPTIONS)
    options = C.config.get_plugin_options(*_OPTIONS_OWNER)
    # str(): a plain string, not Ansible's tagged str subclass.
    return tuple(str(options[name]) if options[name] else None for name in ("keyname", "username"))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Get an Ansible vault password from the system keyring (an Ansible vault password client script).",
        epilog=(
            "The keyring service is the vault id, else [vault] keyname in ansible.cfg, else 'ansible'. "
            "The id Ansible gives an unlabelled password file, the configured default vault id "
            "('default' unless vault_identity is set), also uses keyname."
        ),
    )
    parser.add_argument(
        "--vault-id",
        help="name of the vault secret to get from keyring",
    )
    parser.add_argument("--username", help="the username whose keyring is queried")
    parser.add_argument(
        "--set",
        action="store_true",
        dest="set_password",
        help="set the password instead of getting it; asks before replacing a stored one",
    )
    return parser


def _store(backend, keyname: str, username: str, where: str) -> int:
    # Here, not at the top: keyring is the optional extra, and
    # ansible.parsing.vault runs Display() on import, which the lookup that
    # writes the password to stdout has no use for.
    import keyring.errors
    from ansible.parsing.vault import PromptVaultSecret, verify_secret_is_not_empty

    # Names and paths come from ansible.cfg and its directory: repr keeps
    # control characters out of the terminal.
    config = repr(C.CONFIG_FILE) if C.CONFIG_FILE else "none found"
    # Not in the original. Replacing the entry loses the password files may
    # still be encrypted with: `pilfer rekey` first, then --set.
    replacing = backend.get_password(keyname, username) is not None
    # Notices and questions go to stderr with the password prompts: piped,
    # stdout is block-buffered and would print them out of order (and input()
    # writes its prompt to stdout).
    if replacing:
        sys.stderr.write(
            f"A password is already stored as {where} (config: {config}) via {backend.name!r}. "
            "Files still encrypted with it will not open after this (pilfer rekey first). "
            "Replace it? [y/N] "
        )
        sys.stderr.flush()
        try:
            answer = input()
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            sys.stderr.write(f"{PROG}: kept the stored password\n")
            return 1
    else:
        sys.stderr.write(f"Storing a password as {where} (config: {config}) via {backend.name!r}\n")
    # Ansible's own prompt, as `ansible-vault --ask-vault-pass` asks: strips
    # whitespace, confirms, and turns ctrl-d into an error.
    secret = PromptVaultSecret(
        vault_id=repr(keyname),
        prompt_formats=[
            "New vault password (%(vault_id)s): ",
            "Confirm new vault password (%(vault_id)s): ",
        ],
    )
    try:
        secret.load()
        # Not in the original. PromptVaultSecret refuses an empty answer before
        # it strips, so spaces alone would store "" over the old password.
        verify_secret_is_not_empty(secret.bytes, "refusing an empty password")
    except AnsibleError as exc:
        # str, not repr: these messages are fixed strings or embed repr(keyname).
        sys.stderr.write(f"{PROG}: {exc}\n")
        return 1
    except UnicodeError as exc:
        # An answer that is not UTF-8 fails in getpass (decode, on a terminal)
        # or in PromptVaultSecret's strict encode (piped input). The message
        # names one escaped byte and its position, not the password.
        sys.stderr.write(f"{PROG}: the password is not valid UTF-8 ({exc})\n")
        return 1
    password = secret.bytes.decode()
    # Not in the original: confirm the write. A backend can drop it (keyring's
    # null backend does), and macOS replaces by delete then add, so a failure
    # from here on may already have removed the old password. set_password can
    # also block on a keychain unlock or access dialog, so ctrl-c lands here too.
    try:
        backend.set_password(keyname, username, password)
        stored = backend.get_password(keyname, username)
        if stored == password:
            return 0
        problem = "nothing is stored" if stored is None else "a different value is stored"
    except keyring.errors.KeyringError as exc:
        problem = repr(exc)
    except KeyboardInterrupt:
        # rc 1, not 130: the write may have started (a Keychain dialog can hold
        # it), and "interrupted" alone would suggest nothing changed.
        problem = "interrupted"
    lost = "; the old one may be gone" if replacing else ""
    sys.stderr.write(
        f"{PROG}: could not confirm the new password for {where} ({problem}){lost}. "
        "Run --set again\n"
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        # Anywhere after argument parsing: the backend load (a Secret Service
        # D-Bus probe can block), the lookup, or the prompts.
        sys.stderr.write(f"{PROG}: interrupted\n")
        return 130


def _run(args: argparse.Namespace) -> int:
    try:
        # Imported here: keyring is the optional extra, and --help and this hint
        # must work without it. keyring.errors is named because this catches
        # its KeyringError; `import keyring` binds it only as a side effect.
        import keyring.errors
    except ImportError:
        sys.stderr.write(
            f"{PROG} needs the keyring package: pip install 'pilfer[keyring]' (or: pipx inject pilfer keyring)\n"
        )
        return 1

    try:
        backend = keyring.get_keyring()
    except Exception as exc:
        # A backend named by PYTHON_KEYRING_BACKEND or keyringrc.cfg that fails to
        # load raises its own import or setup error, not a KeyringError.
        sys.stderr.write(f"{PROG}: cannot load the keyring backend: {exc!r}\n")
        return 1

    config_keyname, config_username = vault_settings()
    try:
        username = args.username or config_username or getpass.getuser()
    except (OSError, KeyError):
        # No login name (a container with an arbitrary uid; ansible-core guards the same call).
        sys.stderr.write(f"{PROG}: no login name; pass --username or set [vault] username\n")
        return 1
    # An unlabelled vault_password_file gets Ansible's own id,
    # C.DEFAULT_VAULT_IDENTITY ("default" unless vault_identity is set). The
    # original looked that up as a service name and ignored keyname.
    vault_id = None if args.vault_id == C.DEFAULT_VAULT_IDENTITY else args.vault_id
    keyname = vault_id or config_keyname or DEFAULT_KEYNAME
    # repr: the names come from ansible.cfg and must not inject terminal codes.
    where = f"key={keyname!r} user={username!r}"

    try:
        if args.set_password:
            return _store(backend, keyname, username, where)
        secret = backend.get_password(keyname, username)
    except keyring.errors.KeyringError as exc:
        # Not in the original, which let a traceback through.
        sys.stderr.write(f"{PROG}: keyring error for {where}: {exc!r}\n")
        return 1

    if secret is None:
        sys.stderr.write(f"{PROG} could not find {where} via backend={backend.name!r}\n")
        return KEYNAME_UNKNOWN_RC
    if not secret:
        # Not in the original, which printed an empty line. Ansible would then
        # fail with a confusing vault error instead of naming the entry.
        sys.stderr.write(f"{PROG}: the stored password for {where} is empty\n")
        return 1

    # Ansible reads bytes. UTF-8 whatever stdout's encoding, as a password file
    # or Ansible's prompt would give.
    sys.stdout.buffer.write(secret.encode() + b"\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
