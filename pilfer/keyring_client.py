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

Same interface: the keyring service is the vault id, else ``keyname`` in
ansible.cfg's ``[vault]`` section, else ``ansible``; the account is
``--username``, else ``[vault] username``, else the login name; ``--set`` stores
a password; exit code 2 means none is stored. Where this differs from the
original, the comment at that line says why.
"""

import argparse
import getpass
import sys

import ansible.constants as C
from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_bytes, to_text

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


def _printable(text) -> str:
    """text with control characters escaped: names and paths come from ansible.cfg and its directory."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(text))


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse exits 2, which Ansible would report as "did not find a secret".
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {_printable(message)}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
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
        default=None,
        dest="vault_id",
        help="name of the vault secret to get from keyring",
    )
    parser.add_argument("--username", default=None, help="the username whose keyring is queried")
    parser.add_argument(
        "--set",
        action="store_true",
        default=False,
        dest="set_password",
        help="set the password instead of getting it; asks before replacing a stored one",
    )
    return parser


def _store(keyring, keyname: str, username: str, where: str) -> int:
    # Here, not at the top: Display() runs on import, and the lookup that
    # writes the password to stdout has no use for it.
    from ansible.parsing.vault import PromptVaultSecret

    config = _printable(C.CONFIG_FILE or "none")
    # Not in the original. Replacing the entry loses the password files may
    # still be encrypted with: `pilfer rekey` first, then --set.
    if keyring.get_password(keyname, username) is not None:
        try:
            answer = input(
                f"A password is already stored as {where} (config: {config}). "
                "Files still encrypted with it will not open after this (pilfer rekey first). "
                "Replace it? [y/N] "
            )
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            sys.stderr.write(f"{PROG}: kept the stored password\n")
            return 1
    else:
        sys.stdout.write(f"Storing a password as {where} (config: {config})\n")
    # Ansible's own prompt, as `ansible-vault --ask-vault-pass` asks: strips
    # whitespace, confirms, and turns ctrl-d into an error.
    secret = PromptVaultSecret(
        vault_id=_printable(keyname),
        prompt_formats=[
            "New vault password (%(vault_id)s): ",
            "Confirm new vault password (%(vault_id)s): ",
        ],
    )
    try:
        secret.load()
    except AnsibleError as exc:
        sys.stderr.write(f"{PROG}: {_printable(exc)}\n")
        return 1
    # Not in the original. PromptVaultSecret refuses an empty answer before it
    # strips, so spaces alone would store "" over the old password.
    if not secret.bytes:
        sys.stderr.write(f"{PROG}: refusing an empty password\n")
        return 1
    password = to_text(secret.bytes, errors="strict")
    # Not in the original: confirm the write. A backend can drop it (keyring's
    # null backend does), and macOS replaces by delete then add, so a failure
    # from here on may already have removed the old password.
    from keyring.errors import KeyringError

    try:
        keyring.set_password(keyname, username, password)
        stored = keyring.get_password(keyname, username)
        problem = (
            None
            if stored == password
            else "nothing is stored"
            if stored is None
            else "a different value is stored"
        )
    except (KeyringError, KeyboardInterrupt) as exc:
        problem = _printable(exc) or type(exc).__name__
    if problem:
        sys.stderr.write(
            f"{PROG}: could not confirm the new password for {where} ({problem}); the old one may be gone. "
            "Check with a lookup (no --set) and run --set again\n"
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        # Imported here: keyring is the optional extra, and --help and this hint
        # must work without it.
        import keyring
        from keyring.errors import KeyringError
    except ImportError:
        sys.stderr.write(
            f"{PROG} needs the keyring package: pip install 'pilfer[keyring]' (or: pipx inject pilfer keyring)\n"
        )
        return 1

    config_keyname, config_username = vault_settings()
    username = args.username or config_username or getpass.getuser()
    # An unlabelled vault_password_file gets Ansible's own id,
    # C.DEFAULT_VAULT_IDENTITY ("default" unless vault_identity is set). The
    # original looked that up as a service name and ignored keyname.
    vault_id = None if args.vault_id == C.DEFAULT_VAULT_IDENTITY else args.vault_id
    keyname = vault_id or config_keyname or DEFAULT_KEYNAME
    # repr: the names come from ansible.cfg and must not inject terminal codes.
    where = f"key={keyname!r} user={username!r}"

    try:
        if args.set_password:
            return _store(keyring, keyname, username, where)
        secret = keyring.get_password(keyname, username)
    except KeyringError as exc:
        # Not in the original, which let a traceback through.
        sys.stderr.write(f"{PROG}: keyring error for {where}: {_printable(exc)}\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write(f"{PROG}: interrupted\n")
        return 130

    if secret is None:
        sys.stderr.write(
            f"{PROG} could not find {where} via backend={keyring.get_keyring().name!r}\n"
        )
        return KEYNAME_UNKNOWN_RC

    # Ansible reads bytes. UTF-8 whatever stdout's encoding, as a password file
    # or Ansible's prompt would give.
    sys.stdout.buffer.write(to_bytes(secret, errors="strict") + b"\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
