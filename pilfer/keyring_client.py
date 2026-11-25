"""Vault password client script that reads the password from the system keyring.

Installed as ``pilfer-vault-keyring-client`` by ``pip install 'pilfer[keyring]'``.
Ansible treats an executable named ``*-client`` as a vault password client
script: it runs it with ``--vault-id NAME`` and reads the password from stdout.
ansible-vault, ansible-playbook and pilfer all load it the same way, from
``vault_password_file``, ``vault_identity_list``, ``--vault-id label@PATH`` or
``--vault-password-file PATH``.

Ported from vault-keyring-client.py in ansible-community/contrib-scripts
(GPL-3.0-or-later):

    (c) 2014, Matt Martz <matt@sivel.net>
    (c) 2016, Justin Mayer <https://justinmayer.com/>

It keeps that script's interface: the keyring service is the vault id, or the
``keyname`` option in ansible.cfg's ``[vault]`` section, or ``ansible``; the
account is ``--username``, ``[vault] username``, or the login name; ``--set``
stores a password; exit code 2 means no password is stored, which Ansible
reports as "did not find a secret for vault-id". Changes from the original:

- It reads ``[vault]`` from ``ansible.constants.CONFIG_FILE`` with configparser.
  The original imports ``get_ini_config_value`` from ansible.config.manager,
  which ansible-core 2.21 no longer has (it became the private
  ``ConfigManager._get_ini_config_value``), so it fails to import.
- ``--vault-id default`` uses ``keyname``. Ansible always passes ``--vault-id``,
  and a password file with no label gets the id ``default``, so with
  ``vault_password_file = .../pilfer-vault-keyring-client`` the original
  looked up a service called ``default`` and ignored ``keyname``.
- Values in ``[vault]`` are unquoted as Ansible unquotes its own ini settings,
  so ``username = 'ansible-vault'`` (the original's own example) means
  ``ansible-vault``, not ``'ansible-vault'`` with the quotes.
- A keyring error (a locked keychain, no usable backend) exits 1 with one line
  on stderr instead of a traceback, and ``--set`` refuses an empty password,
  which Ansible would refuse to use.
"""

import argparse
import configparser
import getpass
import sys

from ansible.parsing.quoting import unquote

# ansible.parsing.vault.ClientScriptVaultSecret.VAULT_ID_UNKNOWN_RC: Ansible
# reports this exit code as "did not find a secret for vault-id=...".
KEYNAME_UNKNOWN_RC = 2
DEFAULT_KEYNAME = "ansible"
# ansible.constants.DEFAULT_VAULT_IDENTITY, the id Ansible gives a password
# file or script that has no label. Not a keyring service name.
UNLABELLED_VAULT_ID = "default"


def vault_settings(config_file: str | None) -> tuple[str | None, str | None]:
    """(keyname, username) from the [vault] section of an ansible.cfg, or None each."""
    if not config_file:
        return None, None
    # Parsed as ansible.config.manager parses it, so a file Ansible already
    # loaded parses here too.
    parser = configparser.ConfigParser(inline_comment_prefixes=(";",))
    parser.read(config_file, encoding="utf-8")

    def option(key: str) -> str | None:
        value = parser.get("vault", key, raw=True, fallback=None)
        if value is None:
            return None
        return unquote(value.strip()) or None

    return option("keyname"), option("username")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pilfer-vault-keyring-client",
        description="Get an Ansible vault password from the system keyring (an Ansible vault password client script).",
        epilog=(
            "The keyring service is the vault id, else [vault] keyname in ansible.cfg, else 'ansible'. "
            "Ansible passes --vault-id default for an unlabelled password file; that also uses keyname."
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
        help="set the password instead of getting it",
    )
    return parser


def _config_file() -> str | None:
    # The config file Ansible itself would load: ANSIBLE_CONFIG, ./ansible.cfg,
    # ~/.ansible.cfg, /etc/ansible/ansible.cfg. Ansible runs this script in its
    # own working directory and environment, so it finds the same file.
    import ansible.constants as C

    return C.CONFIG_FILE


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        import keyring
        from keyring.errors import KeyringError
    except ImportError:
        sys.stderr.write(
            "pilfer-vault-keyring-client needs the keyring package: pip install 'pilfer[keyring]'\n"
        )
        return 1

    config_keyname, config_username = vault_settings(_config_file())
    username = args.username or config_username or getpass.getuser()
    vault_id = args.vault_id if args.vault_id != UNLABELLED_VAULT_ID else None
    keyname = vault_id or config_keyname or DEFAULT_KEYNAME

    try:
        if args.set_password:
            sys.stdout.write(
                f'Storing password in "{username}" user keyring using key name: {keyname}\n'
            )
            password = getpass.getpass()
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                sys.stderr.write("Passwords do not match\n")
                return 1
            if not password:
                sys.stderr.write(
                    "Refusing an empty password: Ansible rejects an empty vault password\n"
                )
                return 1
            keyring.set_password(keyname, username, password)
            return 0

        secret = keyring.get_password(keyname, username)
    except KeyringError as exc:
        sys.stderr.write(
            f"pilfer-vault-keyring-client: keyring error for key={keyname!r} user={username!r}: {exc}\n"
        )
        return 1

    if secret is None:
        sys.stderr.write(
            f'pilfer-vault-keyring-client could not find key="{keyname}" for user="{username}" '
            f'via backend="{keyring.get_keyring().name}"\n'
        )
        return KEYNAME_UNKNOWN_RC

    sys.stdout.write(f"{secret}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
