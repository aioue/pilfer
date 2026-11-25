# Copyright: (c) 2026, Tom Paine <github@aioue.net>
# GNU General Public License v3.0+ (see PILFER_LICENSE.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Vault secrets, loaded and used the way ansible-vault does it.

pilfer used to read one password file itself. That missed password scripts
(an executable whose stdout is the password, issue #18), `-client` scripts
that are passed --vault-id, vault_identity_list, prompts, and Ansible's config
search (ANSIBLE_CONFIG, ./ansible.cfg, ~/.ansible.cfg, ANSIBLE_VAULT_* env).
Loading is now CLI.setup_vault_secrets, the call `ansible-vault decrypt`
makes, fed from ansible.constants.

ansible.constants reads the config once, when Ansible is first imported. A
library caller gets the config of the directory it imported pilfer from, as
with any Ansible Python API.

Encrypting follows `ansible-vault edit`: the secret that decrypted the
original, under the original's vault-id label. VaultLib.encrypt without a
secret takes the first one loaded, which is wrong once there are several.
"""

import os
from dataclasses import dataclass

import ansible.constants as C
from ansible.errors import AnsibleError
from ansible.parsing.vault import (
    AnsibleVaultFormatError,
    FileVaultSecret,
    PromptVaultSecret,
    VaultLib,
    VaultSecret,
    get_file_vault_secret,
    parse_vaulttext_envelope,
)

from pilfer.errors import PilferError

# pilfer-only, tried when neither the flags nor Ansible's config name a source.
# Named paths first. The parent-relative file is an ansible-toolkit layout;
# checking it earlier silently beat ~/.ansible-vault/.vault-file.
FALLBACK_PASSWORD_FILES = (
    "~/.ansible-vault/.vault-file",
    ".vault_password",
    "vault_password_file",
    "../../vault_password_file",
)

NO_SOURCE_MESSAGE = (
    "No vault password source. Pass -p FILE, --vault-id or -J, or set "
    "vault_password_file or vault_identity_list in ansible.cfg."
)

Secrets = list[tuple[str, VaultSecret]]


class RoundTripError(PilferError):
    """New ciphertext did not decrypt to its plaintext with the secret it was made with."""


class VaultLabelError(ValueError):
    """The vault-id label cannot be written back.

    Ansible's is_encrypted() rejects any non-ASCII byte in the blob, so a
    UTF-8 label (or a U+FFFD substituted for one) becomes a file Ansible
    will not decrypt. Callers leave the original ciphertext in place.
    """


@dataclass(frozen=True)
class VaultSources:
    """The vault password flags ansible-vault takes, as pilfer received them."""

    password_files: tuple[str, ...] = ()
    vault_ids: tuple[str, ...] = ()
    ask: bool = False

    @classmethod
    def of(cls, value) -> "VaultSources":
        """Accept a VaultSources, one password file path, or None (config only)."""
        if value is None:
            return cls()
        if isinstance(value, VaultSources):
            return value
        return cls(password_files=(os.fspath(value),))

    @property
    def single_password_file(self) -> str | None:
        """The path when the only source is one password file, else None."""
        if len(self.password_files) == 1 and not self.vault_ids and not self.ask:
            return self.password_files[0]
        return None


def _cli():
    # Imported here, not at module level: ansible.cli runs check_blocking_io()
    # and initialize_locale() on import, and both raise SystemExit. The pilfer
    # CLI would exit as ansible-vault does; set_keys promises a PilferError.
    try:
        from ansible.cli import CLI
    except SystemExit as exc:
        raise PilferError(str(exc)) from None
    return CLI


def _loader():
    from ansible.parsing.dataloader import DataLoader

    return DataLoader()


def fallback_password_file() -> str | None:
    for location in FALLBACK_PASSWORD_FILES:
        expanded = os.path.expanduser(location)
        if os.path.exists(expanded):
            return expanded
    return None


def load_secrets(sources=None) -> Secrets:
    """Every secret Ansible would load for these flags, as [(vault_id, secret)].

    vault_identity_list comes first, then --vault-id, then the password files,
    and ansible.cfg's vault_password_file last: setup_vault_secrets appends it.
    A source that fails is a warning while another loads, as in ansible-vault.
    Each source is read or run once per call, so a command calls this once.
    """
    sources = VaultSources.of(sources)
    password_files = list(sources.password_files)
    vault_ids = [*C.DEFAULT_VAULT_IDENTITY_LIST, *sources.vault_ids]
    if not (password_files or vault_ids or sources.ask or C.DEFAULT_VAULT_PASSWORD_FILE):
        fallback = fallback_password_file()
        if fallback is None:
            raise PilferError(NO_SOURCE_MESSAGE)
        password_files.append(fallback)
    try:
        secrets = _cli().setup_vault_secrets(
            _loader(),
            vault_ids=vault_ids,
            vault_password_files=password_files,
            ask_vault_pass=sources.ask,
            # A prompt only when asked for (-J, or a "prompt" vault id).
            auto_prompt=False,
            # pilfer decrypts through VaultLib, not templating, so it needs no
            # ambient context. The default True raises on a second call in one
            # process, and rekey loads two sets of secrets.
            initialize_context=False,
        )
    except AnsibleError as exc:
        raise PilferError(f"vault password: {exc}") from None
    if not secrets:
        raise PilferError(NO_SOURCE_MESSAGE)
    return secrets


class SourceVault(VaultLib):
    """A VaultLib that records which secrets decrypted something.

    Ansible always loads ansible.cfg's vault_password_file beside -p and
    --vault-id, so a wrong -p no longer fails on its own: the config password
    decrypts the files. explicit pairs each flag with the secret it loaded
    (None when it failed to load). unused_explicit() names the flags whose
    password decrypted nothing, so close can refuse and open and set can warn.
    VaultLib.decrypt goes through decrypt_and_get_vault_id, so every decrypt
    is seen without decrypting anything twice.
    """

    def __init__(self, secrets: Secrets, explicit=()):
        super().__init__(secrets)
        self.explicit: list[tuple[str, VaultSecret | None]] = list(explicit)
        self.used: set[bytes] = set()

    def decrypt_and_get_vault_id(self, vaulttext):
        result = super().decrypt_and_get_vault_id(vaulttext)
        self.used.add(result[2].bytes)
        return result

    def unused_explicit(self) -> list[str]:
        # Bytes, not identity: the same password can load twice (vault_identity_list
        # and -p naming one file), and either copy may be the one that decrypts.
        return [
            flag
            for flag, secret in self.explicit
            if secret is None or secret.bytes not in self.used
        ]


def _explicit_secrets(sources: VaultSources, secrets: Secrets) -> list:
    """Pair each flag in sources with the secret setup_vault_secrets loaded for it."""
    from ansible.utils.path import unfrackpath

    def by_file(path: str) -> VaultSecret | None:
        # get_file_vault_secret stores the path unfracked without following links.
        target = unfrackpath(path, follow=False)
        return next((s for _id, s in secrets if getattr(s, "filename", None) == target), None)

    def by_prompt(vault_id: str) -> VaultSecret | None:
        return next(
            (
                s
                for _id, s in secrets
                if isinstance(s, PromptVaultSecret) and s.vault_id == vault_id
            ),
            None,
        )

    found = [(f"-p {path}", by_file(path)) for path in sources.password_files]
    for slug in sources.vault_ids:
        label, source = _cli().split_vault_id(slug)
        if source in ("prompt", "prompt_ask_vault_pass"):
            found.append((f"--vault-id {slug}", by_prompt(label or C.DEFAULT_VAULT_IDENTITY)))
        else:
            found.append((f"--vault-id {slug}", by_file(source)))
    if sources.ask:
        found.append(("-J", by_prompt(C.DEFAULT_VAULT_IDENTITY)))
    return found


def load_vault(sources=None) -> SourceVault:
    sources = VaultSources.of(sources)
    secrets = load_secrets(sources)
    return SourceVault(secrets, _explicit_secrets(sources, secrets))


def load_new_secret(sources) -> tuple[str, VaultSecret]:
    """The one secret rekey encrypts with, from exactly one --new-* source.

    Not setup_vault_secrets. It appends ansible.cfg's vault_password_file,
    which is the old password, and when the named source fails it warns and
    returns the rest, so a mistyped path would leave the old password chosen
    as the new one. These are the calls it makes for a single source.
    """
    sources = VaultSources.of(sources)
    default = C.DEFAULT_VAULT_IDENTITY
    slugs = [*sources.vault_ids, *(f"{default}@{path}" for path in sources.password_files)]
    if sources.ask:
        slugs.append(f"{default}@prompt")
    if len(slugs) != 1:
        raise PilferError("rekey needs exactly one new vault password source")
    vault_id, source = _cli().split_vault_id(slugs[0])
    vault_id = vault_id or default
    try:
        if source in ("prompt", "prompt_ask_vault_pass"):
            secret = PromptVaultSecret(
                prompt_formats=[
                    "New vault password (%(vault_id)s): ",
                    "Confirm new vault password (%(vault_id)s): ",
                ],
                vault_id=vault_id,
            )
        else:
            secret = get_file_vault_secret(filename=source, vault_id=vault_id, loader=_loader())
        secret.load()
    except AnsibleError as exc:
        raise PilferError(f"new vault password: {exc}") from None
    return vault_id, secret


def is_plain_password_file(path: str) -> bool:
    """True when Ansible reads path as the password, rather than running it."""
    try:
        secret = get_file_vault_secret(filename=path, loader=_loader())
    except AnsibleError as exc:
        raise PilferError(f"vault password: {exc}") from None
    # ScriptVaultSecret and ClientScriptVaultSecret subclass FileVaultSecret.
    return type(secret) is FileVaultSecret


def password_file_secret(path: str) -> VaultSecret:
    """Load one password file or script, as Ansible would."""
    try:
        secret = get_file_vault_secret(filename=path, loader=_loader())
        secret.load()
    except AnsibleError as exc:
        raise PilferError(f"vault password: {exc}") from None
    return secret


def vault_label(ciphertext: bytes) -> str | None:
    """The vault-id label of a 1.2 header, or None for a 1.1 header.

    Malformed headers give None; decrypting them fails with its own error.
    """
    try:
        _, version, _, label = parse_vaulttext_envelope(ciphertext)
    except AnsibleVaultFormatError:
        return None
    if version != b"1.2":
        return None
    if not label.isascii():
        raise VaultLabelError(
            "vault header label is not ASCII; Ansible would reject the re-encrypted file"
        )
    return label or None


def secret_for(vault: VaultLib, ciphertext: bytes) -> VaultSecret:
    """The secret that decrypts ciphertext (ansible-vault edit's choice). Raises if none."""
    _, _, secret = vault.decrypt_and_get_vault_id(ciphertext)
    return secret


def single_secret_vault(secret: VaultSecret, label: str | None) -> VaultLib:
    """A VaultLib holding only secret, registered under label.

    The label matters only with vault_id_match = True, which needs the
    header's label among the registered ids. A 1.1 header reads as "default".
    """
    return VaultLib([(label or C.DEFAULT_VAULT_IDENTITY, secret)])


def encrypt_with(secret: VaultSecret, plaintext: bytes, label: str | None) -> bytes:
    """Encrypt under label with exactly this secret, and prove it reads back with it alone."""
    ciphertext = VaultLib().encrypt(plaintext, secret=secret, vault_id=label)
    try:
        ok = single_secret_vault(secret, label).decrypt(ciphertext) == plaintext
    except AnsibleError:
        ok = False
    if not ok:
        raise RoundTripError(
            "new ciphertext does not decrypt to its plaintext with the password it was "
            "made with; nothing written"
        )
    return ciphertext


def encrypt_like(vault: VaultLib, plaintext: bytes, original: bytes) -> bytes:
    """Encrypt plaintext with the secret and label of original, as ansible-vault edit does.

    With dev@ and prod@ identities, a prod file must come back under prod's
    password. VaultLib.encrypt(plaintext, vault_id="prod") alone would label it
    prod and encrypt it with whichever secret loaded first.
    """
    label = vault_label(original)
    return encrypt_with(secret_for(vault, original), plaintext, label)


def decrypts(vault: VaultLib, ciphertext: bytes) -> bool:
    """True if vault decrypts ciphertext. Ansible raises several types for a wrong password."""
    try:
        vault.decrypt(ciphertext)
    except Exception:
        return False
    return True
