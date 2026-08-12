"""Encryption for the one secret torii holds on someone else's behalf: the
credential it presents to an upstream (PRD Q18).

Everything else torii stores is a hash — passwords, keys, tokens — because
torii only ever needs to *verify* those. An upstream's auth header is
different: it has to be replayed verbatim on every proxied call, so it must be
recoverable, and a plaintext column means a `pg_dump` leaks working
credentials.

Envelope format: `enc:v1:<fernet token>`. Two consequences worth knowing:

* A value without the prefix is treated as plaintext and passed through, so a
  row written before this shipped keeps working and gets encrypted the next
  time it's saved. That's what makes this deployable without a data migration
  (there's a CLI for migrating on purpose, rather than doing it implicitly).
* The version is in the envelope, so a future key rotation or algorithm change
  can be told apart from v1 rather than guessed at.
"""

import logging
import os

from . import config

log = logging.getLogger(__name__)

PREFIX = "enc:v1:"


class EncryptionUnavailable(RuntimeError):
    """A stored secret is encrypted but no key is configured.

    Raised at boot rather than per-request: an operator who has lost the key
    should hear about it once, loudly, not as a wall of failing proxy calls
    with a confusing cause.
    """


class PlaintextSecretRefused(RuntimeError):
    """Asked to store an upstream credential with no encryption key set.

    The SAVE path raises this so an admin gets a clear, actionable error
    instead of a working credential silently landing in a plaintext column
    (issue #73 — a claim of "encrypted at rest" that a `pg_dump` disproves).
    Set TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS=1 to consciously downgrade the
    refusal to the old warn-and-store behaviour.
    """


def _allow_plaintext_upstream_secrets() -> bool:
    # Read straight from the environment: config.py is owned elsewhere, and
    # this is a deliberate, rarely-set escape hatch rather than a tunable.
    return os.environ.get(
        "TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS", ""
    ).strip().lower() in ("1", "true", "yes", "on")


def _fernet():
    from cryptography.fernet import Fernet

    if not config.ENCRYPTION_KEY:
        raise EncryptionUnavailable(
            "TORII_ENCRYPTION_KEY is not set, but an encrypted secret exists. "
            "Set it to the key those secrets were written with, or clear the "
            "affected upstream credentials in /ui/admin/upstreams."
        )
    try:
        return Fernet(config.ENCRYPTION_KEY.encode())
    except Exception as exc:  # noqa: BLE001 — a malformed key is operator error
        raise EncryptionUnavailable(f"TORII_ENCRYPTION_KEY is not a valid Fernet key: {exc}")


def available() -> bool:
    return bool(config.ENCRYPTION_KEY)


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(PREFIX)


def encrypt_secret(value: str | None) -> str | None:
    """Encrypt an upstream credential for storage.

    With a key set, returns the `enc:v1:` envelope. Empty values and
    already-encrypted values pass through untouched — so an admin editing
    other fields without re-entering a secret never triggers this.

    With NO key set, refuses (raises `PlaintextSecretRefused`) rather than
    silently persisting plaintext: the boot check can't see the "key never
    set" case, and a plaintext column contradicts the "encrypted at rest"
    promise (issue #73). `TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS=1` restores
    the old warn-and-store behaviour for a deployment that truly wants it.
    """
    if value is None or value == "":
        return value
    if is_encrypted(value):
        return value
    if not available():
        if _allow_plaintext_upstream_secrets():
            log.warning(
                "storing an upstream credential in plaintext: TORII_ENCRYPTION_KEY "
                "is unset and TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS is set"
            )
            return value
        raise PlaintextSecretRefused(
            "Refusing to store an upstream credential: TORII_ENCRYPTION_KEY is not "
            "set, so it could only be written in plaintext. Set an encryption key "
            "(see DEPLOY.md), or set TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS=1 to "
            "store it unencrypted anyway."
        )
    return PREFIX + _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str | None) -> str | None:
    """Recover a stored secret. Passes plaintext through unchanged."""
    if not is_encrypted(value):
        return value
    token = value[len(PREFIX):].encode()
    from cryptography.fernet import InvalidToken

    try:
        return _fernet().decrypt(token).decode()
    except InvalidToken:
        # Wrong key, or a corrupted row. Returning None makes the upstream call
        # fail with "no credential" rather than sending garbage as a bearer
        # token — a 401 from the backend is easier to diagnose than a mangled
        # header.
        log.error("could not decrypt an upstream credential: wrong TORII_ENCRYPTION_KEY?")
        return None


async def assert_key_present_if_needed(conn) -> None:
    """Boot check: encrypted rows without a key is a stop-everything condition.

    Called from the app lifespan. The alternative — discovering it when the
    first proxied call fails — hides the cause behind an upstream error.
    """
    if available():
        return
    encrypted = await conn.fetchval(
        "SELECT count(*) FROM upstreams WHERE auth_header_value LIKE $1", PREFIX + "%"
    )
    if encrypted:
        raise EncryptionUnavailable(
            f"{encrypted} upstream credential(s) are encrypted but "
            "TORII_ENCRYPTION_KEY is not set."
        )
