"""Encryption of the upstream credential (Q18).

The property that matters: what's in the column is not the secret, and the
secret still reaches the upstream. Everything else here is about failing
usefully — wrong key, missing key, legacy plaintext.
"""

import pytest
from cryptography.fernet import Fernet

from torii import config, crypto, proxy

KEY = Fernet.generate_key().decode()
OTHER_KEY = Fernet.generate_key().decode()
SECRET = "Bearer up_super-secret-upstream-token"


@pytest.fixture
def with_key(monkeypatch):
    monkeypatch.setattr(config, "ENCRYPTION_KEY", KEY)


def test_round_trip(with_key):
    stored = crypto.encrypt_secret(SECRET)
    assert stored.startswith("enc:v1:")
    assert SECRET not in stored
    assert crypto.decrypt_secret(stored) == SECRET


def test_ciphertext_differs_each_time(with_key):
    """Fernet includes a nonce, so the same secret never looks the same twice —
    two upstreams sharing a credential shouldn't be detectable from the rows."""
    assert crypto.encrypt_secret(SECRET) != crypto.encrypt_secret(SECRET)


def test_encrypting_twice_is_a_no_op(with_key):
    once = crypto.encrypt_secret(SECRET)
    assert crypto.encrypt_secret(once) == once


def test_empty_values_pass_through(with_key):
    assert crypto.encrypt_secret(None) is None
    assert crypto.encrypt_secret("") == ""
    assert crypto.decrypt_secret(None) is None


def test_legacy_plaintext_still_works(with_key):
    """A row written before this shipped has to keep working, or deploying it
    would break every configured upstream."""
    assert crypto.decrypt_secret(SECRET) == SECRET
    assert not crypto.is_encrypted(SECRET)


def test_without_a_key_saving_is_refused(monkeypatch):
    """#73: silently storing plaintext contradicts 'encrypted at rest' and the
    boot check can't see the 'key never set' case. The save path refuses."""
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "")
    monkeypatch.delenv("TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS", raising=False)
    with pytest.raises(crypto.PlaintextSecretRefused):
        crypto.encrypt_secret(SECRET)


def test_the_override_flag_restores_plaintext_storage(monkeypatch):
    """The explicit escape hatch downgrades the refusal to a warn-and-store,
    for a deployment that consciously wants the old behaviour."""
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "")
    monkeypatch.setenv("TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS", "1")
    assert crypto.encrypt_secret(SECRET) == SECRET


def test_refusal_never_touches_empty_or_already_encrypted_values(monkeypatch):
    """Editing other fields without re-entering a secret must not trip the
    refusal: empty and already-encrypted inputs pass through with no key."""
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "")
    monkeypatch.delenv("TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS", raising=False)
    assert crypto.encrypt_secret("") == ""
    assert crypto.encrypt_secret(None) is None
    assert crypto.encrypt_secret("enc:v1:whatever") == "enc:v1:whatever"


def test_the_wrong_key_yields_nothing_rather_than_garbage(monkeypatch):
    """Sending a mangled header would produce a confusing upstream failure;
    sending none produces a clean 'no credential' one."""
    monkeypatch.setattr(config, "ENCRYPTION_KEY", KEY)
    stored = crypto.encrypt_secret(SECRET)
    monkeypatch.setattr(config, "ENCRYPTION_KEY", OTHER_KEY)
    assert crypto.decrypt_secret(stored) is None


def test_a_missing_key_for_encrypted_data_raises(monkeypatch):
    monkeypatch.setattr(config, "ENCRYPTION_KEY", KEY)
    stored = crypto.encrypt_secret(SECRET)
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "")
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.decrypt_secret(stored)


def test_a_malformed_key_is_operator_error(monkeypatch):
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "not-a-fernet-key")
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.encrypt_secret(SECRET)


def test_the_upstream_still_receives_the_real_header(with_key):
    """The whole point: encrypted at rest, correct on the wire."""
    upstream = proxy.Upstream(
        id="1", name="finder",
        endpoints=[proxy.Endpoint(id="e1", url="http://127.0.0.1:9/mcp")],
        auth_header_name="Authorization",
        auth_header_value=crypto.encrypt_secret(SECRET),
        timeout=30, enabled=True,
    )
    assert upstream.request_headers()["Authorization"] == SECRET


def test_an_undecryptable_credential_sends_no_header(monkeypatch):
    monkeypatch.setattr(config, "ENCRYPTION_KEY", KEY)
    stored = crypto.encrypt_secret(SECRET)
    monkeypatch.setattr(config, "ENCRYPTION_KEY", OTHER_KEY)
    upstream = proxy.Upstream(
        id="1", name="finder",
        endpoints=[proxy.Endpoint(id="e1", url="http://127.0.0.1:9/mcp")],
        auth_header_name="Authorization", auth_header_value=stored,
        timeout=30, enabled=True,
    )
    assert "Authorization" not in upstream.request_headers()


async def test_boot_refuses_encrypted_data_without_a_key(conn, monkeypatch):
    monkeypatch.setattr(config, "ENCRYPTION_KEY", KEY)
    await conn.execute(
        "INSERT INTO upstreams (name, auth_header_name, auth_header_value) "
        "VALUES ('wk', 'Authorization', $1)",
        crypto.encrypt_secret(SECRET),
    )
    # With the key, boot is fine.
    await crypto.assert_key_present_if_needed(conn)

    monkeypatch.setattr(config, "ENCRYPTION_KEY", "")
    with pytest.raises(crypto.EncryptionUnavailable):
        await crypto.assert_key_present_if_needed(conn)


async def test_boot_is_fine_with_plaintext_and_no_key(conn, monkeypatch):
    """Existing deployments must still start."""
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "")
    await conn.execute(
        "INSERT INTO upstreams (name, auth_header_name, auth_header_value) "
        "VALUES ('wk', 'Authorization', 'Bearer plain')"
    )
    await crypto.assert_key_present_if_needed(conn)
