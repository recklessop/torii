"""A fake WebAuthn authenticator for exercising torii's verifier.

Why hand-rolled rather than soft-webauthn: our verifier demands user
verification, and soft-webauthn can only produce UP-only assertions — it
cannot test our happy path at all, and only accidentally tests the negative.
This device puts the flags byte, the sign count, the RP ID and the origin
under the test's control, which is exactly the set of things the negative
tests need to vary.

Attestation format is "none" (what torii requests), so registration needs no
attestation signature: just CBOR over authenticator data carrying the
credential id and a COSE P-256 public key. An assertion is an ECDSA-SHA256
signature over authenticator_data || SHA256(client_data_json).
"""

import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn.helpers import bytes_to_base64url

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40


def _flags(*, up=True, uv=True, at=False, be=False, bs=False) -> int:
    value = 0
    if up:
        value |= FLAG_UP
    if uv:
        value |= FLAG_UV
    if at:
        value |= FLAG_AT
    if be:
        value |= FLAG_BE
    if bs:
        value |= FLAG_BS
    return value


class FakeAuthenticator:
    def __init__(self, rp_id: str = "torii.test"):
        self.rp_id = rp_id
        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.user_handle: bytes | None = None

    # --- key material ------------------------------------------------------

    def _cose_public_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2,        # kty: EC2
            3: -7,       # alg: ES256
            -1: 1,       # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })

    def _auth_data(self, flags: int, sign_count: int, *, attested: bool,
                   rp_id: str | None = None) -> bytes:
        data = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        data += bytes([flags])
        data += struct.pack(">I", sign_count)
        if attested:
            aaguid = b"\x00" * 16
            data += aaguid
            data += struct.pack(">H", len(self.credential_id))
            data += self.credential_id
            data += self._cose_public_key()
        return data

    @staticmethod
    def _client_data(kind: str, challenge_b64u: str, origin: str) -> bytes:
        return json.dumps({
            "type": kind,
            "challenge": challenge_b64u,
            "origin": origin,
            "crossOrigin": False,
        }).encode()

    # --- ceremonies --------------------------------------------------------

    def create(self, options_json: str, origin: str, *, uv=True,
               rp_id: str | None = None, challenge: str | None = None) -> dict:
        """A registration credential for navigator.credentials.create()."""
        options = json.loads(options_json)
        self.user_handle = options["user"]["id"].encode() \
            if isinstance(options["user"]["id"], str) else None
        client_data = self._client_data(
            "webauthn.create", challenge or options["challenge"], origin
        )
        auth_data = self._auth_data(
            _flags(uv=uv, at=True), 0, attested=True, rp_id=rp_id
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
                "transports": ["internal"],
            },
        }

    def get(self, options_json: str, origin: str, *, uv=True, sign_count=0,
            rp_id: str | None = None, challenge: str | None = None,
            signer: "FakeAuthenticator | None" = None) -> dict:
        """An assertion for navigator.credentials.get().

        `signer` lets a test present THIS device's credential id with a
        DIFFERENT device's signature — the cross-user case.
        """
        options = json.loads(options_json)
        client_data = self._client_data(
            "webauthn.get", challenge or options["challenge"], origin
        )
        auth_data = self._auth_data(_flags(uv=uv), sign_count, attested=False, rp_id=rp_id)
        key = (signer or self).private_key
        signature = key.sign(
            auth_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(self.user_handle)
                if self.user_handle else None,
            },
        }
