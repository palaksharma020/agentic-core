# SPDX-License-Identifier: Apache-2.0
"""Ed25519 signing and verification for the audit trail and tool manifests (needs `cryptography`:
pip install "agentic-core[crypto]").

Keys are 32-byte seeds, stored base64url-encoded by the application (a git-ignored .env locally; a KMS or HSM
in production). key_id is the first 16 hex characters of SHA-256 of the public key, so verifiers can pick the
right key after rotation. Signatures are base64url strings.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id_for(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def new_seed() -> str:
    """A fresh private key seed, base64url (store it as a secret)."""
    return _b64(Ed25519PrivateKey.generate().private_bytes_raw())


def public_key_b64(seed_b64: str) -> str:
    return _b64(
        Ed25519PrivateKey.from_private_bytes(_unb64(seed_b64))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


class Ed25519Signer:
    def __init__(self, seed_b64: str) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(_unb64(seed_b64))
        self.key_id = key_id_for(self._key.public_key())

    def sign(self, data: bytes) -> str:
        return _b64(self._key.sign(data))


class Ed25519Verifier:
    """Verify with public keys only. `public_keys` maps key_id -> base64url raw public key."""

    def __init__(self, public_keys: Mapping[str, str]) -> None:
        self.keys = {
            kid: Ed25519PublicKey.from_public_bytes(_unb64(pk)) for kid, pk in public_keys.items()
        }
        for kid, key in self.keys.items():
            if key_id_for(key) != kid:
                raise ValueError(f"key id {kid!r} does not match its public key")

    @classmethod
    def from_public(cls, *public_b64: str) -> Ed25519Verifier:
        return cls(
            {key_id_for(Ed25519PublicKey.from_public_bytes(_unb64(pk))): pk for pk in public_b64}
        )

    def __call__(self, key_id: str, data: bytes, signature: str) -> bool:
        key = self.keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(_unb64(signature), data)
        except (InvalidSignature, ValueError):
            return False
        return True
