"""Ed25519 signing keys for Open Action Records. Private keys are 32-byte seeds in lower-case hex: keep them
secret and never log them."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import canonical_bytes


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: str  # 32-byte hex seed. Secret.

    def __repr__(self) -> str:  # never print the private key
        return f"SigningKey(kid={self.kid!r}, private_key=<hidden>)"


def generate_signing_key(kid: str) -> SigningKey:
    """A new Ed25519 signing key. Store it as a secret, and publish `public_keys(key)`."""
    if not kid:
        raise ValueError('kid: give the key a name, for example "my-agent-2026"')
    return SigningKey(kid, os.urandom(32).hex())


def _private(key: SigningKey) -> Ed25519PrivateKey:
    seed = bytes.fromhex(key.private_key)
    if len(seed) != 32:
        raise ValueError("private_key: expected 32 bytes of hex")
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign_canonical(value: Any, key: SigningKey) -> str:
    """Hex Ed25519 signature over the RFC 8785 canonical bytes of `value`."""
    return _private(key).sign(canonical_bytes(value)).hex()


def public_jwk(key: SigningKey) -> dict[str, str]:
    raw = _private(key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "kid": key.kid,
        "alg": "EdDSA",
        "use": "sig",
    }


def public_keys(*keys: SigningKey) -> dict[str, list[dict[str, str]]]:
    """The key set to publish (for example at /.well-known/aar-keys.json) so others can check your records."""
    return {"keys": [public_jwk(k) for k in keys]}


def load_or_create_key(path: str, kid: str) -> SigningKey:
    """Loads a key from a JSON file, or creates one there (file mode 600) on first use."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return SigningKey(data["kid"], data["privateKey"])
    key = generate_signing_key(kid)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"kid": key.kid, "privateKey": key.private_key}, f)
    return key
