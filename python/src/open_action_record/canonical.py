"""RFC 8785 canonical JSON, SHA-256 digests and Ed25519 keys, as used by Open Action Records."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_bytes(value: Any) -> bytes:
    return rfc8785.dumps(value)


def digest(value: Any) -> str:
    """"sha256:<hex>" of the canonical form of `value`."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def find_public_key(jwks: dict | None, kid: str) -> Ed25519PublicKey | None:
    for k in (jwks or {}).get("keys", []):
        if k.get("kid") == kid and k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
            try:
                raw = base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4))
                return Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32 else None
            except (ValueError, KeyError):
                return None
    return None


def signature_ok(jwks: dict | None, kid: str, value: Any, signature_hex: str) -> bool:
    key = find_public_key(jwks, kid)
    if key is None:
        return False
    try:
        key.verify(bytes.fromhex(signature_hex), canonical_bytes(value))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
