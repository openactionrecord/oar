"""Checks an RFC 3161 timestamp token over a checkpoint, the same way the TypeScript verifiers do.

The token must timestamp the SHA-256 of the signed checkpoint, its signature must verify, and the signing
certificate must be a timestamping certificate that was valid at the time and chains to an accepted root.
Certificate revocation is not checked.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from .canonical import canonical_bytes

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


def bundled_roots() -> list[dict[str, str]]:
    """The DigiCert roots accepted by default (the same list as the TypeScript verifiers)."""
    return json.loads(resources.files(__package__).joinpath("tsa_roots.json").read_text())


def anchor_digest(cp: dict[str, Any]) -> str:
    """SHA-256 (hex) of the signed checkpoint: the value the authority timestamps."""
    body = {k: cp[k] for k in ("count", "head_digest", "at", "sealer_kid", "sig")}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


@dataclass
class TimestampResult:
    ok: bool
    reason: str = ""
    gen_time: str = ""
    tsa: str = ""


class _TokenError(Exception):
    pass


def verify_timestamp_token(token: str, imprint_hex: str, roots: list[dict[str, str]] | None = None) -> TimestampResult:
    try:
        return _check(token, imprint_hex, roots if roots is not None else bundled_roots())
    except _TokenError as e:
        return TimestampResult(False, str(e))
    except Exception:  # noqa: BLE001 - any parsing failure means the token cannot be read
        return TimestampResult(False, "The timestamp token could not be read.")


def _tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """One DER/BER element at `pos`: (tag, content, next position). Definite lengths only."""
    tag = buf[pos]
    length = buf[pos + 1]
    p = pos + 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4:
            raise _TokenError("The timestamp token is not valid DER.")
        length = int.from_bytes(buf[p : p + n], "big")
        p += n
    if p + length > len(buf):
        raise _TokenError("The timestamp token is not valid DER.")
    return tag, buf[p : p + length], p + length


def _octets(tag: int, content: bytes) -> bytes:
    """An OCTET STRING's bytes; a constructed (chunked) one, as some encoders write, is joined."""
    if tag == 0x04:
        return content
    if tag == 0x24:
        out, p = b"", 0
        while p < len(content):
            t, c, p = _tlv(content, p)
            out += _octets(t, c)
        return out
    raise _TokenError("The timestamp token has an unexpected structure.")


def _econtent(encap_contents: bytes) -> bytes:
    """The TSTInfo bytes inside EncapsulatedContentInfo: SEQUENCE { OID, [0] EXPLICIT OCTET STRING }."""
    _t, _oid, p = _tlv(encap_contents, 0)
    tag, explicit, _ = _tlv(encap_contents, p)
    if tag != 0xA0:
        raise _TokenError("The timestamp token has no content.")
    inner_tag, inner, _ = _tlv(explicit, 0)
    return _octets(inner_tag, inner)


def _common_name(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


def _valid_at(cert: x509.Certificate, when) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _signed_by(cert: x509.Certificate, hash_name: str, signature: bytes, data: bytes) -> bool:
    key = cert.public_key()
    algorithm = _HASHES[hash_name]()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(algorithm))
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _check(token: str, imprint_hex: str, roots: list[dict[str, str]]) -> TimestampResult:
    info = cms.ContentInfo.load(base64.b64decode(token))
    if info["content_type"].dotted != "1.2.840.113549.1.7.2":
        raise _TokenError("This is not a timestamp token.")
    signed = info["content"]
    encap = signed["encap_content_info"]
    if encap["content_type"].dotted != "1.2.840.113549.1.9.16.1.4":
        raise _TokenError("This is not a timestamp token.")
    tst_der = _econtent(encap.contents)
    tst = tsp.TSTInfo.load(tst_der)
    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].dotted != "2.16.840.1.101.3.4.2.1":
        raise _TokenError("The timestamp does not use SHA-256.")
    if imprint["hashed_message"].native.hex() != imprint_hex:
        raise _TokenError("The timestamp is for a different checkpoint.")
    gen_time = tst["gen_time"].native

    certs = [x509.load_der_x509_certificate(c.chosen.dump()) for c in (signed["certificates"] or [])]
    signer_info = signed["signer_infos"][0]
    hash_name = signer_info["digest_algorithm"]["algorithm"].native
    if hash_name not in _HASHES:
        raise _TokenError("The timestamp uses an unsupported hash algorithm.")
    attrs = signer_info["signed_attrs"]
    if not attrs:
        raise _TokenError("The timestamp has no signed attributes.")
    sig_alg = signer_info["signature_algorithm"]["algorithm"].dotted
    if not (sig_alg.startswith("1.2.840.113549.1.1.") or sig_alg.startswith("1.2.840.10045.")) or sig_alg == "1.2.840.113549.1.1.10":
        raise _TokenError("The timestamp uses an unsupported signature algorithm.")

    digest = next((a["values"][0].native for a in attrs if a["type"].dotted == "1.2.840.113549.1.9.4"), None)
    if digest is None:
        raise _TokenError("The timestamp has no message digest.")
    h = hashlib.new(hash_name)
    h.update(tst_der)
    if digest != h.digest():
        raise _TokenError("The timestamp token was changed after signing.")

    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        serial = sid.chosen["serial_number"].native
        candidates = [c for c in certs if c.serial_number == serial]
    else:
        candidates = certs
    if not candidates:
        raise _TokenError("The timestamp token does not include the authority's certificate.")

    attrs_der = attrs.dump()
    to_verify = b"\x31" + attrs_der[1:]
    signature = signer_info["signature"].native
    signer = next((c for c in candidates if _signed_by(c, hash_name, signature, to_verify)), None)
    if signer is None:
        raise _TokenError("The timestamp signature does not verify.")

    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = []
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        raise _TokenError("The signing certificate is not a timestamping certificate.")
    if not _valid_at(signer, gen_time):
        raise _TokenError("The authority's certificate was not valid at the time of the timestamp.")

    _chain_to_root(signer, certs, roots, gen_time)
    return TimestampResult(True, gen_time=gen_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{gen_time.microsecond // 1000:03d}Z", tsa=_common_name(signer))


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _chain_to_root(signer: x509.Certificate, certs: list[x509.Certificate], roots: list[dict[str, str]], when) -> None:
    trusted = [(r, x509.load_der_x509_certificate(base64.b64decode(r["der"]))) for r in roots]
    current = signer
    for _ in range(6):
        fingerprint = current.fingerprint(hashes.SHA256()).hex()
        if any(r["sha256"] == fingerprint for r, _c in trusted):
            return
        anchor = next((c for _r, c in trusted if _issued_by(current, c)), None)
        if anchor is not None:
            if not _valid_at(anchor, when):
                raise _TokenError("The root certificate was not valid at the time of the timestamp.")
            return
        issuer = next((c for c in certs if c is not current and _issued_by(current, c)), None)
        if issuer is None:
            raise _TokenError("The authority's certificate does not chain to a recognised root.")
        if not _valid_at(issuer, when):
            raise _TokenError("A certificate in the chain was not valid at the time of the timestamp.")
        current = issuer
    raise _TokenError("The certificate chain is too long.")
