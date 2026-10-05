"""Verify the extension's Platform-SSO-Authorization envelope the way
keycloak-psso-extension does: SHA256withECDSA (DER) over the ASCII bytes of the
base64url envelope, a nonce this IdP issued, a fresh signed_at, and a device
public key looked up by kid."""
from __future__ import annotations
import base64
import json
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


def kid_for(public_key: EllipticCurvePublicKey) -> str:
    """Standard base64 of SHA-256 over the X9.62 uncompressed point (ssoe computeKid)."""
    point = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(point)
    return base64.b64encode(digest.finalize()).decode()


class DeviceRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, EllipticCurvePublicKey] = {}

    def register(self, public_key_x962_b64: str) -> str:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), base64.b64decode(public_key_x962_b64)
        )
        kid = kid_for(key)
        self._keys[kid] = key
        return kid

    def get(self, kid: str) -> EllipticCurvePublicKey | None:
        return self._keys.get(kid)

    def clear(self) -> None:
        self._keys.clear()


@dataclass
class Verdict:
    ok: bool
    reason: str
    envelope: dict | None = None


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_envelope(
    header_value: str,
    *,
    devices: DeviceRegistry,
    issued_nonces: set[str],
    now: int | None = None,
    max_age_s: int = 300,
) -> Verdict:
    value = header_value.strip()
    if value[:7].lower() == "bearer ":
        value = value[7:].strip()
    parts = value.split(".")
    if len(parts) != 2:
        return Verdict(False, "malformed")
    env_b64, sig_b64 = parts
    try:
        env = json.loads(_b64url_decode(env_b64))
        signature = _b64url_decode(sig_b64)
        nonce = str(env["nonce"]).lower()
        kid = str(env["kid"])
        signed_at = int(env["signed_at"])
    except (ValueError, KeyError, TypeError):
        return Verdict(False, "malformed")

    if nonce not in issued_nonces:
        return Verdict(False, "nonce_unknown", env)
    issued_nonces.discard(nonce)

    now = int(time.time()) if now is None else now
    if abs(now - signed_at) > max_age_s:
        return Verdict(False, "stale", env)

    key = devices.get(kid)
    if key is None:
        return Verdict(False, "unknown_device", env)
    try:
        key.verify(signature, env_b64.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return Verdict(False, "bad_signature", env)
    return Verdict(True, "ok", env)
