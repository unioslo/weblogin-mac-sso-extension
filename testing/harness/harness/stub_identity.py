"""The identity a TESTSTUBS build of the extension assumes in the guest:
a P-256 signing key, a username, and the psso-test-stub.json the stub reads."""
from __future__ import annotations
import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

REAUTHENTICATION_MODES = ("succeed", "fail", "hang")


@dataclass
class StubIdentity:
    username: str
    private_key: EllipticCurvePrivateKey

    def public_x962_b64(self) -> str:
        point = self.private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return base64.b64encode(point).decode()

    def x963_private_b64(self) -> str:
        """04 || X || Y || K, the layout SecKeyCreateWithData wants for an EC private key."""
        point = base64.b64decode(self.public_x962_b64())
        k = self.private_key.private_numbers().private_value.to_bytes(32, "big")
        return base64.b64encode(point + k).decode()

    def kid(self) -> str:
        """Matches ssoe computeKid: standard base64 of SHA-256 over the uncompressed point."""
        point = base64.b64decode(self.public_x962_b64())
        return base64.b64encode(hashlib.sha256(point).digest()).decode()

    def stub_json(self, *, id_token: str, reauthentication: str = "succeed") -> str:
        if reauthentication not in REAUTHENTICATION_MODES:
            raise ValueError(f"reauthentication must be one of {REAUTHENTICATION_MODES}, got {reauthentication!r}")
        return json.dumps(
            {
                "username": self.username,
                "authentication_method": "password",
                "sso_tokens": {"id_token": id_token},
                "signing_key_x963_base64": self.x963_private_b64(),
                "reauthentication": reauthentication,
            },
            indent=2,
        )


def new_identity(username: str = "testuser") -> StubIdentity:
    return StubIdentity(username=username, private_key=ec.generate_private_key(ec.SECP256R1()))
