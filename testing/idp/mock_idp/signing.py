from __future__ import annotations
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


class Signer:
    """Holds one RSA keypair; mints RS256 id_tokens and publishes the matching JWKS."""

    def __init__(self, issuer: str, audience: str) -> None:
        self._issuer = issuer
        self._audience = audience
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._kid = "mock-idp-key-1"

    def mint_id_token(
        self,
        *,
        sub: str,
        nonce: str,
        groups: list[str],
        expired: bool = False,
        malformed: bool = False,
    ) -> str:
        now = int(time.time())
        exp = now - 3600 if expired else now + 3600
        claims = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": sub,
            "nonce": nonce,
            "groups": groups,
            "iat": now,
            "exp": exp,
        }
        token = jwt.encode(
            claims, self._key, algorithm="RS256", headers={"kid": self._kid}
        )
        if malformed:
            # Corrupt the signature segment so verification fails.
            head, payload, _sig = token.split(".")
            token = f"{head}.{payload}.AAAAdeadbeef"
        return token

    def jwks(self) -> dict:
        pub = self._key.public_key()
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(pub, as_dict=True)
        jwk.update({"kid": self._kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}
