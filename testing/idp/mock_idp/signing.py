from __future__ import annotations
import time
import uuid
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
            "preferred_username": sub,
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

    def mint_step_up_token(
        self, challenge: str, *, expired: bool = False, forged: bool = False
    ) -> str:
        """The signed step-up token keycloak-psso-extension puts on its
        reauthentication page: the device's reauth_challenge, signed with the
        realm key. forged signs with a key the JWKS does not publish, same kid."""
        now = int(time.time())
        claims = {
            "jti": str(uuid.uuid4()),
            "iss": self._issuer,
            "aud": self._audience,
            "iat": now,
            "exp": now - 3600 if expired else now + 60,
            "reauth_challenge": challenge,
        }
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if forged else self._key
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": self._kid, "typ": "JWT"})

    def jwks(self) -> dict:
        pub = self._key.public_key()
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(pub, as_dict=True)
        jwk.update({"kid": self._kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def verify_id_token(self, token: str) -> dict:
        """Decode and verify a token this signer minted. Raises jwt.PyJWTError."""
        return jwt.decode(
            token,
            self._key.public_key(),
            algorithms=["RS256"],
            audience=self._audience,
            issuer=self._issuer,
        )
