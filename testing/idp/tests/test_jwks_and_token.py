import time
import jwt
from jwt import PyJWKClient  # noqa: F401  (import proves dependency present)
from mock_idp.signing import Signer


def _verify(token: str, jwks: dict, *, audience: str) -> dict:
    key = jwt.PyJWK.from_dict(jwks["keys"][0]).key
    return jwt.decode(token, key=key, algorithms=["RS256"], audience=audience)


def test_id_token_verifies_against_published_jwks():
    s = Signer(issuer="https://idp.test/realms/test", audience="psso-aud")
    tok = s.mint_id_token(sub="alice", nonce="abc", groups=["staff"])
    claims = _verify(tok, s.jwks(), audience="psso-aud")
    assert claims["iss"] == "https://idp.test/realms/test"
    assert claims["sub"] == "alice"
    assert claims["nonce"] == "abc"
    assert claims["groups"] == ["staff"]
    assert claims["exp"] > time.time()


def test_expired_token_flag_produces_past_exp():
    s = Signer(issuer="i", audience="a")
    tok = s.mint_id_token(sub="alice", nonce="abc", groups=[], expired=True)
    try:
        _verify(tok, s.jwks(), audience="a")
        assert False, "expected expired token to fail verification"
    except jwt.ExpiredSignatureError:
        pass


def test_jwks_has_kid_matching_token_header():
    s = Signer(issuer="i", audience="a")
    tok = s.mint_id_token(sub="x", nonce="n", groups=[])
    header = jwt.get_unverified_header(tok)
    assert header["kid"] == s.jwks()["keys"][0]["kid"]


import pytest

pytestmark = pytest.mark.anyio


async def test_certs_endpoint_serves_jwks(client):
    r = await client.get("/protocol/openid-connect/certs")
    assert r.status_code == 200
    assert r.json()["keys"][0]["kty"] == "RSA"


async def test_token_returns_signed_id_token(client):
    r = await client.post("/psso/token", data={"grant_type": "client_credentials"})
    body = r.json()
    assert set(body) >= {"access_token", "refresh_token", "id_token", "expires_in"}
    header = __import__("jwt").get_unverified_header(body["id_token"])
    assert header["alg"] == "RS256"


async def test_token_500_fault(client):
    await client.post("/control/fault", json={"type": "token_500", "times": 1})
    r = await client.post("/psso/token", data={})
    assert r.status_code == 500


async def test_token_bad_json_fault(client):
    await client.post("/control/fault", json={"type": "token_bad_json", "times": 1})
    r = await client.post("/psso/token", data={})
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text == "not json{{{"


async def test_expired_id_token_fault(client):
    import jwt
    await client.post("/control/fault", json={"type": "expired_id_token", "times": 1})
    r = await client.post("/psso/token", data={})
    with pytest.raises(jwt.ExpiredSignatureError):
        key = jwt.PyJWK.from_dict((await client.get("/protocol/openid-connect/certs")).json()["keys"][0]).key
        jwt.decode(r.json()["id_token"], key=key, algorithms=["RS256"], audience="psso-aud")


async def test_malformed_id_token_fault(client):
    import jwt
    await client.post("/control/fault", json={"type": "malformed_id_token", "times": 1})
    r = await client.post("/psso/token", data={})
    key = jwt.PyJWK.from_dict((await client.get("/protocol/openid-connect/certs")).json()["keys"][0]).key
    # Signature is corrupted, so verification must reject the token.
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(r.json()["id_token"], key=key, algorithms=["RS256"], audience="psso-aud")


async def test_enroll_endpoints_ok(client):
    for path in ("/psso/enroll", "/psso/userenroll"):
        r = await client.post(path, json={})
        assert r.json() == {"status": "ok"}
