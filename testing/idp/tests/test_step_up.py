"""The header login and step-up flow as the TESTSTUBS extension drives it."""
import base64
import json
import time
import re
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

pytestmark = pytest.mark.anyio

AUTH = "/protocol/openid-connect/auth"
REDIRECT = "https://sp.test/cb"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class Device:
    """A stand-in for the extension's stub identity."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.pub_b64 = base64.b64encode(pub).decode()
        self.kid = None
        self.id_token = None

    async def register(self, client, username="testuser"):
        r = await client.post("/control/device", json={"public_key_x962_base64": self.pub_b64})
        assert r.status_code == 200
        self.kid = r.json()["kid"]
        r = await client.post("/control/mint", json={"username": username})
        assert r.status_code == 200
        self.id_token = r.json()["id_token"]

    async def envelope(self, client, *, username="testuser", nonce=None, reauth_challenge="dev-challenge"):
        if nonce is None:
            nonce = (await client.post("/psso/nonce", content=b"grant_type=srv_challenge")).json()["nonce"].upper()
        env = {
            "token": self.id_token,
            "token_type": "id_token",
            "kid": self.kid,
            "signed_at": int(time.time()),
            "username": username,
            "nonce": nonce,
            "client_id": "cid",
            "secure_enclave": False,
        }
        if reauth_challenge is not None:
            env["reauth_challenge"] = reauth_challenge
        env_b64 = b64url(json.dumps(env).encode())
        sig = self.priv.sign(env_b64.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return f"{env_b64}.{b64url(sig)}"


async def auth(client, device, reauth_challenge="dev-challenge", **params):
    q = {"client_id": "psso-client", "response_type": "code", "redirect_uri": REDIRECT, "state": "s1", **params}
    header = "Bearer " + await device.envelope(client, reauth_challenge=reauth_challenge)
    return await client.get(AUTH, params=q, headers={"Platform-SSO-Authorization": header})


def step_up_token(page) -> str:
    return re.search(r'id="stepUpToken" name="stepUpToken" value="([^"]+)"', page.text).group(1)


async def verify_step_up_token(client, token) -> dict:
    """Verify the way the extension does: realm JWKS, pinned alg, issuer and audience."""
    jwks = (await client.get("/protocol/openid-connect/certs")).json()
    key = jwt.PyJWK(jwks["keys"][0]).key
    return jwt.decode(token, key, algorithms=["RS256"], audience="psso-aud", issuer="https://idp.test/realms/test")


async def test_auth_without_header_is_plain_page(client):
    r = await client.get(AUTH, params={"redirect_uri": REDIRECT})
    assert r.status_code == 200 and "mock auth" in r.text


async def test_header_login_redirects_with_code(client):
    d = Device()
    await d.register(client)
    r = await auth(client, d)
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == REDIRECT
    qs = parse_qs(loc.query)
    assert qs["code"] and qs["state"] == ["s1"]
    results = (await client.get("/control/auth_results")).json()
    assert results[-1] == {"stage": "header", "ok": True, "reason": "ok", "username": "testuser"}


async def test_header_login_rejects_username_mismatch(client):
    d = Device()
    await d.register(client)
    r = await client.get(AUTH, params={"redirect_uri": REDIRECT},
                         headers={"Platform-SSO-Authorization": "Bearer " + await d.envelope(client, username="mallory")})
    assert r.status_code == 401
    assert r.json()["error"] == "username_mismatch"


async def test_header_login_rejects_unknown_device(client):
    d = Device()
    await d.register(client)
    d.kid = "nope"
    r = await auth(client, d)
    assert r.status_code == 401 and r.json()["error"] == "unknown_device"


async def test_prompt_login_serves_step_up_page(client):
    d = Device()
    await d.register(client)
    r = await auth(client, d, prompt="login")
    assert r.status_code == 200
    assert "messageHandlers.pssoStepUp.postMessage" in r.text
    assert "function pssoSigned" in r.text
    assert "<iframe" not in r.text
    assert "location.href" not in r.text
    assert re.search(r'action="/login-actions/psso\?session_code=[A-Za-z0-9_-]+"', r.text)


async def test_step_up_page_carries_signed_challenge(client):
    d = Device()
    await d.register(client)
    r = await auth(client, d, reauth_challenge="c-123", prompt="login")
    assert 'postMessage({ type: "getSignedToken", challenge: stepUpToken })' in r.text
    token = step_up_token(r)
    assert jwt.get_unverified_header(token)["kid"] == "mock-idp-key-1"
    claims = await verify_step_up_token(client, token)
    assert claims["reauth_challenge"] == "c-123"
    assert claims["exp"] - claims["iat"] == 60


async def test_step_up_token_without_envelope_challenge_says_none(client):
    d = Device()
    await d.register(client)
    r = await auth(client, d, reauth_challenge=None, prompt="login")
    assert (await verify_step_up_token(client, step_up_token(r)))["reauth_challenge"] == "none"


async def test_step_up_forged_token_fails_jwks_verification(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_forged_token"})
    r = await auth(client, d)
    token = step_up_token(r)
    assert jwt.get_unverified_header(token)["kid"] == "mock-idp-key-1"
    with pytest.raises(jwt.InvalidSignatureError):
        await verify_step_up_token(client, token)


async def test_step_up_wrong_challenge_token_is_validly_signed(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_wrong_challenge"})
    r = await auth(client, d, reauth_challenge="c-123")
    claims = await verify_step_up_token(client, step_up_token(r))
    assert claims["reauth_challenge"] not in ("c-123", "none")


async def test_step_up_expired_token(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_expired_token"})
    r = await auth(client, d)
    with pytest.raises(jwt.ExpiredSignatureError):
        await verify_step_up_token(client, step_up_token(r))


async def test_step_up_fault_serves_step_up_page_without_prompt(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up"})
    r = await auth(client, d)
    assert r.status_code == 200 and "pssoStepUp" in r.text


async def test_step_up_iframe_variant_embeds_foreign_origin(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_iframe"})
    r = await auth(client, d)
    assert '<iframe src="https://idp.test:8443/evil/stepup.html"' in r.text


async def test_step_up_navigate_variant_leaves_the_page(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_navigate"})
    r = await auth(client, d)
    assert 'location.href = "https://idp.test:8443/evil/landing.html"' in r.text


async def test_step_up_navigate_slows_the_next_nonce(client, monkeypatch):
    """The page must be gone before the extension can answer, so its nonce waits."""
    from mock_idp import idp_routes
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(idp_routes.asyncio, "sleep", fake_sleep)
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_navigate"})
    await auth(client, d)  # the header-flow nonce above is not delayed
    assert slept == []
    assert (await client.post("/psso/nonce")).status_code == 200
    assert slept == [idp_routes.NONCE_SLOW_SECONDS]
    await client.post("/psso/nonce")
    assert slept == [idp_routes.NONCE_SLOW_SECONDS]


async def test_step_up_post_with_signed_token_redirects(client):
    d = Device()
    await d.register(client)
    page = await auth(client, d, prompt="login")
    action = re.search(r'action="([^"]+)"', page.text).group(1)
    r = await client.post(action, data={"signedtoken": await d.envelope(client), "reauthenticate": ""})
    assert r.status_code == 302
    assert r.headers["location"].startswith(REDIRECT + "?")
    results = (await client.get("/control/auth_results")).json()
    assert results[-1]["stage"] == "step_up" and results[-1]["ok"] is True


async def test_step_up_post_none_is_declined(client):
    d = Device()
    await d.register(client)
    page = await auth(client, d, prompt="login")
    action = re.search(r'action="([^"]+)"', page.text).group(1)
    r = await client.post(action, data={"signedtoken": "none"})
    assert r.status_code == 200 and "declined" in r.text
    results = (await client.get("/control/auth_results")).json()
    assert results[-1] == {"stage": "step_up", "ok": False, "reason": "declined", "username": None}


async def test_step_up_post_reusing_nonce_is_rejected(client):
    d = Device()
    await d.register(client)
    nonce = (await client.post("/psso/nonce")).json()["nonce"].upper()
    first = await d.envelope(client, nonce=nonce)
    page = await client.get(AUTH, params={"redirect_uri": REDIRECT, "prompt": "login"},
                            headers={"Platform-SSO-Authorization": "Bearer " + first})
    action = re.search(r'action="([^"]+)"', page.text).group(1)
    r = await client.post(action, data={"signedtoken": await d.envelope(client, nonce=nonce)})
    assert r.status_code == 401 and r.json()["error"] == "nonce_unknown"


async def test_step_up_nonce_500_arms_after_page(client):
    d = Device()
    await d.register(client)
    await client.post("/control/fault", json={"type": "step_up_nonce_500"})
    r = await auth(client, d)  # the header-flow nonce above must have succeeded
    assert r.status_code == 200 and "pssoStepUp" in r.text
    assert (await client.post("/psso/nonce")).status_code == 500
    assert (await client.post("/psso/nonce")).status_code == 200


async def test_nonce_500_fault(client):
    await client.post("/control/fault", json={"type": "nonce_500"})
    assert (await client.post("/psso/nonce")).status_code == 500


async def test_evil_pages_and_leak_sink(client):
    r = await client.get("/evil/stepup.html")
    assert r.status_code == 200 and "pssoStepUp" in r.text and "/evil/leak" in r.text
    r = await client.get("/evil/landing.html")
    assert r.status_code == 200 and "function pssoSigned" in r.text
    r = await client.post("/evil/leak", content=b"token-bytes")
    assert r.status_code == 204
    log = (await client.get("/control/requests")).json()
    assert any(e["path"] == "/evil/leak" and e["body"] == "token-bytes" for e in log)


async def test_cb_is_logged(client):
    r = await client.get("/cb", params={"code": "x"})
    assert r.status_code == 200
    log = (await client.get("/control/requests")).json()
    assert any(e["path"] == "/cb" and "code=x" in e["query"] for e in log)


async def test_reset_clears_devices_and_results(client):
    d = Device()
    await d.register(client)
    await auth(client, d)
    await client.post("/control/reset")
    assert (await client.get("/control/auth_results")).json() == []
    r = await auth(client, d)
    assert r.status_code == 401 and r.json()["error"] == "unknown_device"
