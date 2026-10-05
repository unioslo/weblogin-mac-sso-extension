from __future__ import annotations
import asyncio
import secrets
import uuid
from urllib.parse import urlencode

import jwt
from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from . import pages
from .envelope import Verdict, verify_envelope
from .faults import FaultKind

router = APIRouter()

BAD_NONCE = "00000000-0000-0000-0000-000000000000"
EVIL_PORT = 8443
# Long enough that the navigate variant's page has left before the extension can answer it.
NONCE_SLOW_SECONDS = 3.0


@router.api_route("/psso/nonce", methods=["GET", "POST"])
async def nonce(request: Request):
    st = request.app.state
    if st.faults.consume(FaultKind.NONCE_500):
        return JSONResponse({"error": "server_error"}, status_code=500)
    if st.faults.consume(FaultKind.NONCE_SLOW):
        await asyncio.sleep(NONCE_SLOW_SECONDS)
    if st.faults.consume(FaultKind.BAD_NONCE):
        st.last_nonce = BAD_NONCE  # not recorded as issued, so an envelope using it fails
    else:
        st.last_nonce = str(uuid.uuid4())
        st.issued_nonces.add(st.last_nonce.lower())
    return {"nonce": st.last_nonce}


def _mint(request: Request, *, expired: bool = False, malformed: bool = False) -> dict:
    signer = request.app.state.signer
    nonce = getattr(request.app.state, "last_nonce", "no-nonce")
    id_token = signer.mint_id_token(
        sub="testuser", nonce=nonce, groups=["staff"], expired=expired, malformed=malformed
    )
    return {
        "access_token": "mock-access-token",
        "refresh_token": "mock-refresh-token",
        "id_token": id_token,
        "expires_in": 3600,
    }


@router.get("/protocol/openid-connect/certs")
async def certs(request: Request):
    return request.app.state.signer.jwks()


async def _token(request: Request):
    # Fault kinds are checked independently, so arming several at once makes them
    # all fire on the same request (e.g. timeout then 500), not on separate calls.
    faults = request.app.state.faults
    if faults.consume(FaultKind.TIMEOUT):
        await asyncio.sleep(60)
    if faults.consume(FaultKind.TOKEN_500):
        return JSONResponse({"error": "server_error"}, status_code=500)
    if faults.consume(FaultKind.TOKEN_BAD_JSON):
        return PlainTextResponse("not json{{{")
    expired = faults.consume(FaultKind.EXPIRED_ID_TOKEN)
    malformed = faults.consume(FaultKind.MALFORMED_ID_TOKEN)
    return _mint(request, expired=expired, malformed=malformed)


@router.post("/psso/token")
async def psso_token(request: Request):
    return await _token(request)


@router.post("/protocol/openid-connect/token")
async def oidc_token(request: Request):
    return await _token(request)


@router.post("/psso/enroll")
async def enroll(request: Request):
    return {"status": "ok"}


@router.post("/psso/userenroll")
async def userenroll(request: Request):
    return {"status": "ok"}


def _check(request: Request, header_value: str, stage: str) -> Verdict:
    """Envelope + id_token + username, recorded in auth_results."""
    st = request.app.state
    verdict = verify_envelope(header_value, devices=st.devices, issued_nonces=st.issued_nonces)
    username = None
    if verdict.ok:
        env = verdict.envelope
        username = env.get("username")
        try:
            claims = st.signer.verify_id_token(str(env.get("token")))
        except jwt.PyJWTError:
            verdict = Verdict(False, "invalid_token", env)
        else:
            if claims.get("preferred_username") != username:
                verdict = Verdict(False, "username_mismatch", env)
    st.auth_results.append({"stage": stage, "ok": verdict.ok, "reason": verdict.reason, "username": username})
    return verdict


def _redirect_with_code(redirect_uri: str, state: str) -> RedirectResponse:
    params = {"code": "mock-code-" + secrets.token_urlsafe(6)}
    if state:
        params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.get("/protocol/openid-connect/auth")
async def auth(request: Request):
    st = request.app.state
    header = request.headers.get("Platform-SSO-Authorization")
    if header is None:
        return HTMLResponse(pages.PLAIN_AUTH)

    verdict = _check(request, header, "header")
    if not verdict.ok:
        return JSONResponse({"error": verdict.reason}, status_code=401)

    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")

    want_step_up = request.query_params.get("prompt") == "login" or st.faults.consume(FaultKind.STEP_UP)
    variant = "plain"
    if st.faults.consume(FaultKind.STEP_UP_IFRAME):
        want_step_up, variant = True, "iframe"
    if st.faults.consume(FaultKind.STEP_UP_NAVIGATE):
        want_step_up, variant = True, "navigate"
        st.faults.arm(FaultKind.NONCE_SLOW, times=1)
    if st.faults.consume(FaultKind.STEP_UP_NONCE_500):
        want_step_up = True
        st.faults.arm(FaultKind.NONCE_500, times=1)
    # Keycloak echoes the envelope's reauth_challenge ("none" when absent) in a realm-signed token.
    challenge = str(verdict.envelope.get("reauth_challenge") or "none")
    forged = expired = False
    if st.faults.consume(FaultKind.STEP_UP_FORGED_TOKEN):
        want_step_up, forged = True, True
    if st.faults.consume(FaultKind.STEP_UP_WRONG_CHALLENGE):
        want_step_up, challenge = True, secrets.token_urlsafe(32)
    if st.faults.consume(FaultKind.STEP_UP_EXPIRED_TOKEN):
        want_step_up, expired = True, True
    if not want_step_up:
        return _redirect_with_code(redirect_uri, state)

    session_code = secrets.token_urlsafe(8)
    st.pending_auth[session_code] = {"redirect_uri": redirect_uri, "state": state}
    evil_origin = f"https://{request.url.hostname}:{EVIL_PORT}"
    step_up_token = st.signer.mint_step_up_token(challenge, expired=expired, forged=forged)
    return HTMLResponse(pages.step_up_page(
        action=f"/login-actions/psso?session_code={session_code}", step_up_token=step_up_token,
        variant=variant, evil_origin=evil_origin,
    ))


@router.post("/login-actions/psso")
async def step_up_action(request: Request):
    st = request.app.state
    form = await request.form()
    signed = str(form.get("signedtoken", ""))
    pending = st.pending_auth.pop(request.query_params.get("session_code", ""), None)
    if signed == "none":
        st.auth_results.append({"stage": "step_up", "ok": False, "reason": "declined", "username": None})
        return HTMLResponse(pages.STEP_UP_DECLINED)
    verdict = _check(request, signed, "step_up")
    if not verdict.ok:
        return JSONResponse({"error": verdict.reason}, status_code=401)
    if pending is None:
        return JSONResponse({"error": "no_pending_auth"}, status_code=400)
    return _redirect_with_code(pending["redirect_uri"], pending["state"])


@router.get("/cb")
async def callback():
    return HTMLResponse(pages.CALLBACK)


@router.get("/evil/stepup.html")
async def evil_step_up():
    return HTMLResponse(pages.EVIL_STEP_UP)


@router.get("/evil/landing.html")
async def evil_landing():
    return HTMLResponse(pages.EVIL_LANDING)


@router.post("/evil/leak")
async def evil_leak():
    return Response(status_code=204)
