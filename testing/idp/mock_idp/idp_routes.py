from __future__ import annotations
import asyncio
import uuid
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from .faults import FaultKind

router = APIRouter()

BAD_NONCE = "00000000-0000-0000-0000-000000000000"


@router.api_route("/psso/nonce", methods=["GET", "POST"])
async def nonce(request: Request):
    faults = request.app.state.faults
    request.app.state.last_nonce = BAD_NONCE if faults.consume(FaultKind.BAD_NONCE) else str(uuid.uuid4())
    return {"nonce": request.app.state.last_nonce}


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


@router.get("/protocol/openid-connect/auth")
async def auth(request: Request):
    return PlainTextResponse("<html><body>mock auth</body></html>", media_type="text/html")
