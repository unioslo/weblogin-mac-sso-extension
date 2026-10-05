from __future__ import annotations
import uuid
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .faults import FaultKind

router = APIRouter(prefix="/control")


class FaultBody(BaseModel):
    type: str
    times: int = 1


class DeviceBody(BaseModel):
    public_key_x962_base64: str


class MintBody(BaseModel):
    username: str = "testuser"


@router.post("/reset")
async def reset(request: Request):
    st = request.app.state
    st.faults.reset()
    st.requests.clear()
    st.issued_nonces.clear()
    st.devices.clear()
    st.auth_results.clear()
    st.pending_auth.clear()
    return {"status": "reset"}


@router.post("/fault")
async def fault(body: FaultBody, request: Request):
    try:
        kind = FaultKind(body.type)
    except ValueError:
        return JSONResponse({"error": f"unknown fault type {body.type!r}"}, status_code=400)
    request.app.state.faults.arm(kind, times=body.times)
    return {"status": "armed", "type": kind.value, "times": body.times}


@router.get("/requests")
async def requests(request: Request):
    return request.app.state.requests


@router.post("/device")
async def device(body: DeviceBody, request: Request):
    """Register the test device's P-256 public key, as PSSO enrollment would."""
    try:
        kid = request.app.state.devices.register(body.public_key_x962_base64)
    except ValueError as e:
        return JSONResponse({"error": f"bad public key: {e}"}, status_code=400)
    return {"kid": kid}


@router.post("/mint")
async def mint(body: MintBody, request: Request):
    """Mint an id_token for the stub's sso_tokens without touching the request log."""
    st = request.app.state
    nonce = str(uuid.uuid4())
    return {"id_token": st.signer.mint_id_token(sub=body.username, nonce=nonce, groups=["staff"])}


@router.get("/auth_results")
async def auth_results(request: Request):
    return request.app.state.auth_results
