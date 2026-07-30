from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .faults import FaultKind

router = APIRouter(prefix="/control")


class FaultBody(BaseModel):
    type: str
    times: int = 1


@router.post("/reset")
async def reset(request: Request):
    request.app.state.faults.reset()
    request.app.state.requests.clear()
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
