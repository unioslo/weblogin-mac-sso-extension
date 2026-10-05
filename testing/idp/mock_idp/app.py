from __future__ import annotations
from fastapi import FastAPI, Request
from .signing import Signer
from .faults import FaultRegistry
from .envelope import DeviceRegistry
from . import control_routes, idp_routes


def create_app(*, issuer: str, audience: str) -> FastAPI:
    app = FastAPI()
    app.state.signer = Signer(issuer=issuer, audience=audience)
    app.state.faults = FaultRegistry()
    app.state.requests = []  # list[dict]
    app.state.last_nonce = None  # last nonce issued by /psso/nonce
    app.state.issued_nonces = set()      # lower-case nonces /psso/nonce handed out, consumed on use
    app.state.devices = DeviceRegistry()  # kid -> public key, from POST /control/device
    app.state.auth_results = []          # dicts: stage, ok, reason, username
    app.state.pending_auth = {}          # session_code -> {redirect_uri, state}

    @app.middleware("http")
    async def record(request: Request, call_next):
        if not request.url.path.startswith("/control"):
            body = (await request.body()).decode("utf-8", "replace")
            app.state.requests.append(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "query": str(request.url.query),
                    "body": body,
                }
            )
        return await call_next(request)

    app.include_router(control_routes.router)
    app.include_router(idp_routes.router)
    return app
