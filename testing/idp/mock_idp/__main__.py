from __future__ import annotations
import os
import uvicorn
from .app import create_app

app = create_app(
    issuer=os.environ.get("IDP_ISSUER", "https://idp.test/realms/test"),
    audience=os.environ.get("IDP_AUDIENCE", "psso-aud"),
)


def main() -> None:
    cert = os.environ.get("IDP_TLS_CERT", "certs/idp.test.crt")
    key = os.environ.get("IDP_TLS_KEY", "certs/idp.test.key")
    uvicorn.run(
        app,
        host=os.environ.get("IDP_HOST", "0.0.0.0"),
        port=int(os.environ.get("IDP_PORT", "8443")),
        ssl_certfile=cert,
        ssl_keyfile=key,
    )


if __name__ == "__main__":
    main()
