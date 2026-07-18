import pytest
from httpx import ASGITransport, AsyncClient
from mock_idp.app import create_app


@pytest.fixture
def anyio_backend():
    # Async tests are marked with pytest.mark.anyio; run them on asyncio only.
    return "asyncio"


@pytest.fixture
def app():
    return create_app(issuer="https://idp.test/realms/test", audience="psso-aud")


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://idp.test") as c:
        yield c
