import pytest

pytestmark = pytest.mark.anyio


async def test_requests_recorded(client):
    await client.get("/psso/nonce")
    r = await client.get("/control/requests")
    paths = [e["path"] for e in r.json()]
    assert "/psso/nonce" in paths
    # /control/* traffic must be excluded from the recorder (the request that
    # reads the log must not appear in it).
    assert "/control/requests" not in paths


async def test_reset_clears_requests_and_faults(client):
    await client.get("/psso/nonce")
    await client.post("/control/fault", json={"type": "token_500", "times": 1})
    await client.post("/control/reset")
    r = await client.get("/control/requests")
    assert r.json() == []


async def test_arm_unknown_fault_is_400(client):
    r = await client.post("/control/fault", json={"type": "nonsense", "times": 1})
    assert r.status_code == 400
