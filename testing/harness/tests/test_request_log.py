from harness.drivers.idp import RequestLog, fault_payload

# Shape mirrors Plan-1 mock-idp GET /control/requests entries.
ENTRIES = [
    {"method": "POST", "path": "/psso/nonce", "query": "", "body": "grant_type=srv_challenge"},
    {"method": "POST", "path": "/psso/token", "query": "", "body": "grant_type=authorization_code&code=abc"},
    {"method": "POST", "path": "/psso/token", "query": "", "body": "grant_type=refresh_token"},
]


def test_paths_lists_paths_in_order():
    rl = RequestLog(ENTRIES)
    assert rl.paths() == ["/psso/nonce", "/psso/token", "/psso/token"]


def test_count_filters_by_path_and_method():
    rl = RequestLog(ENTRIES)
    assert rl.count("/psso/token") == 2
    assert rl.count("/psso/nonce", method="POST") == 1
    assert rl.count("/psso/nonce", method="GET") == 0


def test_nonce_requested_true_when_present():
    assert RequestLog(ENTRIES).nonce_requested() is True
    assert RequestLog([]).nonce_requested() is False


def test_bodies_for_returns_matching_bodies():
    rl = RequestLog(ENTRIES)
    bodies = rl.bodies_for("/psso/token")
    assert any("authorization_code" in b for b in bodies)
    assert len(bodies) == 2


def test_fault_payload_builds_expected_dict():
    assert fault_payload("token_500") == {"type": "token_500", "times": 1}
    assert fault_payload("timeout", times=3) == {"type": "timeout", "times": 3}
