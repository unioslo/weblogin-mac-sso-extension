import base64
import hashlib
import json

from harness.stub_identity import new_identity


def test_private_key_is_x963_97_bytes():
    ident = new_identity()
    raw = base64.b64decode(ident.x963_private_b64())
    assert len(raw) == 97 and raw[0] == 0x04
    pub = base64.b64decode(ident.public_x962_b64())
    assert raw[:65] == pub


def test_kid_matches_extension_derivation():
    ident = new_identity()
    pub = base64.b64decode(ident.public_x962_b64())
    assert ident.kid() == base64.b64encode(hashlib.sha256(pub).digest()).decode()


def test_stub_json_has_snake_case_schema():
    ident = new_identity(username="alice")
    doc = json.loads(ident.stub_json(id_token="a.b.c", reauthentication="fail"))
    assert doc == {
        "username": "alice",
        "authentication_method": "password",
        "sso_tokens": {"id_token": "a.b.c"},
        "signing_key_x963_base64": ident.x963_private_b64(),
        "reauthentication": "fail",
    }


def test_stub_json_rejects_unknown_reauthentication():
    try:
        new_identity().stub_json(id_token="a.b.c", reauthentication="maybe")
        assert False, "expected ValueError"
    except ValueError:
        pass
