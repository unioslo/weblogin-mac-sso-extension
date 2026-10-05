import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mock_idp.envelope import DeviceRegistry, kid_for, verify_envelope


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_device(reg: DeviceRegistry):
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_x962 = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    kid = reg.register(base64.b64encode(pub_x962).decode())
    return priv, kid


def sign_envelope(priv, env: dict) -> str:
    env_b64 = b64url(json.dumps(env).encode())
    sig = priv.sign(env_b64.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return f"{env_b64}.{b64url(sig)}"


def envelope(kid: str, nonce: str, **over) -> dict:
    env = {
        "token": "a.b.c",
        "token_type": "id_token",
        "kid": kid,
        "signed_at": int(time.time()),
        "username": "testuser",
        "nonce": nonce,
        "client_id": "cid",
        "secure_enclave": False,
    }
    env.update(over)
    return env


def test_kid_is_standard_base64_sha256_of_uncompressed_point():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_x962 = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_x962)
    assert kid_for(pub) == base64.b64encode(digest.finalize()).decode()


def test_register_returns_kid_and_get_round_trips():
    reg = DeviceRegistry()
    priv, kid = make_device(reg)
    assert reg.get(kid) is not None
    assert reg.get("missing") is None


def test_valid_envelope_verifies_and_consumes_nonce():
    reg = DeviceRegistry()
    priv, kid = make_device(reg)
    nonce = "6F9619FF-8B86-D011-B42D-00C04FC964FF"  # extension sends upper case
    issued = {nonce.lower()}
    v = verify_envelope("Bearer " + sign_envelope(priv, envelope(kid, nonce)), devices=reg, issued_nonces=issued)
    assert v.ok, v.reason
    assert v.envelope["username"] == "testuser"
    assert issued == set()


def test_unknown_nonce_rejected():
    reg = DeviceRegistry()
    priv, kid = make_device(reg)
    v = verify_envelope(sign_envelope(priv, envelope(kid, "never-issued")), devices=reg, issued_nonces=set())
    assert not v.ok and v.reason == "nonce_unknown"


def test_unknown_device_rejected():
    reg = DeviceRegistry()
    priv, _ = make_device(reg)
    v = verify_envelope(sign_envelope(priv, envelope("other-kid", "n")), devices=reg, issued_nonces={"n"})
    assert not v.ok and v.reason == "unknown_device"


def test_bad_signature_rejected():
    reg = DeviceRegistry()
    priv, kid = make_device(reg)
    other = ec.generate_private_key(ec.SECP256R1())
    v = verify_envelope(sign_envelope(other, envelope(kid, "n")), devices=reg, issued_nonces={"n"})
    assert not v.ok and v.reason == "bad_signature"


def test_stale_signed_at_rejected():
    reg = DeviceRegistry()
    priv, kid = make_device(reg)
    env = envelope(kid, "n", signed_at=int(time.time()) - 3600)
    v = verify_envelope(sign_envelope(priv, env), devices=reg, issued_nonces={"n"})
    assert not v.ok and v.reason == "stale"


def test_malformed_header_rejected():
    reg = DeviceRegistry()
    v = verify_envelope("Bearer not-an-envelope", devices=reg, issued_nonces=set())
    assert not v.ok and v.reason == "malformed"
