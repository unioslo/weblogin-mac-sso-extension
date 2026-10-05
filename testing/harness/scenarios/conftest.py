from __future__ import annotations
import os
import time
import pytest

from harness.stub_identity import new_identity

# Guest-side base URL of the SSO host. Must match the profile's PSSO_BASE_URL
# (testing/golden/.env): the extension only activates for URLs on its authsrv
# associated domain, which the guest remaps to the mock IdP.
GUEST_BASE_URL = os.environ.get("PSSO_GUEST_BASE_URL", "https://weblogin2.uio.no")


@pytest.fixture
def trigger_activation(guest):
    """Provoke the extension's authorization path (beginAuthorization).

    Opening a URL under the profile's URLPrefix makes Safari hand the navigation
    to the SSO extension. The agent is primed first so extension discovery doesn't
    race the authorization request. The path is BaseURL + /protocol/openid-connect/auth
    exactly, because beginAuthorization compares the URL prefix against that.
    """
    def _trigger(extra_cmd: str | None = None, settle: float = 12.0, prompt_login: bool = False):
        if extra_cmd:
            guest.run(extra_cmd)
        guest.run("app-sso platform -s >/dev/null 2>&1")
        time.sleep(3)
        auth_url = (
            f"{GUEST_BASE_URL}/protocol/openid-connect/auth"
            f"?client_id=psso-client&response_type=code&scope=openid&state=s1"
            f"&redirect_uri={GUEST_BASE_URL}/cb"
        )
        if prompt_login:
            auth_url += "&prompt=login"
        guest.run(f"open '{auth_url}'")
        time.sleep(settle)
    return _trigger


@pytest.fixture
def stub_identity(request, guest, idp):
    """Register a software device with the mock IdP and write psso-test-stub.json
    into the guest so a TESTSTUBS build treats the device as registered.

    Parametrize indirectly with the reauthentication mode ("succeed", "fail", "hang").
    """
    reauthentication = getattr(request, "param", "succeed")
    ident = new_identity()
    idp.register_device(ident.public_x962_b64())
    id_token = idp.mint_id_token(ident.username)
    guest.write_file(guest.stub_config_path(), ident.stub_json(id_token=id_token, reauthentication=reauthentication))
    return ident
