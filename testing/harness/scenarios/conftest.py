from __future__ import annotations
import os
import time
import pytest

# Guest-side base URL of the SSO host. Must match the profile's PSSO_BASE_URL
# (testing/golden/.env): the extension only activates for URLs on its authsrv
# associated domain, which the guest remaps to the mock IdP.
GUEST_BASE_URL = os.environ.get("PSSO_GUEST_BASE_URL", "https://weblogin2.uio.no")


@pytest.fixture
def trigger_activation(guest):
    """Provoke the extension's authorization path (beginAuthorization).

    Opening a URL under the profile's URLPrefix makes Safari hand the navigation
    to the SSO extension. The agent is primed first so extension discovery doesn't
    race the authorization request. In a VM there is no functional SEP, so PSSO
    registration is never offered; the extension runs its authorization path and
    logs its (unregistered) decision.
    """
    def _trigger(extra_cmd: str | None = None, settle: float = 12.0):
        if extra_cmd:
            guest.run(extra_cmd)
        guest.run("app-sso platform -s >/dev/null 2>&1")
        time.sleep(3)
        auth_url = (
            f"{GUEST_BASE_URL}/realms/test/protocol/openid-connect/auth"
            f"?client_id=psso-client&response_type=code"
            f"&redirect_uri={GUEST_BASE_URL}/cb"
        )
        guest.run(f"open '{auth_url}'")
        time.sleep(settle)
    return _trigger
