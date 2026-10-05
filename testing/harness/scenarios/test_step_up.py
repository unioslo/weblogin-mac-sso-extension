"""Header login and step-up through a TESTSTUBS build (testing/build-test-pkg.sh).

Each row clones the golden VM, installs the pkg, writes the stub identity, opens
the auth URL in Safari and asserts on the mock IdP's request log and auth results.
Each row pins one step-up behaviour: the signed step-up token must carry the
challenge from the extension's last envelope, foreign documents never receive an
answer, and every failure path replies.
"""
from __future__ import annotations
import json
import pathlib

import pytest

from harness.log_assert import assert_logged, count_matching, parse_webloginlog

pytestmark = [pytest.mark.live, pytest.mark.scenario]

STUB_ACTIVE = "TESTSTUB login manager active"
STEP_UP_POST = "/login-actions/psso"
NO_CHALLENGE = "getSignedToken with no challenge token"
NOT_DELIVERING = "Not delivering step-up result"
VERIFY_FAILED = "step-up assertion failed verification"
REAUTH_PROMPT = "Reauthentication required"


def _collect(guest, idp, artifacts):
    logs = parse_webloginlog(guest.ext_logs(last="5m"))
    pathlib.Path(artifacts, "webloginlog.txt").write_text("\n".join(logs), encoding="utf-8")
    log = idp.request_log()
    results = idp.auth_results()
    with open(f"{artifacts}/idp-requests.json", "w", encoding="utf-8") as fh:
        json.dump(log.entries, fh, indent=2)
    with open(f"{artifacts}/idp-auth-results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    assert_logged(logs, STUB_ACTIVE)  # a pkg without TESTSTUBS makes every row here meaningless
    return logs, log, results


def test_header_login_completes(idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts):
    trigger_activation()
    logs, log, results = _collect(guest, idp, artifacts)
    assert_logged(logs, "There are SSO Tokens")
    assert results[0] == {"stage": "header", "ok": True, "reason": "ok", "username": "testuser"}
    assert log.count("/cb", "GET") == 1, "Safari never fetched the callback with the code"
    assert log.count(STEP_UP_POST) == 0


def test_step_up_signs_and_submits_once(idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts):
    trigger_activation(prompt_login=True, settle=20.0)
    logs, log, results = _collect(guest, idp, artifacts)
    assert count_matching(logs, VERIFY_FAILED) == 0
    assert log.count(STEP_UP_POST, "POST") == 1
    assert [r["stage"] for r in results] == ["header", "step_up"]
    assert results[1]["ok"] is True, results[1]
    assert log.count("/cb", "GET") == 1


@pytest.mark.parametrize(("fault", "reason"), [
    ("step_up_forged_token", "step-up verify: bad signature"),
    ("step_up_wrong_challenge", "step-up verify: challenge mismatch"),
    ("step_up_expired_token", "step-up verify: expired"),
])
def test_unverified_step_up_token_is_declined_without_prompt(
    idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts, fault, reason
):
    """A step-up token the extension cannot verify answers none before any reauthentication."""
    idp.arm(fault, times=1)
    trigger_activation(settle=20.0)
    logs, log, results = _collect(guest, idp, artifacts)
    assert_logged(logs, reason)
    assert_logged(logs, VERIFY_FAILED)
    assert count_matching(logs, REAUTH_PROMPT) == 0
    assert log.count(STEP_UP_POST, "POST") == 1
    assert all("signedtoken=none" in body for body in log.bodies_for(STEP_UP_POST))
    assert results[-1]["reason"] == "declined"


@pytest.mark.parametrize("stub_identity", ["fail"], indirect=True)
def test_step_up_reauth_failure_answers_none_once(idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts):
    """A failed reauthentication answers pssoSigned('none') exactly once."""
    trigger_activation(prompt_login=True, settle=20.0)
    logs, log, results = _collect(guest, idp, artifacts)
    assert log.count(STEP_UP_POST, "POST") == 1
    assert all("signedtoken=none" in body for body in log.bodies_for(STEP_UP_POST))
    assert results[-1]["reason"] == "declined"


def test_step_up_nonce_failure_still_answers_the_page(idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts):
    """A failed nonce fetch still answers the step-up page (declined)."""
    idp.arm("step_up_nonce_500", times=1)
    trigger_activation(settle=20.0)
    logs, log, results = _collect(guest, idp, artifacts)
    assert_logged(logs, "Failed to fetch nonce")
    assert log.count(STEP_UP_POST, "POST") == 1
    assert results[-1]["reason"] == "declined"


def test_foreign_iframe_gets_no_token(idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts):
    """The foreign frame has no step-up token, so its request is answered none, in the main frame only."""
    idp.arm("step_up_iframe", times=1)
    trigger_activation(settle=20.0)
    logs, log, results = _collect(guest, idp, artifacts)
    assert log.count("/evil/stepup.html", "GET") == 1, "the iframe never loaded; the variant did not render"
    assert log.count("/evil/leak") == 0, "a foreign-origin frame received pssoSigned"
    assert_logged(logs, NO_CHALLENGE)


def test_navigating_away_drops_the_answer(idp, guest, installed_pkg, stub_identity, trigger_activation, artifacts):
    idp.arm("step_up_navigate", times=1)
    trigger_activation(settle=20.0)
    logs, log, results = _collect(guest, idp, artifacts)
    assert log.count("/evil/landing.html", "GET") == 1, "the page never navigated; the variant did not render"
    assert log.count("/evil/leak") == 0, "the foreign document received the step-up answer"
    assert count_matching(logs, VERIFY_FAILED) == 0  # NOT_DELIVERING alone also follows a failed verify
    assert_logged(logs, "Sending signed token to the IdP")
    assert_logged(logs, NOT_DELIVERING)
    assert log.count(STEP_UP_POST) == 0
    assert count_matching(logs, "Error calling pssoSigned") == 0
