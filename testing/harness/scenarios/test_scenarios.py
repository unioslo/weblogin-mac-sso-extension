from __future__ import annotations
import json
import os
import pathlib

import pytest

from harness.log_assert import (
    parse_webloginlog,
    assert_logged,
    count_matching,
    double_completion_after_save_failure,
)

# Which IdP the golden image's PSSO profile was baked to point at (repointing
# requires a re-bake — see testing/golden/README.md). Rows for the other IdP
# skip so the matrix never overclaims coverage.
PROFILE_IDP = os.environ.get("PSSO_PROFILE_IDP", "mock")

pytestmark = [pytest.mark.live, pytest.mark.scenario]


# Each entry = one design-spec row.
#   id            : short name -> shows up as [id] in the matrix
#   fault         : mock-idp FaultKind to arm (None = happy path / no fault)
#   idp           : "mock" | "keycloak"
#   expect_log    : substring that MUST appear in webloginlog output (seed placeholders — tighten to fault-specific lines during first live runs)
#   forbid_log    : substring that MUST NOT appear (or None)
#   skip_reason   : non-None => xfail/skip with this reason (out-of-scope in VM)
SCENARIOS = [
    dict(id="happy_path",            fault=None,                 idp="keycloak",
         expect_log="viewDidLoad",   forbid_log=None,            skip_reason=None),
    dict(id="invalid_id_token",      fault="malformed_id_token", idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="expired_id_token",      fault="expired_id_token",   idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="malformed_id_token",    fault="malformed_id_token", idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="wrong_nonce",           fault="bad_nonce",          idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="token_500",             fault="token_500",          idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="token_timeout",         fault="timeout",            idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="token_bad_json",        fault="token_bad_json",     idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="reauth_password",       fault=None,                 idp="keycloak",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="concurrent_auth",       fault=None,                 idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="corrupt_app_group",     fault=None,                 idp="mock",
         expect_log="webloginlog:",  forbid_log=None,            skip_reason=None),
    dict(id="profile_repush",        fault=None,                 idp="mock",
         expect_log=None,            forbid_log=None,
         skip_reason="needs nanomdm live; profile change loop is a later effort"),
]


@pytest.mark.parametrize("spec", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario(spec, idp, guest, installed_pkg, trigger_activation, artifacts):
    if spec["skip_reason"]:
        pytest.skip(spec["skip_reason"])

    if spec["idp"] != PROFILE_IDP:
        pytest.skip(f"golden image profile targets {PROFILE_IDP!r}, row needs {spec['idp']!r}")

    # Arm the fault (if any) on the clean mock IdP.
    if spec["fault"]:
        idp.arm(spec["fault"], times=1)

    # Scenario-specific pre-state.
    if spec["id"] == "corrupt_app_group":
        guest.corrupt_app_group()
    if spec["id"] == "concurrent_auth":
        # True fire-and-forget: without nohup+redirect the backgrounded child holds
        # the SSH channel open and the call degrades to sequential.
        guest.run("nohup app-sso platform -s >/dev/null 2>&1 &")

    trigger_activation()

    logs = parse_webloginlog(guest.ext_logs(last="5m"))
    pathlib.Path(artifacts, "webloginlog.txt").write_text("\n".join(logs), encoding="utf-8")

    # Dump the IdP-side request log for post-mortem (seed rows don't assert on it yet).
    with open(f"{artifacts}/idp-requests.json", "w", encoding="utf-8") as fh:
        json.dump(idp.request_log().entries, fh, indent=2)

    if spec["expect_log"]:
        assert_logged(logs, spec["expect_log"])
    if spec["forbid_log"]:
        assert count_matching(logs, spec["forbid_log"]) == 0

    # Universal invariant across EVERY scenario: no double completion (regression 89c5a0a).
    assert not double_completion_after_save_failure(logs), (
        "double-completion signature present: save-config failure followed by password success path"
    )


def test_scenario_registration_save_failure_no_double_completion(
    idp, guest, installed_pkg, trigger_activation, artifacts
):
    """Dedicated regression for commit 89c5a0a.

    We cannot force `saveUserLoginConfiguration` to throw from outside the SEP in
    a VM (SE-backed registration is out of scope), so this asserts the *observable*
    invariant on whatever registration path the VM reaches: the double-completion
    log signature must never appear. The GUARANTEED guard for the throwing path is
    the ssoeTests XCTest added in Task 11's fallback.
    """
    trigger_activation()
    logs = parse_webloginlog(guest.ext_logs(last="5m"))
    pathlib.Path(artifacts, "webloginlog.txt").write_text("\n".join(logs), encoding="utf-8")
    assert not double_completion_after_save_failure(logs)
