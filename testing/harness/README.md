# PSSO test harness (Plan 3 of 3)

pytest harness that runs the VM-based PSSO extension scenarios. Depends on
**Plan 1** (the `testing/idp/` mock + Keycloak stack) and **Plan 2** (the golden
Tart image `ghcr.io/unioslo/weblogin-psso-test-vm:tahoe-26`). Runs on
an Apple Silicon Mac with `tart`, `docker`, and `sshpass`.

## One command

    testing/test-pkg.sh path/to/WebloginSSO.pkg

This brings up the IdP stack (keeping the existing test CA — the golden image
trusts it), clones the golden VM per scenario, installs the pkg, triggers the
extension, asserts, and writes a report + per-run artifacts + a scenario
matrix, then tears the stack down.

## What it asserts

The guest has no functional Secure Enclave, so SE-backed registration cannot
complete in a VM. Scenarios assert the extension's **observable** behavior:
`webloginlog:` log lines (`sudo log show --info --debug`) plus the **89c5a0a**
invariant (no double-completion log signature) on every row. Per-scenario
artifacts are collected for post-mortem: `webloginlog.txt` and the IdP-side
request log (`idp-requests.json`, from mock-idp `GET /control/requests`). The
drivers can additionally read guest / app-group state and take VNC screenshots
for tighter future rows.

The guaranteed guard for the throwing save-config path is the
`ssoeTests/RegistrationCompletionRegressionTests` XCTest (run it on a machine
with full Xcode; this repo's dev hosts may carry only Command Line Tools).

## Layout

- `harness/log_assert.py`, `harness/matrix.py`, `harness/drivers/idp.py` — pure,
  unit-tested logic (`pytest tests`).
- `harness/drivers/{guest,ui}.py` — live SSH / VNC drivers. SSH is sshpass
  password auth (cirruslabs admin/admin — the golden image bakes no key);
  every SSH/scp op retries the early-boot auth flake (fresh clones reject the
  correct password intermittently for ~60s). Logs are read with
  `sudo log show --info --debug` — non-root `log show` silently returns
  nothing, and most extension lines are info/debug level. The UI driver does
  coordinate clicks + full-frame `expect_screen` (vncdotool has no template
  search); capture reference PNGs with `screenshot()`, not external tools.
- `conftest.py` — `vm` (clone-per-test), `guest`, `ui`, `idp`, `artifacts`
  fixtures + the JUnit→matrix `pytest_sessionfinish` hook.
- `scenarios/test_scenarios.py` — one parametrized case per design-spec row.
  Rows declare which IdP the golden image's profile must target; mismatched
  rows skip (`PSSO_PROFILE_IDP`, default `mock` — repointing at Keycloak
  requires a re-bake, see `testing/golden/README.md`).
- `coverage/spike-llvm-cov.sh` — SPIKE (in-VM llvm-cov, uncertain; exits 3 →
  run the fallback).
- `coverage/fallback-xctest.sh` — FALLBACK (guaranteed: ssoeTests coverage via
  the `ssoeTests` scheme + the scenario matrix).

## Run just the pure unit tests (no VM needed)

    python3.12 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
    pytest tests

## Environment (set by test-pkg.sh; override as needed)

`PSSO_PKG`, `PSSO_GOLDEN_IMAGE`, `PSSO_IDP_BASE_URL` (host side — defaults to
`https://127.0.0.1:8443`; the test leaf cert's SAN covers 127.0.0.1, so no
/etc/hosts entry is needed), `PSSO_IDP_CA_CERT`, `PSSO_SSH_USER`,
`PSSO_SSH_PASS`, `PSSO_APP_GROUP` (default `group.no.uio.weblogin`; forks
override with their app group), `PSSO_PROFILE_IDP`,
`PSSO_ARTIFACTS`, `PSSO_MATRIX` (+ `--junitxml` as the JUnit source of truth).

## How the extension gets activated

macOS only hands a URL to the SSO extension when ALL of these hold; the golden
image and harness provide each one:

1. **Managed config + SSO payload carry real values** (TeamIdentifier must equal
   the pkg's signing team; placeholders = extension silently never loads).
2. **The URL's host is the extension's authsrv associated domain** (`SSO_HOST`,
   e.g. `weblogin2.uio.no`). swcd validates the domain against the
   *production* host's AASA via Apple's CDN; the guest remaps the host to the
   mock IdP (port 443) for actual traffic. Profile BaseURL/URLs use this host.
3. **LaunchServices knows the appex**: Spotlight indexing on (golden image) +
   `lsregister -f` of the app after pkg install + `killall AppSSOAgent`
   (`installed_pkg` fixture does the latter two).
4. **Trigger**: `open <BaseURL-prefixed URL>` in the guest — Safari hands the
   navigation to the extension (`trigger_activation`). `app-sso platform -s`
   alone provokes nothing.

Without a SEP, PSSO registration is never *offered* (no REGISTER_DEVICE
notification), so the extension takes its unregistered path: it logs
`webloginlog: ... Won't display browser` and declines. That is the observable
behavior scenario rows assert; token-flow assertions need registration and stay
out of VM scope.

## Open items

- Scenario rows assert the generic `webloginlog:` presence; tighten per-row
  `expect_log` once fault-specific lines are worth pinning.
- `defaults`-CLI app-group domain vs the extension's group-container plist —
  unverified (see comment in `harness/drivers/guest.py`).
