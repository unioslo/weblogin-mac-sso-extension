#!/usr/bin/env bash
# One command: run the full VM-based PSSO scenario suite against a built .pkg.
#
#   testing/test-pkg.sh path/to/WebloginSSO.pkg
#
# Runs pytest, which starts the mock IdP compose stack for the session (see the
# idp_stack fixture), clones the golden VM per scenario, installs the pkg,
# triggers the extension, asserts, and tears everything down. Collects report,
# per-run artifacts and the scenario matrix.
set -euo pipefail

PKG="${1:?usage: test-pkg.sh <path-to-.pkg>}"
PKG_ABS="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"
[[ -f "$PKG_ABS" ]] || { echo "error: pkg not found: $PKG" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARTIFACTS="$HERE/harness/artifacts/run-$STAMP"
mkdir -p "$ARTIFACTS"

GOLDEN="${PSSO_GOLDEN_IMAGE:-ghcr.io/unioslo/weblogin-psso-test-vm:tahoe-26}"
# Host-side control URL; the leaf cert's SAN covers 127.0.0.1, so no /etc/hosts entry.
IDP_BASE="${PSSO_IDP_BASE_URL:-https://127.0.0.1:8443}"

for bin in tart docker sshpass; do
  command -v "$bin" >/dev/null || { echo "error: required binary '$bin' not found" >&2; exit 2; }
done

echo "==> Ensuring golden image is present (Plan 2)"
tart pull "$GOLDEN" || echo "   (tart pull failed; assuming local image $GOLDEN)"

echo "==> Preparing harness venv"
cd "$HERE/harness"
if [[ ! -d .venv ]]; then python3.12 -m venv .venv; fi
# shellcheck disable=SC1091
. .venv/bin/activate
pip install -q -e '.[dev]'

echo "==> Running scenarios against $PKG_ABS"
set +e
PSSO_PKG="$PKG_ABS" \
PSSO_GOLDEN_IMAGE="$GOLDEN" \
PSSO_IDP_BASE_URL="$IDP_BASE" \
PSSO_IDP_CA_CERT="$HERE/idp/certs/ca.crt" \
PSSO_ARTIFACTS="$ARTIFACTS" \
PSSO_MATRIX="$ARTIFACTS/scenario-matrix.md" \
  pytest -v scenarios \
    --junitxml="$ARTIFACTS/junit.xml" \
    --html="$ARTIFACTS/report.html" --self-contained-html
RC=$?
set -e

echo "==> Done. Artifacts in: $ARTIFACTS"
echo "    - report.html          (pytest-html)"
echo "    - junit.xml            (CI)"
echo "    - scenario-matrix.md   (pass/fail/skip per scenario)"
echo "    - <scenario>/webloginlog.txt, idp-requests.json, *.png (per-scenario)"
[[ -f "$ARTIFACTS/scenario-matrix.md" ]] && cat "$ARTIFACTS/scenario-matrix.md"
exit $RC
