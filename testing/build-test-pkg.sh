#!/usr/bin/env bash
# Build a Weblogin SSO .pkg with the TESTSTUBS login manager compiled in, for
# testing/test-pkg.sh. Never ship this pkg: a stub file in the app group
# container makes the extension skip Secure Enclave registration.
#
#   testing/build-test-pkg.sh [extra xcodebuild settings, e.g. DEVELOPMENT_TEAM=XXXX]
#
# The pkg must be signed by the team the golden image's profile names
# (TEAM_ID in testing/golden/.env), or the extension never loads in the guest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/teststubs"
PRODUCTS="$OUT/Build/Products/Release"
APP="$PRODUCTS/Weblogin SSO.app"
PKG="$OUT/WebloginSSO-teststubs.pkg"
MARKER="TESTSTUB login manager active"

rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> Building with TESTSTUBS"
# shellcheck disable=SC2016  # $(inherited) is for xcodebuild, not the shell
xcodebuild -project "$ROOT/Weblogin SSO.xcodeproj" -scheme "Weblogin SSO" \
  -configuration Release -derivedDataPath "$OUT" build \
  SWIFT_ACTIVE_COMPILATION_CONDITIONS='$(inherited) TESTSTUBS' "$@"

APPEX_BIN="$APP/Contents/PlugIns/ssoe.appex/Contents/MacOS/ssoe"
[[ -x "$APPEX_BIN" ]] || { echo "error: appex binary not found at $APPEX_BIN" >&2; exit 1; }
if ! strings "$APPEX_BIN" | grep -F "$MARKER" >/dev/null; then
  echo "error: built appex does not contain the stub marker; TESTSTUBS did not take effect" >&2
  exit 1
fi

echo "==> Packaging"
pkgbuild --component "$APP" --install-location /Applications "$PKG"
echo "==> $PKG"
