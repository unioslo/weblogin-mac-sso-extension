#!/usr/bin/env bash
# FALLBACK (guaranteed coverage measure). Runs regardless of the spike outcome.
#
# Two complementary signals:
#   1. ssoeTests XCTest line coverage for the pure helpers (Helpers.swift,
#      RegistrationState.swift) — Xcode's own coverage.
#   2. The scenario matrix (scenario-matrix.md) as the behavioral coverage map.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../artifacts/coverage-fallback"
mkdir -p "$OUT"

echo "[fallback] Running ssoeTests with coverage enabled"
rm -rf "$OUT/ssoeTests.xcresult"
xcodebuild test \
  -project "$HERE/../../../Weblogin SSO.xcodeproj" \
  -scheme ssoeTests \
  -destination 'platform=macOS' \
  -enableCodeCoverage YES \
  -resultBundlePath "$OUT/ssoeTests.xcresult"

echo "[fallback] Extracting line coverage"
xcrun xccov view --report "$OUT/ssoeTests.xcresult" | tee "$OUT/xctest-coverage.txt"

MATRIX="$HERE/../artifacts"/run-*/scenario-matrix.md
if ls $MATRIX >/dev/null 2>&1; then
  echo "[fallback] Latest scenario matrix:"
  cat $(ls -t $MATRIX | head -1)
else
  echo "[fallback] No scenario matrix yet — run test-pkg.sh to produce one."
fi
echo "[fallback] Done. See $OUT/xctest-coverage.txt + scenario-matrix.md"
