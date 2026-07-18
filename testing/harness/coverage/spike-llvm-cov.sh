#!/usr/bin/env bash
# SPIKE (uncertain outcome — see plan 'Open items carried forward').
#
# Attempt in-VM LLVM line coverage of the extension:
#   1. build ssoe with coverage instrumentation,
#   2. run the scenarios so the instrumented extension executes,
#   3. pull the .profraw out of the guest,
#   4. render llvm-cov line coverage.
#
# If step 3 yields no .profraw (system-extension sandbox blocks
# LLVM_PROFILE_FILE writes to a readable path), STOP and run
# ./fallback-xctest.sh — that is the guaranteed coverage measure.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../artifacts/coverage-spike"
mkdir -p "$OUT"

echo "[spike] Building ssoe with coverage instrumentation"
xcodebuild \
  -project "$HERE/../../../Weblogin SSO.xcodeproj" \
  -scheme ssoe \
  -configuration Debug \
  -derivedDataPath "$OUT/dd" \
  OTHER_SWIFT_FLAGS="-profile-generate -profile-coverage-mapping" \
  build

echo "[spike] (manual) install the instrumented build's pkg in the guest, run scenarios,"
echo "[spike] then attempt to pull the profraw the extension wrote:"
cat <<'NOTE'
  # inside a scenario/guest session:
  #   export LLVM_PROFILE_FILE=/tmp/ssoe-%p.profraw   (must be set for the ext's process)
  #   ... run the flow ...
  #   scp guest:/tmp/ssoe-*.profraw "$OUT/"
NOTE

if ! ls "$OUT"/*.profraw >/dev/null 2>&1; then
  echo "[spike] NO .profraw collected — sandbox likely blocked it."
  echo "[spike] FALL BACK: run $HERE/fallback-xctest.sh"
  exit 3
fi

echo "[spike] Merging + rendering llvm-cov"
xcrun llvm-profdata merge -sparse "$OUT"/*.profraw -o "$OUT/ssoe.profdata"
BIN="$(find "$OUT/dd" -name 'ssoe' -type f | head -1)"
xcrun llvm-cov report "$BIN" -instr-profile="$OUT/ssoe.profdata" | tee "$OUT/llvm-cov-report.txt"
echo "[spike] SUCCESS — coverage in $OUT/llvm-cov-report.txt"
