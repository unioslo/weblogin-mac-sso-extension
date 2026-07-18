# Sourced by golden.sh. Asserts every prerequisite BEFORE anything mutates state.
# shellcheck shell=bash

preflight() {
  local ok=1
  command -v tart  >/dev/null || { echo "MISSING: tart (brew install cirruslabs/cli/tart)" >&2; ok=0; }
  command -v docker >/dev/null || { echo "MISSING: docker" >&2; ok=0; }
  command -v sshpass >/dev/null || { echo "MISSING: sshpass (brew install sshpass)" >&2; ok=0; }
  command -v cliclick >/dev/null || echo "WARN: cliclick not on host (only needed if driving VNC from host)" >&2

  # Refuse to bake unfilled placeholder config into the image (the first bake shipped
  # REPLACE_WITH_* values in the PSSO managed prefs this way).
  if grep -q "REPLACE_WITH_" .env; then
    echo "MISSING: .env still contains REPLACE_WITH_* placeholders — fill them in first" >&2
    ok=0
  fi
  # Plan 1 dependency: the disposable test CA (cert + key; the key signs the MDM TLS cert).
  if [[ ! -f "${CA_CRT}" || ! -f "${CA_CRT%/*}/ca.key" ]]; then
    echo "MISSING: ${CA_CRT} (+ ca.key) — run Plan 1's testing/idp/gen-test-ca.sh first" >&2
    ok=0
  fi
  # GATED APNs push cert.
  if [[ ! -f "nanomdm/secrets/push.pem" || ! -f "nanomdm/secrets/push.key" ]]; then
    echo "MISSING: nanomdm/secrets/push.{pem,key} — one-time gated APNs cert (see nanomdm/.env.example)" >&2
    ok=0
  fi
  [[ "$ok" == 1 ]] || { echo "preflight FAILED" >&2; return 1; }
  echo "preflight OK"
}
