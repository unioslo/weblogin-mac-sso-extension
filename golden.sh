#!/usr/bin/env bash
# Single entry point for the golden VM image pipeline (testing/golden/). See
# testing/golden/README.md for the full pipeline and testing/golden/.env.example
# for bake configuration.
#
# Usage:
#   ./golden.sh build [--dry-run]   bake the golden image (maintainer-run, occasional)
#   ./golden.sh start [vm-name]     boot a local golden VM for inspection
#   ./golden.sh stop  [vm-name]     stop a running golden VM
#   ./golden.sh push  [vm-name]     push a local golden VM to GHCR
#   ./golden.sh verify [source]     clone a golden image fresh and assert it's correct
#   ./golden.sh status              show .env config and local/remote image state
set -euo pipefail

GOLDEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/testing/golden" && pwd)"
cd "${GOLDEN_DIR}"
if [[ ! -f .env ]]; then
  echo "ERROR: ${GOLDEN_DIR}/.env not found." >&2
  echo "Copy .env.example to .env and fill in the REPLACE_WITH_* values:" >&2
  echo "  cp ${GOLDEN_DIR}/.env.example ${GOLDEN_DIR}/.env" >&2
  exit 1
fi
set -a; . ./.env; set +a

usage() {
  cat <<USAGE >&2
Usage: $0 <build|start|stop|push|verify|status> [args...]
  build [--dry-run]   bake the golden image
  start [vm-name]     boot a local golden VM
  stop  [vm-name]     stop a running golden VM
  push  [vm-name]     push a local golden VM to GHCR
  verify [source]     clone-and-verify a golden image
  status              show .env config and local/remote image state
USAGE
  exit 1
}

cmd_build() {
  . lib/preflight.sh; . lib/guest.sh; . lib/provision.sh; . lib/enroll.sh
  local DRY_RUN=0; [[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

  plan() {
    cat <<PLAN
Golden-image bake plan:
  1. preflight            (tart, docker, sshpass, ${CA_CRT}, APNs push cert)
  2. tart clone           ${BASE_IMAGE} -> ${GOLDEN_LOCAL}
  3. tart run             ${GOLDEN_LOCAL} --no-graphics --vnc-experimental (background)
  4. wait_for_ssh
  5. generate PSSO profile (BaseURL=${PSSO_BASE_URL})
  6. provision_guest      (ssh key, cliclick, guest-agent, trust CA, idp.test -> gateway)
  7. enroll_guest         (nanomdm up, stage profile, manual UAMDM approve via VNC, push InstallProfile)
  8. shutdown + tart stop
  9. tart push            ${GOLDEN_LOCAL} -> ${GOLDEN_REMOTE}
 10. cleanup              (tart delete ${GOLDEN_LOCAL}, nanomdm_down)
PLAN
  }

  if [[ "$DRY_RUN" == 1 ]]; then plan; return 0; fi

  preflight
  plan
  tart clone "${BASE_IMAGE}" "${GOLDEN_LOCAL}"
  tart run "${GOLDEN_LOCAL}" --no-graphics --vnc-experimental >/tmp/tart-golden.log 2>&1 &
  local TART_PID=$!
  trap 'tart stop "${GOLDEN_LOCAL}" 2>/dev/null || true; nanomdm_down 2>/dev/null || true' EXIT

  wait_for_ssh
  ./generate-psso-profile.sh
  provision_guest
  enroll_guest

  guest_exec "sudo shutdown -h now" || true
  tart stop "${GOLDEN_LOCAL}" 2>/dev/null || true
  wait "${TART_PID}" 2>/dev/null || true

  tart push "${GOLDEN_LOCAL}" "${GOLDEN_REMOTE}"
  echo "PUSHED ${GOLDEN_REMOTE}"

  nanomdm_down
  tart delete "${GOLDEN_LOCAL}"
  echo "BAKE COMPLETE"
}

cmd_start() {
  . lib/guest.sh; . lib/enroll.sh
  local VM="${1:-${GOLDEN_LOCAL}}"
  GOLDEN_LOCAL="${VM}"                # so guest_ip/wait_for_ssh target this VM
  local LOG="/tmp/tart-${VM}.log"

  vm_running() { tart list 2>/dev/null | grep -w "${VM}" | grep -qw running; }

  echo "== nanomdm stack =="
  nanomdm_up

  echo "== VM ${VM} =="
  if vm_running; then
    echo "already running"
  else
    nohup tart run "${VM}" --no-graphics --vnc-experimental >"${LOG}" 2>&1 &
    disown
  fi

  wait_for_ssh
  echo
  echo "VM ready:  ssh ${GUEST_USER}@$(guest_ip)   (password: ${GUEST_PASS})"
  echo "VNC:       $(grep -Eo 'vnc://[^[:space:]]+' "${LOG}" 2>/dev/null | tail -1 || echo '<see '"${LOG}"'>')"
  echo "MDM API:   ${NANOMDM_URL}   (device endpoint: https://${IDP_HOST}:9000/mdm via nginx mTLS)"
  echo "Down with: $0 stop ${VM}"
}

cmd_stop() {
  . lib/enroll.sh
  local VM="${1:-${GOLDEN_LOCAL}}"

  if tart stop "${VM}" 2>/dev/null; then echo "stopped VM ${VM}"; else echo "VM ${VM} was not running"; fi
  nanomdm_down
  echo "nanomdm stack down"
}

cmd_push() {
  local VM="${1:-${GOLDEN_LOCAL}}"
  tart list 2>/dev/null | grep -qw "${VM}" || { echo "MISSING: no local Tart VM named ${VM}" >&2; exit 1; }
  tart push "${VM}" "${GOLDEN_REMOTE}"
  echo "PUSHED ${GOLDEN_REMOTE}"
}

cmd_status() {
  echo "== .env (${GOLDEN_DIR}/.env) =="
  local v
  for v in ORG MACOS_VER BASE_IMAGE GOLDEN_LOCAL GOLDEN_REMOTE \
           EXT_BUNDLE_ID TEAM_ID PSSO_CLIENT_ID PSSO_BASE_URL IDP_HOST NANOMDM_URL; do
    printf '  %-14s = %s\n' "$v" "${!v-<unset>}"
  done

  echo
  echo "== local Tart VMs/images =="
  local list; list="$(tart list 2>/dev/null || true)"
  if grep -qw "${GOLDEN_LOCAL}" <<<"$list"; then
    grep -w "${GOLDEN_LOCAL}" <<<"$list" | sed 's/^/  /'
  else
    echo "  MISSING: no local VM named ${GOLDEN_LOCAL}"
  fi
  grep -F "${BASE_IMAGE%%:*}" <<<"$list" | sed 's/^/  /' || echo "  base image not pulled locally"

  echo
  echo "== remote ${GOLDEN_REMOTE} =="
  local pkg="${GOLDEN_REMOTE#ghcr.io/"${ORG}"/}"; pkg="${pkg%%:*}"
  local versions
  if versions="$(gh api "orgs/${ORG}/packages/container/${pkg}/versions" 2>/dev/null \
              || gh api "users/${ORG}/packages/container/${pkg}/versions" 2>/dev/null)"; then
    jq -r '.[] | "  \(.name)  tags=\(.metadata.container.tags | join(","))  updated=\(.updated_at)"' \
      <<<"$versions" | head -5
  else
    echo "  MISSING: ghcr.io/${ORG}/${pkg} not found (never pushed, or no gh access)"
  fi
}

cmd_verify() {
  . lib/guest.sh
  # Not `local`: on a set -e abort, bash unwinds function locals before running the
  # EXIT trap, so a local CLONE would be unbound (set -u) and cleanup would be skipped.
  CLONE="verify-$(date +%s)"
  local SRC="${1:-${GOLDEN_REMOTE}}"
  trap 'tart stop "${CLONE}" 2>/dev/null || true; tart delete "${CLONE}" 2>/dev/null || true' EXIT

  tart clone "${SRC}" "${CLONE}"
  tart run "${CLONE}" --no-graphics >/tmp/tart-verify.log 2>&1 &

  # Point the guest helpers at the clone.
  GOLDEN_LOCAL="${CLONE}"
  wait_for_ssh

  # check <label> <guest command> <grep pattern>. Failures don't abort (a failing
  # left-hand side of && is exempt from set -e); they're collected so every check
  # runs and the final exit status is honest.
  local FAILED=0
  check() {
    echo "== $1 =="
    if guest_exec "$2" | grep -qi "$3"; then
      echo "PASS: $1"
    else
      echo "FAIL: $1" >&2; FAILED=1
    fi
  }

  check "1. MDM enrollment is user-approved (UAMDM)" \
        "profiles status -type enrollment" "User Approved"
  # MDM-delivered profiles are device-level: visible to `sudo profiles list`, not the
  # user-level `profiles list`.
  check "2. PSSO payload present (device profile)" \
        "sudo profiles list -type configuration" "${EXT_BUNDLE_ID}.psso"
  # MDM-managed prefs land in /Library/Managed Preferences/<domain>.plist, which
  # `defaults read <domain>` does not consult — read the file's domain explicitly.
  local SSO_HOST_FROM_URL
  SSO_HOST_FROM_URL="$(sed -E 's#^[a-z]+://([^/:]+).*#\1#' <<<"${PSSO_BASE_URL}")"
  check "3. extension reads its managed config (BaseURL = SSO host)" \
        "defaults read '/Library/Managed Preferences/${EXT_BUNDLE_ID}'" "${SSO_HOST_FROM_URL}"
  echo "== 3b. managed config carries real values, not placeholders =="
  if guest_exec "defaults read '/Library/Managed Preferences/${EXT_BUNDLE_ID}'" | grep -q "REPLACE_WITH"; then
    echo "FAIL: 3b. managed config still has REPLACE_WITH_* placeholders (bake ran with an unfilled .env)" >&2
    FAILED=1
  else
    echo "PASS: 3b. managed config carries real values"
  fi
  # The extension validates TLS via SecTrust, so assert with security verify-cert, not
  # curl: both of Tahoe's curl backends ignore System-keychain trust for custom CAs.
  # Fetching the leaf over the wire also proves the mock IdP is reachable over NAT.
  check "4. test CA trusted (SecTrust) + mock IdP reachable over NAT" \
        "echo | openssl s_client -connect ${IDP_HOST}:8443 2>/dev/null \
           | openssl x509 > /tmp/verify-leaf.pem \
           && security verify-cert -p ssl -s ${IDP_HOST} -c /tmp/verify-leaf.pem 2>&1" \
        "certificate verification successful"
  # The extension only activates for URLs on its authsrv associated domain, reached
  # in-guest via this /etc/hosts remap on the standard port (see .env.example).
  check "5. SSO host (${SSO_HOST_FROM_URL}) remapped to the NAT gateway" \
        "grep -w '${SSO_HOST_FROM_URL}' /etc/hosts" "${SSO_HOST_FROM_URL}"
  # Spotlight indexing must be ON or LaunchServices never discovers an installed
  # ssoe.appex and AppSSOAgent refuses to activate it (no containing-app proxy).
  check "6. Spotlight indexing enabled (appex discovery)" \
        "mdutil -s /" "Indexing enabled"

  if (( FAILED )); then
    echo "VERIFY FAILED for clone of ${SRC}" >&2
    exit 1
  fi
  echo "ALL CHECKS PASSED for clone of ${SRC}"
}

CMD="${1:-}"; [[ -n "$CMD" ]] || usage
shift

case "$CMD" in
  build)  cmd_build "$@" ;;
  start)  cmd_start "$@" ;;
  stop)   cmd_stop "$@" ;;
  push)   cmd_push "$@" ;;
  verify) cmd_verify "$@" ;;
  status) cmd_status "$@" ;;
  *) usage ;;
esac
