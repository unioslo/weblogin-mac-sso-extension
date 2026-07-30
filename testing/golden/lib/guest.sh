# Sourced by golden.sh. SSH plumbing against the booting guest.
# shellcheck shell=bash

# Force password auth only: skip the SSH agent (else e.g. the 1Password agent prompts on
# every call) and any on-disk keys. sshpass supplies GUEST_PASS.
_SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no -o IdentityAgent=none)

# Fresh clones intermittently reject the correct password for ~60s after boot
# (directory services still settling), interleaved with successes — retry that
# signature (exit 255 + "Permission denied") with a deadline, like the pytest
# harness's guest driver does.
_retry_auth_flake() {
  local rc stderr_f deadline=$((SECONDS + 120))
  stderr_f="$(mktemp)"
  while true; do
    "$@" 2>"${stderr_f}"; rc=$?
    if (( rc != 255 )) || ! grep -q "Permission denied" "${stderr_f}" || (( SECONDS >= deadline )); then
      cat "${stderr_f}" >&2; rm -f "${stderr_f}"; return "${rc}"
    fi
    sleep 3
  done
}
_ssh() { _retry_auth_flake sshpass -p "${GUEST_PASS}" ssh "${_SSH_OPTS[@]}" "$@"; }
_scp() { _retry_auth_flake sshpass -p "${GUEST_PASS}" scp "${_SSH_OPTS[@]}" "$@"; }

guest_ip() { tart ip "${GOLDEN_LOCAL}"; }

wait_for_ssh() {
  local ip deadline=$((SECONDS + 300))
  echo "waiting for guest SSH..."
  while (( SECONDS < deadline )); do
    ip="$(tart ip "${GOLDEN_LOCAL}" 2>/dev/null || true)"
    if [[ -n "$ip" ]] && _ssh "${GUEST_USER}@${ip}" true 2>/dev/null; then
      echo "guest reachable at ${ip}"; return 0
    fi
    sleep 5
  done
  echo "timed out waiting for guest SSH" >&2; return 1
}

guest_exec() { _ssh "${GUEST_USER}@$(guest_ip)" "$@"; }
guest_push() { _scp "$1" "${GUEST_USER}@$(guest_ip):$2"; }

# Hardware UUID (== MDM UDID) for addressing nanomdm commands.
guest_udid() {
  guest_exec "ioreg -rd1 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print \$4}'"
}
