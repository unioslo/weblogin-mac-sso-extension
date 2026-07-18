# Sourced by golden.sh. Enrolls the guest into the disposable nanomdm via UAMDM,
# then pushes the PSSO configuration profile as an MDM InstallProfile command.
#
# UAMDM cannot be fully headless: macOS requires a GUI approval click for user-approved
# MDM. We install the enrollment profile over SSH, then drive the approval via cliclick
# in the guest (Tart is booted with --vnc-experimental). The exact click coordinates are
# screen/OS-version dependent — see OPEN ITEM; verify_enrolled() below is the real gate.
# shellcheck shell=bash

# Mint the disposable MDM certs, build the local scep image, bring the stack up, and
# upload the APNs push cert (nanomdm takes it via its API, not a CLI flag).
nanomdm_up() {
  # NB: `cp -n` returns non-zero when the target exists, which aborts this subshell under
  # `set -e` (callers set it) — so copy only when .env is actually missing.
  ( cd nanomdm && { [[ -f .env ]] || cp .env.example .env; } && ./gen-mdm-certs.sh && \
    docker compose up -d --build )
  local deadline=$((SECONDS + 60))
  until curl -sf "${NANOMDM_URL}/version" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || { echo "nanomdm API did not come up" >&2; return 1; }
    sleep 2
  done
  cat nanomdm/secrets/push.pem nanomdm/secrets/push.key \
    | curl -sf -u "nanomdm:${NANOMDM_API_KEY}" -T - "${NANOMDM_URL}/v1/pushcert" >/dev/null \
    && echo "uploaded APNs push cert to nanomdm"
}
nanomdm_down() { ( cd nanomdm && docker compose down -v ); }

# The APNs topic nanomdm serves under is the UID value in the push cert subject,
# e.g. subject=UID=com.apple.mgmt.External.<uuid>, CN=APSP:<uuid>, C=NO
push_topic() {
  openssl x509 -in nanomdm/secrets/push.pem -noout -subject \
    | sed -n 's/.*UID=\([^,/]*\).*/\1/p'
}

# Build the manual-enrollment .mobileconfig: SCEP identity + MDM payload -> nanomdm.
# URLs use idp.test (mapped to the NAT gateway in the guest's /etc/hosts by provision),
# so the MDM server's TLS cert (CN=idp.test, signed by the trusted test CA) validates.
generate_enrollment_profile() {
  # The MDM payload's IdentityCertificateUUID must equal the SCEP payload's PayloadUUID
  # (Apple resolves the client identity by UUID, not by PayloadIdentifier), so mint one
  # UUID and use it for both — otherwise the MDM connection has no client cert to present.
  local out="enroll.mobileconfig" topic scep_uuid; topic="$(push_topic)"; scep_uuid="$(uuidgen)"
  cat > "$out" <<ENROLL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>${EXT_BUNDLE_ID}.enroll</string>
  <key>PayloadUUID</key><string>$(uuidgen)</string>
  <key>PayloadDisplayName</key><string>Weblogin PSSO Test MDM Enrollment</string>
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.scep</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${EXT_BUNDLE_ID}.enroll.scep</string>
      <key>PayloadUUID</key><string>${scep_uuid}</string>
      <key>PayloadContent</key><dict>
        <key>URL</key><string>http://${IDP_HOST}:8080/scep</string>
        <key>Challenge</key><string>testchallenge</string>
        <key>Key Usage</key><integer>5</integer>
        <key>Keysize</key><integer>2048</integer>
        <key>Subject</key><array><array><array><string>CN</string><string>Weblogin PSSO Test Device</string></array></array></array>
      </dict>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.mdm</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${EXT_BUNDLE_ID}.enroll.mdm</string>
      <key>PayloadUUID</key><string>$(uuidgen)</string>
      <key>IdentityCertificateUUID</key><string>${scep_uuid}</string>
      <key>Topic</key><string>${topic}</string>
      <!-- nanomdm serves check-in AND commands on one combined endpoint (/mdm); it has no
           separate /checkin route, so both URLs must point at /mdm. -->
      <key>ServerURL</key><string>https://${IDP_HOST}:9000/mdm</string>
      <key>CheckInURL</key><string>https://${IDP_HOST}:9000/mdm</string>
      <key>AccessRights</key><integer>8191</integer>
      <!-- Tahoe rejects an MDM payload that doesn't declare user-channel support. -->
      <key>ServerCapabilities</key>
      <array><string>com.apple.mdm.per-user-connections</string></array>
    </dict>
  </array>
</dict></plist>
ENROLL
  echo "$out"
}

# Queue an InstallProfile command carrying the given .mobileconfig, then push so the
# guest checks in and installs it. Command plist name is derived from the profile.
push_profile() {
  local udid="$1" path="$2" b64 cmd_uuid cmd; cmd_uuid="$(uuidgen)"
  cmd="install-$(basename "${path%.mobileconfig}").plist"
  b64="$(base64 < "$path" | tr -d '\n')"
  cat > "$cmd" <<CMD
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Command</key><dict>
    <key>RequestType</key><string>InstallProfile</string>
    <key>Payload</key><data>${b64}</data>
  </dict>
  <key>CommandUUID</key><string>${cmd_uuid}</string>
</dict></plist>
CMD
  curl -sf -u "nanomdm:${NANOMDM_API_KEY}" \
    "${NANOMDM_URL}/v1/enqueue/${udid}?push=1" -T "$cmd" >/dev/null
  echo "enqueued InstallProfile ($(basename "$path")) for ${udid}"
}

# Build a PPPC (Privacy Preferences Policy Control) profile that pre-authorizes cliclick
# for Accessibility, so the Plan 3 harness can post synthetic clicks over SSH without a TCC
# prompt. A PPPC grant only takes effect when the profile is delivered via MDM (below).
# The CodeRequirement is read from the actual installed binary at bake time so it matches
# whatever cliclick provision installed (Homebrew bottles are ad-hoc signed, so the
# requirement is cdhash-based and version-specific).
# Note: only Accessibility is granted — ScreenCapture is not reliably PPPC-grantable, so
# in-guest screenshots still need a separate mechanism.
generate_pppc_profile() {
  local out="pppc-profile.mobileconfig" bin="/opt/homebrew/bin/cliclick" req
  # codesign prints the requirement as "designated => …" (sometimes "# designated => …").
  req="$(guest_exec "codesign -dr - '$bin' 2>&1" | sed -n 's/.*designated => //p')"
  [[ -n "$req" ]] || { echo "could not read cliclick code requirement" >&2; return 1; }
  cat > "$out" <<PPPC
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>${EXT_BUNDLE_ID}.pppc</string>
  <key>PayloadUUID</key><string>$(uuidgen)</string>
  <key>PayloadDisplayName</key><string>Weblogin PSSO Test Automation (cliclick)</string>
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${EXT_BUNDLE_ID}.pppc.tcc</string>
      <key>PayloadUUID</key><string>$(uuidgen)</string>
      <key>Services</key><dict>
        <key>Accessibility</key><array>
          <dict>
            <key>Identifier</key><string>${bin}</string>
            <key>IdentifierType</key><string>path</string>
            <key>CodeRequirement</key><string>${req}</string>
            <key>Authorization</key><string>Allow</string>
          </dict>
        </array>
      </dict>
    </dict>
  </array>
</dict></plist>
PPPC
  echo "$out"
}

verify_enrolled() {
  guest_exec "profiles status -type enrollment" 2>/dev/null | grep -q "User Approved"
}

# Tahoe removed CLI profile installs and gates synthetic clicks (cliclick) behind
# Accessibility TCC, which nothing can grant on a headless SSH bake. So the maintainer
# approves the staged profile once via the VNC console; this polls until it lands.
wait_for_manual_approval() {
  local deadline=$((SECONDS + MDM_APPROVE_TIMEOUT)) vnc
  vnc="$(grep -Eo 'vnc://[^[:space:]]+' /tmp/tart-golden.log 2>/dev/null | tail -1)"
  cat >&2 <<MSG

=== MANUAL STEP: approve MDM enrollment on the guest ===
Connect a VNC viewer to the running guest:
  ${vnc:-<VNC URL not found; check /tmp/tart-golden.log>}
Then: System Settings > General > Device Management > double-click
  "Weblogin PSSO Test MDM Enrollment" > Install > Install > password: ${GUEST_PASS}
Waiting up to $((MDM_APPROVE_TIMEOUT / 60)) min for user-approved enrollment...
MSG
  while (( SECONDS < deadline )); do
    verify_enrolled && { echo "MDM enrollment user-approved" >&2; return 0; }
    sleep 5
  done
  echo "timed out waiting for manual MDM approval" >&2; return 1
}

enroll_guest() {
  nanomdm_up
  local prof; prof="$(generate_enrollment_profile)"
  guest_push "$prof" "/tmp/${prof}"
  # Stage the profile (Tahoe `profiles install` is gone); it then appears under
  # System Settings > General > Device Management awaiting the manual approval below.
  guest_exec "open /tmp/${prof}"
  guest_exec "open 'x-apple.systempreferences:com.apple.preferences.configurationprofiles'"
  wait_for_manual_approval || return 1
  local udid; udid="$(guest_udid)"
  push_profile "$udid" psso-profile.mobileconfig
  # Ship the golden image with cliclick pre-authorized for unattended Plan 3 automation.
  local pppc; pppc="$(generate_pppc_profile)" || return 1
  push_profile "$udid" "$pppc"
}
