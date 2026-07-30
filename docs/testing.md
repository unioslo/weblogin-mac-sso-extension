# VM-based PSSO testing

Setup guide for testing the Platform SSO (PSSO) extension against a real macOS
Extensible SSO stack, using a prebaked "golden" Tart VM image instead of
provisioning MDM enrollment on every test run.

## 1. Overview

The golden image is a reusable, **UAMDM-enrolled** macOS Tart VM with the
Weblogin PSSO configuration profile already installed and the test harness's
disposable CA already trusted. A maintainer bakes it occasionally; everyone
else (and later CI) just clones it. Per-test VMs boot
already enrolled, with the extension's managed config in place, so a test run
never touches MDM, APNs, or enrollment UI.

See `testing/golden/README.md` for the full pipeline (the two seams that make
a clone "just work", and what's out of scope) and `testing/idp/README.md` for
the mock IdP / Keycloak stack the extension talks to.

## 2. Prerequisites

- Apple Silicon Mac (Tart requires Virtualization.framework).
- `tart` (`brew install cirruslabs/cli/tart`), `docker`, `sshpass`.
- Plan 1's test CA: run `testing/idp/gen-test-ca.sh` so `testing/idp/certs/ca.crt`
  exists.
- The **gated one-time APNs push certificate** in
  `testing/golden/nanomdm/secrets/push.pem` + `push.key` — only needed to bake
  the golden image, not to consume it.
- A **signed test build of the extension**. The golden image bakes in a real
  `.mobileconfig` referencing a specific code-signing team; whichever build you
  install must be signed by the team you put in `.env`'s `TEAM_ID` (see §6–7)
  or the extension won't load.

## 3. The APNs push certificate

The disposable nanomdm needs one Apple **MDM push certificate** (`push.pem` +
its private key `push.key`, in `testing/golden/nanomdm/secrets/`) to complete
UAMDM enrollment during the bake: nanomdm derives the enrollment profile's
`Topic` from this cert and uses it to send the wake-up push that makes the VM
fetch the `InstallProfile` command. It is a **bake-only** input — per-test
clones never push over APNs (§8), and the profile's `AuthenticationMethod` is
`Password`.

An APNs MDM push certificate is the same kind of certificate every Apple MDM
uses to wake managed devices — it is issued by the **Apple Push Certificates
Portal** (<https://identity.apple.com>) and bound to a *topic*, not to any one
server. So there are two ways to obtain the `push.pem` / `push.key` pair.

### Option A — reuse the push cert your org's MDM already has (recommended)

If your organization already operates an Apple MDM (Jamf, Kandji, Mosyle,
Fleet, Intune, a MicroMDM/nanomdm deployment, …), it already holds a push
certificate of exactly this kind. Reusing it is the pragmatic choice for a
disposable bake:

- Copy the MDM's APNs **certificate *and* its matching private key** into
  `testing/golden/nanomdm/secrets/` as `push.pem` and `push.key`. You need both
  halves — the key is the one generated for the CSR Apple signed, and most MDMs
  cannot hand it back after the fact, so export it wherever it was created.
- nanomdm auto-derives the `Topic` from the cert, so the baked enrollment
  profile simply carries that cert's topic. That's fine.
- **No cross-talk with your production fleet.** MDM pushes are addressed per
  device (via the push-magic token each device sends in its `TokenUpdate`), so
  a bake push only wakes the test VM that checked in to nanomdm — it can never
  reach a production device just because they share a topic.
- The only shared thing is the certificate, hence its **renewal fate**:
  renewing or revoking it in one place affects the other. Acceptable for a
  disposable bake — just don't point production renewal tooling at these copies.

### Option B — mint a dedicated cert

Prefer this only if you'd rather keep test infrastructure from touching
production signing material. The Portal will only accept a CSR that has been
signed by an Apple-approved MDM **vendor** certificate, so unless you are an
approved vendor yourself you need some MDM tool to sign the CSR for you:

1. Use your MDM's "generate/renew APNs certificate" workflow (e.g.
   `fleetctl generate mdm-apple`, MicroMDM's `mdmctl`, or your vendor's
   equivalent) to produce a **vendor-signed CSR** and keep the **private key**
   it generates.
2. Upload the signed CSR to the Apple Push Certificates Portal
   (<https://identity.apple.com>), signed in with the Apple ID that should own
   the cert, and download the issued `.pem`.
3. Place the downloaded `.pem` as `secrets/push.pem` and the private key from
   step 1 as `secrets/push.key`.

Either way both files are **gitignored** (`testing/golden/.gitignore`); only
`secrets/.gitkeep` is tracked. Never commit the cert or key.

## 4. Creating the golden image

Maintainer-run, occasional — not part of the per-test loop.

```bash
./golden.sh build --dry-run     # preview the 10-step plan, no side effects
./golden.sh build               # full bake
```

The bake: pull the base image, boot it headless, wait for SSH, provision it
(trust the test CA, point `idp.test` at the host), enroll it into a disposable
local nanomdm via UAMDM, push the PSSO profile as an `InstallProfile` command,
shut the VM down, and `tart push` the result. See `golden.sh`'s own header
comment and `testing/golden/README.md` for the exact step list.

## 5. Pushing to ghcr.io

`golden.sh build` pushes automatically at the end of a full bake, to
`${GOLDEN_REMOTE}` = `ghcr.io/<org>/weblogin-psso-test-vm:<macos-ver>` (from
`ORG` and `MACOS_VER` in `.env`). You need to be authenticated to GHCR
first with a GitHub PAT that has `write:packages`.

`tart login` takes the password on stdin (confirmed via `tart login --help`;
there is no `--password` flag):

```bash
# With a GitHub PAT (needs write:packages):
echo "$PAT" | tart login ghcr.io --username <github-user> --password-stdin

# Or reuse your gh CLI session instead of minting a PAT (needs the
# read:packages/write:packages scopes — see `gh auth status`, and
# `gh auth refresh -h github.com -s read:packages,write:packages` if missing):
gh auth token | tart login ghcr.io --username <github-user> --password-stdin
```

Once pushed, make the package readable by consumers: either set it **public**
in the GHCR package settings, or grant the org's members **read** access. With
that in place, consumers only ever run:

```bash
tart pull ghcr.io/<org>/weblogin-psso-test-vm:<macos-ver>
```

## 6. Configuring TEAM_ID / ClientID / Issuer / Audience

Copy `testing/golden/.env.example` to `testing/golden/.env` (gitignored) before
baking:

```bash
cp testing/golden/.env.example testing/golden/.env
```

Four keys in `testing/golden/.env` land in the `com.apple.extensiblesso`
payload of the generated `.mobileconfig` (see
`testing/golden/generate-psso-profile.sh`), under the extension's bundle id
(`EXT_BUNDLE_ID` — default `no.uio.WebloginSSO.ssoe`; forks override it in
their `.env`).

| Key | What it is | Where the value comes from |
|---|---|---|
| `TEAM_ID` | Apple Developer Team ID that code-signed the extension binary being installed. Becomes the profile's `TeamIdentifier`. | `SIGNING_TEAM` in `Config/Deployment.xcconfig`, or the deployer's `Config/Local.xcconfig` override — must match whichever build you actually install in the VM. |
| `PSSO_CLIENT_ID` | OAuth/OIDC client id the extension presents to the IdP. | The IdP's client registration — for Plan 1's Keycloak realm, `psso-client` (`testing/idp/keycloak/realm-export.json`). The mock IdP doesn't validate `ClientID` at all, so any value works against it. |
| `PSSO_ISSUER` | Expected `iss` claim on minted ID tokens. | The IdP. Mock IdP default is `https://idp.test/realms/test` (`IDP_ISSUER` env var, default in `testing/idp/mock_idp/__main__.py`); Keycloak's real issuer is `https://idp.test:8444/realms/test`. |
| `PSSO_AUDIENCE` | Expected `aud` claim on minted ID tokens. | The IdP. Mock IdP default is `psso-aud` (`IDP_AUDIENCE` env var, same file); Keycloak's realm export has no explicit audience mapper configured, so confirm what `aud` it actually issues before using it as the expected value. |
| `PSSO_BASE_URL` | Redirect/base URL the extension calls (`/psso/nonce`, `/psso/token`, etc., appended to this). | **Its hostname must be the extension's `SSO_HOST`** (its `authsrv` associated domain — e.g. `weblogin2.uio.no`): macOS refuses to activate the extension for URLs on any other host, MDM profile or not. swcd validates the domain against the production host's AASA via Apple's CDN; the guest's `/etc/hosts` remaps the host to the mock IdP, which also listens on 443 (standard port only). |

`.env.example` ships upstream defaults for `TEAM_ID`/`EXT_BUNDLE_ID`/`APP_GROUP_ID`
and the mock IdP's defaults for `PSSO_CLIENT_ID`/`PSSO_ISSUER`/`PSSO_AUDIENCE` —
override in your copied `.env` for your deployment (see the comment in
`.env.example`) or for a real production bake against a different IdP.

### Does every organization need its own TEAM_ID?

**No.** `TEAM_ID` is not per-MDM-tenant configuration — it is the signing team
of the specific extension binary being installed in the VM. The macOS
ExtensibleSSO subsystem checks that `ExtensionIdentifier`
(`no.uio.WebloginSSO.ssoe`) is actually code-signed by
`TeamIdentifier` in the profile; a mismatch means the extension silently fails
to load (no crash, no visible error — it just never registers).

Two cases:

- **Org deploys a binary signed by someone else** (e.g. an upstream release) →
  the profile must carry *that* signing team.
- **Org builds and signs its own copy** (overriding `SIGNING_TEAM` in its own
  `Config/Local.xcconfig`) → the profile must carry *that org's* team instead.

The rule is simple: `TEAM_ID` in `.env` must always equal the `SIGNING_TEAM`
of the exact build baked into the VM. Nothing else about the `.mobileconfig`
needs to vary by org for this reason.

By contrast, `PSSO_CLIENT_ID` / `PSSO_ISSUER` / `PSSO_AUDIENCE` genuinely are
per-IdP / per-deployment — they describe which OIDC client and issuer the
extension is authenticating against, which is an IdP-side concern, not a
code-signing one.

## 7. Verifying

```bash
cd testing/idp && docker compose up -d mock-idp   # host-side mock IdP, if not already up
cd - && ./golden.sh verify
```

`golden.sh verify` clones the golden image fresh and asserts:

1. user-approved MDM enrollment (`profiles status -type enrollment`),
2. the PSSO payload is present as a device profile (`sudo profiles list` —
   MDM-delivered profiles are device-level and invisible to the user-level
   `profiles list`),
3. the managed `BaseURL` preference exists under
   `/Library/Managed Preferences/<bundle-id>.plist` (the path MDM-managed
   prefs land in; plain `defaults read <domain>` does not consult it), names
   the SSO host, and (3b) carries real values, not `REPLACE_WITH_*`
   placeholders,
4. the test CA is trusted and the mock IdP is reachable over the Tart NAT
   gateway, asserted via `security verify-cert` (SecTrust — what the extension
   actually uses). `curl` is the wrong instrument here: both of Tahoe's curl
   backends ignore System-keychain trust for custom CAs. Note SecTrust also
   rejects leaf certs that are non-compliant with Apple's TLS policy (≤ 398-day
   validity, serverAuth EKU) even when the CA is trusted — `gen-test-ca.sh`
   and `gen-mdm-certs.sh` both mint compliant leaves for this reason,
5. the SSO host is remapped to the NAT gateway in the guest's `/etc/hosts`
   (macOS only activates the extension for URLs on its `authsrv` associated
   domain — see §6),
6. Spotlight indexing is enabled (with it off, LaunchServices never discovers
   an installed `ssoe.appex` and AppSSOAgent refuses to activate it).

Every check prints `PASS:`/`FAIL:` and the script exits non-zero if any check
failed — the exit status is the real signal.

## 8. Open items / caveats

- `BASE_IMAGE` in `.env` is pinned to `:latest`; pin to a specific digest
  before treating a baked image as reproducible.
- `PSSO_CLIENT_ID` / `PSSO_ISSUER` / `PSSO_AUDIENCE` in `.env.example` default
  to the mock IdP — fill in real values from production PSSO configuration in
  your `.env` before using the golden image for anything beyond a mock-IdP
  smoke test.
- nanomdm / SCEP image tags and CLI flags in `testing/golden/nanomdm/compose.yaml`
  are plausible but unconfirmed against current upstream docs.
- UAMDM approval during a bake is a manual VNC step (System Settings > Device
  Management); `verify_enrolled()` in the enrollment library is the
  correctness gate.
- Out of scope entirely: Secure-Enclave-backed key registration (no functional
  guest SE), ADE/DEP enrollment, and per-test APNs pushes. The profile's
  `AuthenticationMethod` is `Password` for this reason.
