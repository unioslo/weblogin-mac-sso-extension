# Golden VM image pipeline

Bakes a reusable, UAMDM-enrolled macOS Tart image with the Weblogin PSSO
configuration profile installed and the disposable test CA trusted, then pushes
it to GHCR. Per-test runs (Plan 3) just `tart clone` this image — they never run
this pipeline, nanomdm, or APNs.

## Who runs what

- **Maintainer, occasionally:** `../../golden.sh build` — the full bake. Needs a
  one-time **gated APNs push certificate** in `nanomdm/secrets/` (see
  `nanomdm/.env.example`). Never runs per test.
- **Consumers (and CI later):** `tart pull ghcr.io/<org>/weblogin-psso-test-vm:<macos-ver>`.
  Nothing else.

## Prerequisites

- Apple Silicon Mac; `tart` (`brew install cirruslabs/cli/tart`), `docker`, `sshpass`.
- **Bake config:** copy `.env.example` to `.env` and override for your deployment
  (`.env.example` ships UiO's, i.e. upstream's, defaults). `.env` is gitignored —
  see [Never commit Developer ID, certificates, or secrets](../../CLAUDE.md).
- **Plan 1's test CA:** run `../idp/gen-test-ca.sh` so `../idp/certs/ca.crt` exists.
- Gated **APNs push cert**: `nanomdm/secrets/push.pem` + `push.key`.

## Bake

    ../../golden.sh build --dry-run     # preview the 10-step plan
    ../../golden.sh build               # full bake -> tart push

## Verify the result

Start Plan 1's mock IdP on the host (`cd ../idp && docker compose up -d mock-idp`),
then:

    ../../golden.sh verify          # clones the golden image, asserts:
                                    #   user-approved MDM, PSSO payload present,
                                    #   managed BaseURL pref, CA trusted + mock
                                    #   reachable over NAT

## Other commands

    ../../golden.sh start [vm-name]     # boot a built VM + nanomdm, for inspection
    ../../golden.sh stop  [vm-name]     # tear both back down
    ../../golden.sh push  [vm-name]     # push a local VM to GHCR without re-baking
    ../../golden.sh status              # show .env config, local VM, remote image state

## The seams (why a clone "just works")

1. **Test CA trusted** in the guest System keychain, so mock/Keycloak TLS
   validates. The CA is disposable and test-only — never trust it on a real Mac.
2. **`/etc/hosts`**: `idp.test` AND the SSO host (`PSSO_BASE_URL`'s hostname,
   e.g. `weblogin2.uio.no`) -> the guest's default gateway (the host
   under Tart NAT). The SSO-host mapping matters because macOS only activates
   the extension for URLs on its `authsrv` associated domain — the profile's
   `BaseURL` must use that host, remapped to the mock (which listens on 443).
3. **Spotlight indexing on** — the cirruslabs base disables it, which breaks
   LaunchServices appex discovery: an installed `ssoe.appex` never registers
   and AppSSOAgent refuses to activate it.

## Repointing the profile at Keycloak

Set `PSSO_BASE_URL` in `.env` to the Keycloak realm URL and re-run — but note
the SSO-host constraint above: the hostname must stay the extension's `authsrv`
domain, so Keycloak would need to be served at that name (guest-side remap +
cert SANs), not at `idp.test:8444`.

## Out of scope

SE-backed registration (no functional guest Secure Enclave), ADE/DEP enrollment,
and real APNs in the per-test loop. See the design spec.
