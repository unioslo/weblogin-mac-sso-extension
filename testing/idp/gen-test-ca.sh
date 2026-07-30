#!/usr/bin/env bash
# Generate a DISPOSABLE, TEST-ONLY root CA and an idp.test server cert.
# The CA is deliberately low-value and is trusted only inside test VMs.
# Never trust this CA on a real machine.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
cd certs

# --force regenerates everything. Deleting idp.test.crt alone re-mints just the leaf
# against the existing CA (so machines already trusting the CA stay valid).
[[ "${1:-}" != "--force" ]] || rm -f ca.crt ca.key idp.test.crt idp.test.key

if [[ -f ca.crt ]]; then
  echo "certs/ca.crt already exists; keeping CA (pass --force to regenerate all)" >&2
else
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca.key -out ca.crt \
    -subj "/CN=Weblogin PSSO Test Root CA"
fi

# The leaf's SANs must include the deployment's SSO host: the guest remaps that
# host to the mock IdP (see testing/golden/.env.example, PSSO_BASE_URL) and the
# extension connects to it by that name. Override for your deployment.
SSO_HOST="${SSO_HOST:-weblogin2.uio.no}"

if [[ -f idp.test.crt ]]; then
  echo "certs/idp.test.crt already exists; delete it to re-mint" >&2
else
  openssl req -newkey rsa:2048 -nodes \
    -keyout idp.test.key -out idp.test.csr \
    -subj "/CN=idp.test"
  # Apple's TLS server-cert trust policy (iOS 13 / macOS 10.15+) rejects a leaf that
  # lacks a serverAuth EKU or sane basicConstraints, and caps validity at 398 days for
  # certs issued after 2020-09-01 — a non-compliant leaf fails SecTrust in the guest
  # even with the CA trusted. Mint a compliant leaf (same shape as nanomdm's, see
  # ../golden/nanomdm/gen-mdm-certs.sh).
  openssl x509 -req -in idp.test.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 397 -out idp.test.crt \
    -extfile <(printf "%s\n" \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth" \
      "subjectAltName=DNS:idp.test,DNS:${SSO_HOST},DNS:localhost,IP:127.0.0.1")
  rm -f idp.test.csr
fi

echo "Wrote certs/ca.crt, certs/idp.test.crt, certs/idp.test.key"
