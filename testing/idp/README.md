# Test IdP stack

Two IdPs the PSSO test harness points the extension at:

- **mock-idp** (`https://idp.test:8443`) — fault-injectable fake. Primary tool
  for provoking bug scenarios. Control API under `/control`.
- **keycloak** (`https://idp.test:8444`) — real Keycloak + seeded `test` realm
  for happy-path fidelity.

Both serve TLS signed by a **disposable test CA** (`certs/ca.crt`). This CA is
test-only and must never be trusted on a real machine.

## Quick start

    ./gen-test-ca.sh                 # once, creates certs/
    docker compose up -d --build     # both IdPs, bound on 0.0.0.0

Reach them from another host (e.g. a guest VM) by mapping `idp.test` to this
host's IP in the guest's /etc/hosts and trusting certs/ca.crt in the guest.

## Fault injection (mock-idp)

    # arm a fault for the next matching request
    curl --cacert certs/ca.crt -X POST https://idp.test:8443/control/fault \
      -d '{"type":"token_500","times":1}' -H 'content-type: application/json'

    # read what the extension sent
    curl --cacert certs/ca.crt https://idp.test:8443/control/requests

    # clear faults + recorded requests between tests
    curl --cacert certs/ca.crt -X POST https://idp.test:8443/control/reset

Fault types: `bad_nonce`, `token_500`, `timeout`, `expired_id_token`,
`malformed_id_token`, `token_bad_json`.

## Endpoint contract

Mirrors what the extension calls (appended to the profile `BaseURL`):
`/psso/nonce`, `/psso/token`, `/protocol/openid-connect/certs`, `/psso/enroll`,
`/psso/userenroll`, `/protocol/openid-connect/{auth,token}`.

## Run the unit tests

    python3.12 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
    pytest
