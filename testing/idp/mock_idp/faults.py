from __future__ import annotations
from enum import Enum


class FaultKind(str, Enum):
    BAD_NONCE = "bad_nonce"            # /psso/nonce returns a nonce that won't match
    TOKEN_500 = "token_500"           # /psso/token returns HTTP 500
    TIMEOUT = "timeout"               # endpoint sleeps past client timeout
    EXPIRED_ID_TOKEN = "expired_id_token"   # id_token exp in the past
    MALFORMED_ID_TOKEN = "malformed_id_token"  # id_token signature garbage
    TOKEN_BAD_JSON = "token_bad_json"       # /psso/token returns non-JSON body
    NONCE_500 = "nonce_500"                     # /psso/nonce returns HTTP 500
    STEP_UP = "step_up"                         # auth serves the step-up page even without prompt=login
    STEP_UP_IFRAME = "step_up_iframe"           # step-up page embeds a foreign-origin iframe that also asks
    STEP_UP_NAVIGATE = "step_up_navigate"       # step-up page asks, then navigates to a foreign origin; arms NONCE_SLOW once
    NONCE_SLOW = "nonce_slow"                   # /psso/nonce answers after NONCE_SLOW_SECONDS
    STEP_UP_NONCE_500 = "step_up_nonce_500"     # serves the step-up page and arms NONCE_500 once for its nonce fetch
    STEP_UP_FORGED_TOKEN = "step_up_forged_token"       # step-up page whose token is signed by a key not in the JWKS
    STEP_UP_WRONG_CHALLENGE = "step_up_wrong_challenge" # step-up page whose token carries another reauth_challenge
    STEP_UP_EXPIRED_TOKEN = "step_up_expired_token"     # step-up page whose token has expired


class FaultRegistry:
    """Arms faults to fire N times, then auto-disarm. In-memory, per-process."""

    def __init__(self) -> None:
        self._counts: dict[FaultKind, int] = {}

    def arm(self, kind: FaultKind, times: int = 1) -> None:
        kind = FaultKind(kind)  # raises ValueError on unknown
        self._counts[kind] = self._counts.get(kind, 0) + times

    def consume(self, kind: FaultKind) -> bool:
        """Return True if a fault of this kind is armed, decrementing the count."""
        remaining = self._counts.get(kind, 0)
        if remaining <= 0:
            return False
        self._counts[kind] = remaining - 1
        return True

    def reset(self) -> None:
        self._counts.clear()
