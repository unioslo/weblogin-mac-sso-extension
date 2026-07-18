from __future__ import annotations
from enum import Enum


class FaultKind(str, Enum):
    BAD_NONCE = "bad_nonce"            # /psso/nonce returns a nonce that won't match
    TOKEN_500 = "token_500"           # /psso/token returns HTTP 500
    TIMEOUT = "timeout"               # endpoint sleeps past client timeout
    EXPIRED_ID_TOKEN = "expired_id_token"   # id_token exp in the past
    MALFORMED_ID_TOKEN = "malformed_id_token"  # id_token signature garbage
    TOKEN_BAD_JSON = "token_bad_json"       # /psso/token returns non-JSON body


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
