from __future__ import annotations
from typing import Any
import requests


def fault_payload(kind: str, times: int = 1) -> dict[str, Any]:
    """Build the JSON body for POST /control/fault. `kind` matches Plan-1 FaultKind values."""
    return {"type": kind, "times": times}


class RequestLog:
    """Pure read-model over GET /control/requests entries — for scenario assertions."""

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self.entries = entries

    def paths(self) -> list[str]:
        return [e["path"] for e in self.entries]

    def count(self, path: str, method: str | None = None) -> int:
        return sum(
            1
            for e in self.entries
            if e["path"] == path and (method is None or e["method"] == method)
        )

    def bodies_for(self, path: str) -> list[str]:
        return [e.get("body", "") for e in self.entries if e["path"] == path]

    def nonce_requested(self) -> bool:
        return "/psso/nonce" in self.paths()


class IdpControl:
    """Live client for the Plan-1 mock-idp /control API (TLS via the test CA)."""

    def __init__(self, base_url: str, ca_cert: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._verify = ca_cert
        self._timeout = timeout

    def reset(self) -> None:
        r = requests.post(f"{self.base_url}/control/reset", verify=self._verify, timeout=self._timeout)
        r.raise_for_status()

    def arm(self, kind: str, times: int = 1) -> None:
        r = requests.post(
            f"{self.base_url}/control/fault",
            json=fault_payload(kind, times),
            verify=self._verify,
            timeout=self._timeout,
        )
        r.raise_for_status()

    def request_log(self) -> RequestLog:
        r = requests.get(f"{self.base_url}/control/requests", verify=self._verify, timeout=self._timeout)
        r.raise_for_status()
        return RequestLog(r.json())
