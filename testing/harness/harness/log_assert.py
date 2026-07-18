from __future__ import annotations
import json

MARKER = "webloginlog:"
SAVE_FAILURE = "Failed to save the configuration"
# `registerUser`'s password success path logs this immediately before
# completion(.success). Seeing it AFTER a save failure is the double-completion
# signature the 89c5a0a fix removed.
PASSWORD_SUCCESS_PATH = "The audience in user registration is"


def parse_webloginlog(ndjson_text: str) -> list[str]:
    """Extract `webloginlog:` eventMessages from `log show --style ndjson` output, in order.

    Records from /usr/bin/log itself are dropped: `log show` logs its own argv,
    which contains the literal predicate string, so every query would otherwise
    self-match and an empty run would falsely satisfy `expect_log`.
    """
    out: list[str] = []
    for line in ndjson_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("processImagePath", "").endswith("/log"):
            continue
        msg = rec.get("eventMessage") or ""
        if MARKER in msg:
            out.append(msg)
    return out


def count_matching(msgs: list[str], needle: str) -> int:
    return sum(1 for m in msgs if needle in m)


def assert_logged(msgs: list[str], needle: str) -> None:
    if count_matching(msgs, needle) == 0:
        raise AssertionError(f"expected a webloginlog line containing {needle!r}; got {msgs!r}")


def double_completion_after_save_failure(msgs: list[str]) -> bool:
    """True iff a save-config failure is followed by the password success-path log."""
    for i, m in enumerate(msgs):
        if SAVE_FAILURE in m:
            if any(PASSWORD_SUCCESS_PATH in later for later in msgs[i + 1 :]):
                return True
    return False
