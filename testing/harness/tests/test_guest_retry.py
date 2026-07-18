"""Retry logic for the early-boot SSH auth flake (see drivers/guest.py).

Fresh clones intermittently reject the correct password for ~60s after boot
(observed interleaved with successes), so every SSH/scp operation retries on
that signature until a deadline.
"""
from harness.drivers.guest import RunResult, _is_transient_auth_failure, _retry_auth_flake


def test_detects_auth_flake_signature():
    assert _is_transient_auth_failure(255, "Permission denied, please try again.")


def test_remote_command_failure_is_not_a_flake():
    # Exit 1 from the remote command itself must not be retried.
    assert not _is_transient_auth_failure(1, "Permission denied")


def test_transport_error_is_not_a_flake():
    assert not _is_transient_auth_failure(255, "Connection refused")


def test_success_is_not_a_flake():
    assert not _is_transient_auth_failure(0, "")


def _fake_clock(step: float):
    t = [0.0]

    def monotonic() -> float:
        return t[0]

    def sleep(s: float) -> None:
        t[0] += s

    return monotonic, sleep


def test_retries_flake_until_success():
    monotonic, sleep = _fake_clock(1.0)
    outcomes = [
        RunResult(255, "", "Permission denied, please try again."),
        RunResult(255, "", "Permission denied, please try again."),
        RunResult(0, "ok", ""),
    ]
    res = _retry_auth_flake(
        lambda: outcomes.pop(0), deadline_s=60, interval_s=1,
        sleep=sleep, monotonic=monotonic,
    )
    assert res.returncode == 0
    assert not outcomes  # all three attempts consumed


def test_gives_up_at_deadline():
    monotonic, sleep = _fake_clock(1.0)
    attempts = [0]

    def always_flaky():
        attempts[0] += 1
        return RunResult(255, "", "Permission denied, please try again.")

    res = _retry_auth_flake(
        always_flaky, deadline_s=10, interval_s=5,
        sleep=sleep, monotonic=monotonic,
    )
    assert res.returncode == 255
    assert attempts[0] == 3  # t=0, 5, 10 — then deadline reached


def test_non_flake_failure_returns_immediately():
    attempts = [0]

    def remote_failure():
        attempts[0] += 1
        return RunResult(1, "", "some real error")

    res = _retry_auth_flake(remote_failure, deadline_s=60, interval_s=1)
    assert res.returncode == 1
    assert attempts[0] == 1
