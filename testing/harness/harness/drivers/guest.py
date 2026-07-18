from __future__ import annotations
import subprocess
import time
from dataclasses import dataclass
from shlex import quote

DEFAULT_APP_GROUP = "group.no.uio.weblogin"

# Fresh clones intermittently reject the correct password for ~60s after boot
# (macOS directory services still settling), interleaved with successes, so
# every SSH/scp operation retries on that signature until a deadline.
_AUTH_FLAKE_DEADLINE = 120.0
_AUTH_FLAKE_INTERVAL = 3.0


def _is_transient_auth_failure(returncode: int, stderr: str) -> bool:
    return returncode == 255 and "Permission denied" in (stderr or "")


def _retry_auth_flake(
    attempt,
    deadline_s: float = _AUTH_FLAKE_DEADLINE,
    interval_s: float = _AUTH_FLAKE_INTERVAL,
    *,
    sleep=time.sleep,
    monotonic=time.monotonic,
):
    """Call attempt() -> RunResult, retrying while it hits the auth flake."""
    deadline = monotonic() + deadline_s
    while True:
        res = attempt()
        if not _is_transient_auth_failure(res.returncode, res.stderr):
            return res
        if monotonic() >= deadline:
            return res
        sleep(interval_s)

# Password-only auth, mirroring testing/golden/lib/guest.sh: the golden image
# ships the cirruslabs admin/admin login and no baked SSH key; skip the agent
# (else e.g. the 1Password agent prompts on every call) and any on-disk keys.
_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no",
    "-o", "IdentityAgent=none",
    "-o", "ConnectTimeout=10",
]


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


class Guest:
    """SSH into the cloned macOS VM to install the pkg and observe state/logs."""

    def __init__(
        self,
        ip: str,
        user: str = "admin",
        password: str = "admin",
        app_group: str = DEFAULT_APP_GROUP,
    ) -> None:
        self.ip = ip
        self._user = user
        self._password = password
        self.app_group = app_group

    def _ssh_base(self) -> list[str]:
        return [
            "sshpass", "-p", self._password,
            "ssh", *_SSH_OPTS,
            f"{self._user}@{self.ip}",
        ]

    def run(self, command: str, timeout: float = 120.0) -> RunResult:
        def attempt() -> RunResult:
            p = subprocess.run(
                self._ssh_base() + [command],
                capture_output=True, text=True, timeout=timeout,
            )
            return RunResult(p.returncode, p.stdout, p.stderr)

        return _retry_auth_flake(attempt)

    def copy_in(self, local_path: str, remote_path: str, timeout: float = 300.0) -> None:
        cmd = [
            "sshpass", "-p", self._password,
            "scp", *_SSH_OPTS,
            local_path, f"{self._user}@{self.ip}:{quote(remote_path)}",
        ]

        def attempt() -> RunResult:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return RunResult(p.returncode, p.stdout, p.stderr)

        res = _retry_auth_flake(attempt)
        if res.returncode != 0:
            raise subprocess.CalledProcessError(
                res.returncode, cmd, output=res.stdout, stderr=res.stderr
            )

    def install_pkg(self, remote_pkg: str) -> RunResult:
        return self.run(f"sudo installer -pkg {quote(remote_pkg)} -target /", timeout=300.0)

    def platform_state(self) -> str:
        """`app-sso platform -s` — device/user registration + broker state."""
        return self.run("app-sso platform -s").stdout

    def profiles_list(self) -> str:
        # System/MDM profiles are only visible to root over SSH.
        return self.run("sudo profiles list -all").stdout

    def ext_logs(self, last: str = "5m") -> str:
        """`webloginlog:` extension log lines as `log show --style ndjson`.

        sudo is required — non-root `log show` silently returns nothing for other
        processes' entries — and --info/--debug because most extension lines are
        logger.info/.debug level.
        """
        cmd = (
            "sudo log show --style ndjson --info --debug "
            "--predicate 'eventMessage CONTAINS \"webloginlog:\"' "
            f"--last {last}"
        )
        return self.run(cmd, timeout=120.0).stdout

    # Caveat (unverified): the `defaults` CLI is not group-entitled, so
    # `defaults read <group-id>` targets ~/Library/Preferences/<group-id>.plist, which may
    # differ from the group-container plist the extension's UserDefaults(suiteName:) uses.
    # If so, switch to the container plist path (+ `killall cfprefsd`).
    def read_app_group_defaults(self, key: str) -> str:
        """Read a key from the extension's app-group defaults suite."""
        return self.run(f"defaults read {quote(self.app_group)} {quote(key)} 2>&1 || true").stdout.strip()

    def clear_registration_state(self) -> None:
        """Delete the app-group defaults domain to simulate leftover/corrupt state cleanup."""
        self.run(f"defaults delete {quote(self.app_group)} 2>/dev/null || true")

    def corrupt_app_group(self) -> None:
        """Write a bogus value so the extension reads corrupt app-group state."""
        self.run(f"defaults write {quote(self.app_group)} disable_sso -string not-a-bool")
