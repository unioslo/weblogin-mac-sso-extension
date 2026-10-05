"""Session lifecycle for the testing/idp docker compose stack.

The guest VM reaches the IdP on fixed host ports baked into the golden image's
profile (443 and 8443), so ports cannot be randomized. Isolation instead comes
from a dedicated compose project name, and a stack already holding those ports
is reported rather than silently reused.
"""
from __future__ import annotations

import socket
import subprocess
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

PROJECT = "psso-harness-idp"


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


@dataclass
class ComposeStack:
    compose_dir: Path
    project: str = PROJECT
    started: list[str] = field(default_factory=list)

    def cmd(self, *args: str) -> list[str]:
        return ["docker", "compose", "--project-directory", str(self.compose_dir), "-p", self.project, *args]

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(self.cmd(*args), capture_output=True, text=True)

    def up(self, service: str, ready: Callable[[], bool], timeout: float = 120.0) -> None:
        """Build and start `service`, then poll `ready` until it returns True."""
        # Recorded before checking the result: a failed `up` can still leave a network or container.
        self.started.append(service)
        res = self._run("up", "-d", "--build", service)
        if res.returncode != 0:
            raise RuntimeError(f"docker compose up {service} failed:\n{res.stderr}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if ready():
                return
            time.sleep(1)
        raise TimeoutError(f"{service} not ready within {timeout}s\n--- logs ---\n{self.logs(service)}")

    def logs(self, service: str) -> str:
        res = self._run("logs", "--no-color", service)
        return res.stdout + res.stderr

    def down(self) -> None:
        if self.started:
            res = self._run("down", "-v")
            self.started.clear()
            if res.returncode != 0:
                warnings.warn(f"docker compose down failed for {self.project}:\n{res.stderr}")
