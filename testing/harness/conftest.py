from __future__ import annotations
import datetime as dt
import os
import re
import signal
import subprocess
import time
import uuid
import warnings

import pytest
import requests

from harness.drivers.idp import IdpControl
from harness.drivers.guest import Guest
from harness.drivers.ui import UI

# --- Environment contract (set by test-pkg.sh; sane local defaults otherwise) ---
HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN_IMAGE = os.environ.get("PSSO_GOLDEN_IMAGE", "ghcr.io/unioslo/weblogin-psso-test-vm:tahoe-26")
IDP_BASE_URL = os.environ.get("PSSO_IDP_BASE_URL", "https://idp.test:8443")
IDP_CA_CERT = os.environ.get("PSSO_IDP_CA_CERT", os.path.join(HERE, "..", "idp", "certs", "ca.crt"))
SSH_USER = os.environ.get("PSSO_SSH_USER", "admin")
SSH_PASS = os.environ.get("PSSO_SSH_PASS", "admin")
APP_GROUP = os.environ.get("PSSO_APP_GROUP", "group.no.uio.weblogin")
EXT_BUNDLE_ID = os.environ.get("PSSO_EXT_BUNDLE_ID", "no.uio.WebloginSSO.ssoe")
PKG_PATH = os.environ.get("PSSO_PKG", "")
ARTIFACTS_ROOT = os.environ.get("PSSO_ARTIFACTS", os.path.join(HERE, "artifacts"))


def _needs(path_or_bin: str, kind: str) -> None:
    if kind == "bin" and subprocess.run(["which", path_or_bin], capture_output=True).returncode != 0:
        pytest.skip(f"required binary {path_or_bin!r} not on PATH (Plans 1 & 2 host requirement)")
    if kind == "file" and not os.path.exists(path_or_bin):
        pytest.skip(f"required file {path_or_bin!r} missing (produced by Plans 1 & 2)")


@pytest.fixture(scope="session")
def artifacts_root() -> str:
    # test-pkg.sh passes an already-stamped per-run dir via PSSO_ARTIFACTS;
    # only bare pytest runs need a fresh run-<stamp> here.
    if "PSSO_ARTIFACTS" in os.environ:
        root = ARTIFACTS_ROOT
    else:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        root = os.path.join(ARTIFACTS_ROOT, f"run-{stamp}")
    os.makedirs(root, exist_ok=True)
    return root


@pytest.fixture
def artifacts(artifacts_root, request) -> str:
    """Per-scenario artifacts subdir named after the test node."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.name)
    d = os.path.join(artifacts_root, safe)
    os.makedirs(d, exist_ok=True)
    return d


@pytest.fixture
def idp() -> IdpControl:
    """Clean mock-IdP control client; resets faults + recorded requests before AND after."""
    _needs(IDP_CA_CERT, "file")
    control = IdpControl(base_url=IDP_BASE_URL, ca_cert=IDP_CA_CERT)
    try:
        control.reset()
    except requests.ConnectionError:
        pytest.skip(f"mock IdP not reachable at {IDP_BASE_URL} (is the testing/idp stack up?)")
    yield control
    control.reset()


@pytest.fixture
def vm(artifacts_root) -> dict:
    """Clone the golden image, boot it, yield name/ip/vnc_url, then delete the clone."""
    _needs("tart", "bin")
    name = f"run-{uuid.uuid4().hex[:8]}"
    subprocess.run(["tart", "clone", GOLDEN_IMAGE, name], check=True)
    # tart run output goes to a log file: readline() on a pipe cannot honor a
    # deadline, and an undrained pipe would eventually block the VM process.
    # The log doubles as a per-run debugging artifact.
    log_path = os.path.join(artifacts_root, f"tart-run-{name}.log")
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            ["tart", "run", name, "--vnc-experimental", "--no-graphics"],
            stdout=log, stderr=subprocess.STDOUT, text=True,
        )
        try:
            vnc_url = _wait_for_vnc_url(proc, log_path)
            ip = _wait_for_ip(name)
            yield {"name": name, "ip": ip, "vnc_url": vnc_url}
        finally:
            # tart traps SIGINT (not SIGTERM) for graceful stop; wait for the run
            # process to release the VM before deleting, else delete fails and
            # leaks a ~50GB clone.
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            subprocess.run(["tart", "stop", name], capture_output=True)
            if subprocess.run(["tart", "delete", name], capture_output=True).returncode != 0:
                warnings.warn(f"tart delete {name} failed — clone may be leaked")


def _wait_for_vnc_url(proc, log_path: str, timeout: float = 60.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with open(log_path) as fh:
            for line in fh:
                if "vnc://" in line:
                    return line.strip().split("vnc://", 1)[1]
        if proc.poll() is not None:
            raise RuntimeError(f"tart run exited before printing a VNC URL (see {log_path})")
        time.sleep(0.5)
    raise TimeoutError(f"no VNC URL from tart run within {timeout}s (see {log_path})")


def _wait_for_ip(name: str, timeout: float = 120.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(["tart", "ip", name], capture_output=True, text=True)
        ip = r.stdout.strip()
        if r.returncode == 0 and ip:
            return ip
        time.sleep(3)
    raise TimeoutError(f"no IP for {name} within {timeout}s")


@pytest.fixture
def guest(vm) -> Guest:
    _needs("sshpass", "bin")
    g = Guest(ip=vm["ip"], user=SSH_USER, password=SSH_PASS, app_group=APP_GROUP)
    _wait_for_ssh(g)
    return g


def _wait_for_ssh(g: Guest, timeout: float = 300.0) -> None:
    """`tart ip` proves DHCP, not sshd; on macOS boots the IP appears first."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if g.run("true", timeout=15.0).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(5)
    raise TimeoutError(f"guest SSH at {g.ip} not ready within {timeout}s")


@pytest.fixture
def ui(vm, artifacts) -> UI:
    # vnc_url form: [:password@]host:port — tart emits password-only userinfo.
    creds, _, hostport = vm["vnc_url"].rpartition("@")
    host, _, port = hostport.partition(":")
    password = creds.partition(":")[2] or creds or None
    client = UI(host=host, port=int(port), artifacts_dir=artifacts, password=password)
    yield client
    client.close()


_LSREGISTER = (
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
    "LaunchServices.framework/Support/lsregister"
)


@pytest.fixture
def installed_pkg(guest) -> str:
    """Copy the built pkg into the guest, install it, and register the appex.

    `installer` alone is not enough: LaunchServices must discover ssoe.appex
    (lsregister of the app + Spotlight, enabled in the golden image) and
    AppSSOAgent must reload before it will activate the extension.
    """
    _needs(PKG_PATH, "file")
    remote = "/tmp/weblogin-sso.pkg"
    guest.copy_in(PKG_PATH, remote)
    res = guest.install_pkg(remote)
    assert res.returncode == 0, f"installer failed: {res.stderr}"
    guest.run(f"{_LSREGISTER} -f '/Applications/Weblogin SSO.app'")
    deadline = time.time() + 60
    while time.time() < deadline:
        if EXT_BUNDLE_ID in guest.run("pluginkit -m 2>/dev/null").stdout:
            break
        time.sleep(3)
    else:
        pytest.fail(f"{EXT_BUNDLE_ID} never appeared in pluginkit after install")
    # AppSSOAgent only activates the extension once swcd has validated its authsrv
    # associated domain (async AASA fetch via Apple's CDN after app registration) —
    # a fresh clone starts with an empty swcd DB, so wait for approval.
    app_id = EXT_BUNDLE_ID.rsplit(".", 1)[0]
    deadline = time.time() + 120
    while time.time() < deadline:
        swc = guest.run("sudo swcutil show 2>/dev/null").stdout
        block = [b for b in swc.split("-" * 10) if f"{app_id}\n" in b and "authsrv" in b]
        if block and "approved" in block[0]:
            break
        time.sleep(5)
    else:
        pytest.fail(f"authsrv associated domain never approved for {app_id} (swcd)")
    guest.run("killall AppSSOAgent 2>/dev/null; true")
    return remote


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """After the run, render the scenario matrix from the JUnit XML we produced."""
    from harness.matrix import parse_junit, render_matrix

    # --junitxml is the authoritative source; PSSO_JUNIT is a fallback only. No
    # default filename: a stale gitignored junit.xml must not silently regenerate
    # the matrix on runs that produced no JUnit output.
    junit = session.config.getoption("xmlpath") or os.environ.get("PSSO_JUNIT")
    if not junit or not os.path.exists(junit):
        return
    out = os.environ.get("PSSO_MATRIX", "scenario-matrix.md")
    with open(junit, "r", encoding="utf-8") as fh:
        results = parse_junit(fh.read())
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# PSSO scenario matrix\n\n")
        fh.write(render_matrix(results))
