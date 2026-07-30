from __future__ import annotations
import os
from vncdotool import api


class UI:
    """Drive the loginwindow login/registration sheet over Tart's --vnc-experimental framebuffer.

    AppleScript UI scripting is restricted in loginwindow, so we drive pixels:
    screenshot, coordinate click, and type. Coordinate maps for the
    login sheet are an open item (see 'Open items carried forward').
    """

    def __init__(
        self, host: str, port: int, artifacts_dir: str, password: str | None = None, timeout: float = 60.0
    ) -> None:
        self._artifacts = artifacts_dir
        os.makedirs(self._artifacts, exist_ok=True)
        # vncdotool address form is 'host::port' (double colon = raw port, not display #).
        # timeout bounds every proxied client call (e.g. a never-matching expectScreen).
        self._client = api.connect(f"{host}::{port}", password=password, timeout=timeout)

    def screenshot(self, name: str) -> str:
        path = os.path.join(self._artifacts, name if name.endswith(".png") else f"{name}.png")
        self._client.captureScreen(path)
        return path

    def click(self, x: int, y: int) -> None:
        self._client.mouseMove(x, y)
        self._client.mousePress(1)

    def expect_screen(self, template_png: str, maxrms: float = 20) -> None:
        """Block until the framebuffer matches `template_png`, or the client timeout fires.

        vncdotool has no template *search*: the compare is anchored at top-left and
        the reference must be a same-size RGB capture (save templates from
        screenshot(), not external tools — RGBA never matches). Click via click(x, y).
        """
        self._client.expectScreen(template_png, maxrms=maxrms)

    def type(self, text: str) -> None:
        # vncdotool's client has no `type`; mirror the CLI: per-char keyPress
        # ('-' is named 'minus' in SPECIAL_KEYS_US).
        for ch in text:
            self._client.keyPress("minus" if ch == "-" else ch)

    def key(self, keyname: str) -> None:
        self._client.keyPress(keyname)

    def close(self) -> None:
        # Never call api.shutdown() between tests: the module-global Twisted reactor
        # is not restartable and a later connect() would hang.
        self._client.disconnect()
