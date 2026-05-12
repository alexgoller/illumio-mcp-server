"""Browser onboarding page for per-user PCE credentials.

GET  /setup  -> HTML form
POST /setup  -> Process form, write to keystore, show success page

Auth is handled by the JWTAuthMiddleware mounted at the app level, so by the
time these handlers run, request.state.user is populated.
"""
from __future__ import annotations

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from ..pce import PCECredentials


_FORM_HTML = """\
<!doctype html>
<html><head>
<title>Illumio MCP - Register PCE Credentials</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 540px; margin: 3em auto; padding: 0 1em; color: #222; }}
  h1 {{ font-size: 1.4em; margin-bottom: 0.2em; }}
  .meta {{ color: #666; font-size: 0.9em; margin-bottom: 2em; }}
  label {{ display: block; margin-top: 1em; font-weight: 600; }}
  input {{ width: 100%; padding: 0.5em; font-size: 1em; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }}
  button {{ margin-top: 2em; padding: 0.7em 1.5em; font-size: 1em; background: #1f6feb; color: white; border: 0; border-radius: 4px; cursor: pointer; }}
  .note {{ background: #fff3cd; padding: 1em; border-radius: 4px; font-size: 0.9em; margin-top: 1em; }}
</style>
</head><body>
<h1>Register PCE Credentials</h1>
<div class="meta">Authenticated as <code>{sub}</code> via <code>{iss}</code></div>
<form method="post" action="/setup" autocomplete="off">
  <label>PCE Host (URL)<input name="pce_host" placeholder="https://your-pce.example.com" required></label>
  <label>PCE Port<input name="pce_port" type="number" value="8443" required></label>
  <label>PCE Org ID<input name="pce_org_id" type="number" value="1" required></label>
  <label>API Key<input name="api_key" required></label>
  <label>API Secret<input name="api_secret" type="password" required></label>
  <label>Label (optional)<input name="label" placeholder="e.g. EMEA-prod"></label>
  <label><input type="checkbox" name="tls_verify" value="1" checked> Verify TLS</label>
  <button type="submit">Register</button>
</form>
<div class="note">
  Credentials are stored encrypted at rest. They will be used to authenticate
  this MCP server to PCE on your behalf. To remove them later, call the
  <code>delete-pce-credentials</code> MCP tool or visit <a href="/setup">/setup</a> again.
</div>
</body></html>
"""

_DONE_HTML = """\
<!doctype html>
<html><head><title>Illumio MCP - Registered</title>
<style>body{font-family:system-ui,sans-serif;max-width:540px;margin:3em auto;padding:0 1em;}</style>
</head><body>
<h1>PCE credentials registered</h1>
<p>You can now close this tab and use the MCP server from your client.</p>
<p><a href="/setup">Update credentials</a></p>
</body></html>
"""


def build_setup_routes(keystore) -> list[Route]:
    async def get_setup(request: Request) -> Response:
        user = getattr(request.state, "user", None)
        if user is None:
            return HTMLResponse("Unauthorized", status_code=401)
        return HTMLResponse(_FORM_HTML.format(sub=user.sub, iss=user.iss))

    async def post_setup(request: Request) -> Response:
        user = getattr(request.state, "user", None)
        if user is None:
            return HTMLResponse("Unauthorized", status_code=401)
        form = await request.form()
        try:
            creds = PCECredentials(
                host=str(form["pce_host"]),
                port=int(form["pce_port"]),
                org_id=int(form["pce_org_id"]),
                api_key=str(form["api_key"]),
                api_secret=str(form["api_secret"]),
                tls_verify=form.get("tls_verify") == "1",
            )
        except (KeyError, ValueError) as e:
            return HTMLResponse(f"Bad form: {e}", status_code=400)
        label = str(form.get("label") or "") or None
        keystore.put(sub=user.sub, iss=user.iss, creds=creds, label=label)
        return HTMLResponse(_DONE_HTML)

    return [
        Route("/setup", get_setup, methods=["GET"]),
        Route("/setup", post_setup, methods=["POST"]),
    ]
