# alien-sso-jinja

Server-rendered sign-in button + QR modal for [Alien SSO](https://alien.org).
Drop-in replacement for [`@alien-id/sso-react`](https://www.npmjs.com/package/@alien-id/sso-react)
when the consuming app is Python instead of a React SPA.

Ships:

- Jinja2 templates for the **button** and the **modal** (with embedded CSS).
- A small **vanilla-JS** bundle (no React, no QR-code lib in the browser) that
  drives the modal: open → fetch `/sso/start` → render QR → poll `/sso/poll`
  → POST `/sso/finish` on success → fire `alien-sso:success` DOM event.
- Server-side SVG QR generation via `segno` (zero-deps, pure-Python).
- Framework-agnostic handlers (`SsoUi.start()`, `.poll()`, `.finish()`) plus
  thin **Flask Blueprint** and **FastAPI APIRouter** adapters.

## Install

```bash
pip install alien-sso-jinja                       # base
pip install "alien-sso-jinja[fastapi]"            # + FastAPI adapter
pip install "alien-sso-jinja[flask]"              # + Flask adapter
```

## Quick start (FastAPI + Jinja templates)

```python
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from alien_sso import AlienSsoClient, AlienSsoClientConfig
from alien_sso_jinja import SsoUi

app = FastAPI()
templates = Jinja2Templates(directory="templates")

sso = AlienSsoClient(AlienSsoClientConfig(
    sso_base_url="https://sso.alien-api.com",
    provider_address="<your-provider>",
))
ui = SsoUi(client=sso, api_base="/sso")
app.include_router(ui.fastapi_router(), prefix="/sso")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request, "index.html",
        {"sso_button": ui.render_button(), "sso_modal": ui.render_modal(), "sso_assets": ui.render_assets()},
    )
```

In your `index.html`:

```jinja
<!doctype html>
<html>
<head>{{ sso_assets | safe }}</head>
<body>
  {{ sso_button | safe }}
  {{ sso_modal | safe }}
</body>
</html>
```

## Quick start (Flask)

```python
from flask import Flask, render_template_string
from alien_sso import AlienSsoClient, AlienSsoClientConfig
from alien_sso_jinja import SsoUi

app = Flask(__name__)
ui = SsoUi(client=AlienSsoClient(AlienSsoClientConfig(...)), api_base="/sso")
app.register_blueprint(ui.flask_blueprint(url_prefix="/sso"))

@app.get("/")
def home():
    return render_template_string(
        "<!doctype html><html><head>{{ assets|safe }}</head>"
        "<body>{{ btn|safe }}{{ modal|safe }}</body></html>",
        assets=ui.render_assets(), btn=ui.render_button(), modal=ui.render_modal(),
    )
```

## Quick start (no framework — NiceGUI / Django / vanilla ASGI)

`SsoUi` exposes async handlers that take primitive arguments and return a
`HandlerResult(status, body)`. Wire them into whatever route table you have:

```python
from alien_sso_jinja import SsoUi
ui = SsoUi(client=sso)

# In your async route handler for POST /sso/start:
result = await ui.start()                                # HandlerResult
return result.body, result.status                        # JSON-serialize body

# POST /sso/poll, body: {"polling_code": "..."}
result = await ui.poll(request_body["polling_code"])

# POST /sso/finish, body: {"authorization_code": "..."}
result = await ui.finish(request_body["authorization_code"])
```

## API

| Method | Description |
| --- | --- |
| `render_button(modal_id=...)` | HTML for the trigger button. |
| `render_modal(modal_id=...)` | HTML for the modal dialog. |
| `render_assets()` | `<style>` + `<script>` block. Include once per page. |
| `render_all()` | Convenience: button + modal + assets. |
| `await start()` → `HandlerResult` | POST `/start`. Returns `deep_link`, `polling_code`, inline `qr_svg`. |
| `await poll(polling_code)` → `HandlerResult` | POST `/poll`. Passes the upstream status through. |
| `await finish(authorization_code)` → `HandlerResult` | POST `/finish`. Stores tokens and returns the `sub` claim. |
| `fastapi_router()` | Returns a FastAPI `APIRouter` wired to start/poll/finish (async). |
| `flask_blueprint()` | Returns a Flask `Blueprint` with async views (Flask 3.0+). |

## Customizing

```python
ui = SsoUi(
    client=sso,
    api_base="/auth/sso",                    # where you mount the router
    button_label="Connect with Alien",
    title="Connect to Acme",
    instructions="Open Alien on your phone, scan the QR.",
    polling_interval_ms=4000,                # default = client.polling_interval * 1000
)
```

The CSS uses CSS variables and is light-weight — override the styles in your
own stylesheet or fork the template (`templates/_assets.html.j2`) if you need
deeper control.

## Browser → server contract

The bundled JS makes exactly three requests, all `application/json` POSTs:

| Path | Body | Response |
| --- | --- | --- |
| `{api_base}/start` | (none) | `{ ok, deep_link, polling_code, expired_at, qr_svg }` |
| `{api_base}/poll` | `{ polling_code }` | `{ ok, status, authorization_code? }` |
| `{api_base}/finish` | `{ authorization_code }` | `{ ok, sub }` |

On successful sign-in the modal fires a bubbling `alien-sso:success` `CustomEvent`
on itself with `event.detail = { ok: true, sub: "..." }`. Listen for it to
redirect or refresh:

```js
document.getElementById('alien-sso-modal').addEventListener('alien-sso:success', () => {
    window.location.reload();
});
```

## License

MIT.
