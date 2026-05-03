"""Server-rendered Alien SSO sign-in UI.

Replacement for the JS `@alien-id/sso-react` (and `@alien-id/sso-solana-react`)
packages. Ships Jinja2 templates for a sign-in button + QR modal, a tiny
embedded vanilla-JS polling loop, and framework-agnostic HTTP handlers you can
mount in Flask, FastAPI, Starlette, or anything else with a route table.

Quick start (FastAPI):

    from alien_sso import AlienSsoClient, AlienSsoClientConfig
    from alien_sso_jinja import SsoUi

    sso = AlienSsoClient(AlienSsoClientConfig(
        sso_base_url="https://sso.alien.com",
        provider_address="<your-provider>",
    ))
    ui = SsoUi(client=sso)

    app = FastAPI()
    app.include_router(ui.fastapi_router(), prefix="/sso")

    # In your template:
    #   {{ ui.render_button() | safe }}
    #   {{ ui.render_modal() | safe }}
"""

from alien_sso_jinja.qr import render_qr_svg
from alien_sso_jinja.ui import HandlerResult, SsoUi

__all__ = [
    "HandlerResult",
    "SsoUi",
    "render_qr_svg",
]
