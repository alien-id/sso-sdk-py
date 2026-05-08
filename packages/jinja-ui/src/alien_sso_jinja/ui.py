"""Framework-agnostic UI helper.

`SsoUi` wraps an `AlienSsoClient` and exposes:

  - `render_button(...)` / `render_modal(...)` — return HTML strings.
  - `start()` / `poll(code)` / `finish(code)` — pure-Python handlers
    that take dicts and return `HandlerResult`s. Adapter modules wire these
    into Flask / FastAPI / Starlette / Django routes.

Designed so the JS in the modal does the bare minimum (start → render QR →
poll on a timer → POST finish on success). All cryptographic + storage state
stays on the server, where the `AlienSsoClient` instance lives.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

from jinja2 import Environment, PackageLoader, select_autoescape

from alien_sso_jinja.qr import render_qr_svg

if TYPE_CHECKING:
    from alien_sso import AlienSsoClient


@dataclass
class HandlerResult:
    """Plain return value for the framework-agnostic HTTP handlers."""

    status: int
    body: dict[str, Any]


_jinja = Environment(
    loader=PackageLoader("alien_sso_jinja", "templates"),
    autoescape=select_autoescape(("html", "j2")),
    trim_blocks=True,
    lstrip_blocks=True,
)


class SsoUi:
    """UI helper for the OAuth2 PKCE Alien SSO flow."""

    def __init__(
        self,
        client: "AlienSsoClient",
        *,
        api_base: str = "/sso",
        button_label: str = "Sign in with Alien",
        title: str = "Sign in with Alien",
        instructions: str = "Open the Alien app on your phone and scan the QR code.",
        polling_interval_ms: Optional[int] = None,
    ) -> None:
        self.client = client
        self.api_base = api_base.rstrip("/")
        self.button_label = button_label
        self.title = title
        self.instructions = instructions
        self.polling_interval_ms = polling_interval_ms or int(client.polling_interval * 1000)

    # ─── HTML rendering ─────────────────────────────────────────────────

    def render_assets(self) -> str:
        """Render the CSS + JS bundle. Include this once per page."""
        return _jinja.get_template("_assets.html.j2").render(
            api_base=self.api_base,
            polling_interval_ms=self.polling_interval_ms,
        )

    def render_button(self, *, modal_id: str = "alien-sso-modal") -> str:
        return _jinja.get_template("button.html.j2").render(
            label=self.button_label,
            modal_id=modal_id,
        )

    def render_modal(self, *, modal_id: str = "alien-sso-modal") -> str:
        return _jinja.get_template("modal.html.j2").render(
            modal_id=modal_id,
            title=self.title,
            instructions=self.instructions,
        )

    def render_all(self, *, modal_id: str = "alien-sso-modal") -> str:
        """Convenience: button + modal + assets in one string."""
        return "\n".join(
            [
                self.render_assets(),
                self.render_button(modal_id=modal_id),
                self.render_modal(modal_id=modal_id),
            ]
        )

    # ─── HTTP handlers (framework-agnostic, async) ──────────────────────

    async def start(self) -> HandlerResult:
        """Begin a flow. Returns deep_link, polling_code, qr_svg."""
        try:
            resp = await self.client.generate_deeplink()
        except Exception as e:
            return HandlerResult(500, {"ok": False, "error": str(e)})
        return HandlerResult(
            200,
            {
                "ok": True,
                "deep_link": resp.deep_link,
                "polling_code": resp.polling_code,
                "expired_at": resp.expired_at,
                "qr_svg": render_qr_svg(resp.deep_link),
            },
        )

    async def poll(self, polling_code: str) -> HandlerResult:
        """Poll for authorization. Returns the upstream PollResponse fields."""
        if not polling_code:
            return HandlerResult(400, {"ok": False, "error": "polling_code required"})
        try:
            resp = await self.client.poll_auth(polling_code)
        except Exception as e:
            return HandlerResult(502, {"ok": False, "error": str(e)})
        body: dict[str, Any] = {"ok": True, "status": resp.status.value}
        if resp.authorization_code:
            body["authorization_code"] = resp.authorization_code
        return HandlerResult(200, body)

    async def finish(self, authorization_code: str) -> HandlerResult:
        """Exchange the code for tokens. Returns subject claim on success."""
        if not authorization_code:
            return HandlerResult(400, {"ok": False, "error": "authorization_code required"})
        try:
            await self.client.exchange_token(authorization_code)
        except Exception as e:
            return HandlerResult(400, {"ok": False, "error": str(e)})
        return HandlerResult(200, {"ok": True, "sub": self.client.get_subject()})

    # ─── Framework adapters ─────────────────────────────────────────────

    def fastapi_router(self):
        """Return a FastAPI APIRouter wired to start/poll/finish.

        Requires the `fastapi` extra: `pip install 'alien-sso-jinja[fastapi]'`.
        """
        from alien_sso_jinja._fastapi import build_router

        return build_router(self)

    def flask_blueprint(self, name: str = "alien_sso", url_prefix: Optional[str] = None):
        """Return a Flask Blueprint wired to start/poll/finish.

        Requires the `flask` extra: `pip install 'alien-sso-jinja[flask]'`.
        """
        from alien_sso_jinja._flask import build_blueprint

        return build_blueprint(self, name=name, url_prefix=url_prefix)
