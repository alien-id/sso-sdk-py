"""Flask adapter — only imported when the user calls `ui.flask_blueprint()`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

try:
    from flask import Blueprint, jsonify, request
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "Flask is not installed. Install with: pip install 'alien-sso-jinja[flask]'"
    ) from e

if TYPE_CHECKING:
    from alien_sso_jinja.ui import SsoUi


def build_blueprint(ui: "SsoUi", *, name: str = "alien_sso", url_prefix: Optional[str] = None):
    """Build a Flask Blueprint. Requires Flask 3.0+ for `async def` view support
    (and `pip install 'flask[async]'` to pull in the asgiref dep)."""
    bp = Blueprint(name, __name__, url_prefix=url_prefix)

    @bp.post("/start")
    async def _start():
        r = await ui.start()
        return jsonify(r.body), r.status

    @bp.post("/poll")
    async def _poll():
        data = request.get_json(silent=True) or {}
        r = await ui.poll(str(data.get("polling_code") or ""))
        return jsonify(r.body), r.status

    @bp.post("/finish")
    async def _finish():
        data = request.get_json(silent=True) or {}
        r = await ui.finish(str(data.get("authorization_code") or ""))
        return jsonify(r.body), r.status

    return bp
