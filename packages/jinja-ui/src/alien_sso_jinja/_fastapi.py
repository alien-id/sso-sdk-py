"""FastAPI adapter — only imported when the user calls `ui.fastapi_router()`."""

from __future__ import annotations

from typing import TYPE_CHECKING

try:
    from fastapi import APIRouter, Body
    from fastapi.responses import JSONResponse
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "FastAPI is not installed. Install with: pip install 'alien-sso-jinja[fastapi]'"
    ) from e

if TYPE_CHECKING:
    from alien_sso_jinja.ui import SsoUi


def build_router(ui: "SsoUi") -> "APIRouter":
    router = APIRouter()

    @router.post("/start")
    async def _start():
        r = await ui.start()
        return JSONResponse(r.body, status_code=r.status)

    @router.post("/poll")
    async def _poll(payload: dict = Body(...)):
        r = await ui.poll(str(payload.get("polling_code") or ""))
        return JSONResponse(r.body, status_code=r.status)

    @router.post("/finish")
    async def _finish(payload: dict = Body(...)):
        r = await ui.finish(str(payload.get("authorization_code") or ""))
        return JSONResponse(r.body, status_code=r.status)

    return router
