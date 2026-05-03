"""SVG QR-code rendering. Uses `segno` — pure-Python, zero deps."""

from __future__ import annotations

import io

import segno


def render_qr_svg(data: str, *, scale: int = 6, dark: str = "#0f766e") -> str:
    """Return the SVG for `data` as a string, sized for inline embedding."""
    qr = segno.make(data, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=scale, dark=dark, light="white", border=2, xmldecl=False)
    return buf.getvalue().decode("utf-8")
