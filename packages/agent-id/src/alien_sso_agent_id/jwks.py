"""JWKS fetching + JWT parsing helpers."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any

from alien_sso_agent_id._b64 import b64url_decode
from alien_sso_agent_id.types import JWKS

DEFAULT_SSO_BASE_URL = "https://sso.alien-api.com"
_HTTP_TIMEOUT = 5.0


@dataclass(frozen=True)
class _ParsedJwt:
    header_b64url: str
    payload_b64url: str
    signature_b64url: str
    header: dict[str, Any]
    payload: dict[str, Any]


def parse_jwt(token: str) -> _ParsedJwt:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 parts")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    return _ParsedJwt(header_b64, payload_b64, sig_b64, header, payload)


def fetch_alien_jwks(sso_base_url: str = DEFAULT_SSO_BASE_URL) -> JWKS:
    """Fetch the JWKS from the Alien SSO server.

    Callers should cache the result (e.g. for 24h) and refresh on key rotation.
    """
    url = sso_base_url.rstrip("/") + "/oauth/jwks"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Failed to fetch JWKS: {resp.status} {resp.reason}")
        body = resp.read()
    jwks: JWKS = json.loads(body)
    if not isinstance(jwks.get("keys"), list):
        raise ValueError("JWKS response missing keys[]")
    return jwks
