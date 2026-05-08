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


class EncryptedIdTokenError(ValueError):
    """Raised when an id_token is a JWE (RFC 7516) instead of a JWS.

    OIDC §3.1.3.7 requires the client to either decrypt or reject. We do
    not implement decryption, so this surfaces the policy explicitly.
    """


@dataclass(frozen=True)
class _ParsedJwt:
    header_b64url: str
    payload_b64url: str
    signature_b64url: str
    header: dict[str, Any]
    payload: dict[str, Any]


def parse_jwt(token: str) -> _ParsedJwt:
    parts = token.split(".")
    # RFC 7516 §9: JWEs have five segments separated by four periods. The
    # caller passed an Encrypted ID Token; we don't support decryption.
    if len(parts) == 5:
        raise EncryptedIdTokenError(
            "Encrypted ID Tokens (JWE) are not supported"
        )
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 parts")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    # RFC 7519 §7.2 steps 2 & 7: JOSE Header and JWT Claims Set MUST be
    # JSON objects. Reject literals (null, strings, arrays).
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Invalid JWT: header and payload must be JSON objects")
    # RFC 7516 §4.1.2: `enc` is mandatory in JWE protected headers. A
    # 3-part token carrying `enc` is mis-routed encryption — reject with
    # the same explicit policy as a 5-part JWE.
    if "enc" in header:
        raise EncryptedIdTokenError(
            "Encrypted ID Tokens (JWE) are not supported"
        )
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
