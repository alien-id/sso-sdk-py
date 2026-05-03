"""PKCE helpers — code verifier + S256 challenge.

Mirrors the JS `generateCodeVerifier` + `generateCodeChallenge`. RFC 7636.
"""

from __future__ import annotations

import base64
import hashlib
import os


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def generate_code_verifier(length: int = 128) -> str:
    """Return a 128-byte (configurable) base64url string of random bytes."""
    return _b64url(os.urandom(length))


def generate_code_challenge(code_verifier: str) -> str:
    """Return BASE64URL(SHA256(code_verifier))."""
    return _b64url(hashlib.sha256(code_verifier.encode("utf-8")).digest())
