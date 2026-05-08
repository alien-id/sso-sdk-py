"""PKCE helpers — code verifier + S256 challenge.

Mirrors the JS `generateCodeVerifier` + `generateCodeChallenge`. RFC 7636.
"""

from __future__ import annotations

import base64
import hashlib
import os


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def generate_code_verifier() -> str:
    """RFC 7636 §4.1 / §7.1: 32 random octets → 43-char base64url verifier
    (256-bit entropy floor, within the 43–128 length window)."""
    return _b64url(os.urandom(32))


def generate_code_challenge(code_verifier: str) -> str:
    """Return BASE64URL(SHA256(code_verifier))."""
    return _b64url(hashlib.sha256(code_verifier.encode("utf-8")).digest())
