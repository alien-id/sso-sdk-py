"""Boundary checks on AlienSsoClient construction (RFC 6749 §10.4)."""

from __future__ import annotations

import pytest

from alien_sso import AlienSsoClient, AlienSsoClientConfig, MemoryStorage

PROVIDER = "00000001000000000000000000000000"


def _make(url: str) -> AlienSsoClient:
    return AlienSsoClient(
        AlienSsoClientConfig(sso_base_url=url, provider_address=PROVIDER),
        storage=MemoryStorage(),
    )


def test_rejects_plain_http_remote_base_url():
    # RFC 6749 §10.4: tokens MUST be transmitted over TLS in transit and
    # storage. Reject http:// for non-loopback hosts at construction time
    # so callers can't accidentally send credentials in cleartext.
    with pytest.raises(ValueError, match="https"):
        _make("http://sso.example.com")


def test_accepts_https_remote_base_url():
    c = _make("https://sso.example.com")
    assert c.sso_base_url == "https://sso.example.com"


def test_accepts_http_localhost_for_dev():
    # Local development convenience — loopback is not over the wire.
    c = _make("http://localhost:8080")
    assert c.sso_base_url == "http://localhost:8080"


def test_accepts_http_127_0_0_1_for_dev():
    c = _make("http://127.0.0.1:8080")
    assert c.sso_base_url == "http://127.0.0.1:8080"
