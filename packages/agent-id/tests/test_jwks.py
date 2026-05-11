"""Unit tests for `alien_sso_agent_id.jwks.parse_jwt`."""

from __future__ import annotations

import base64
import json

import pytest

from alien_sso_agent_id.jwks import parse_jwt


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def test_parse_jwt_rejects_non_object_header():
    # RFC 7519 §7.2 step 2: "the JOSE Header is a completely valid JSON
    # object". A JWT whose header decodes to a JSON literal (e.g. `null`,
    # a string, or a list) MUST be rejected before `.get` is called.
    bad_header = _b64(b"null")
    payload = _b64(json.dumps({"sub": "x"}).encode("utf-8"))
    with pytest.raises(ValueError):
        parse_jwt(f"{bad_header}.{payload}.sig")


def test_parse_jwt_rejects_non_object_payload():
    # RFC 7519 §7.2 step 7: the JWT Claims Set MUST be a JSON object.
    header = _b64(json.dumps({"alg": "RS256"}).encode("utf-8"))
    bad_payload = _b64(b'"a string is not a claims set"')
    with pytest.raises(ValueError):
        parse_jwt(f"{header}.{bad_payload}.sig")


def test_parse_jwt_accepts_well_formed_object_header_and_payload():
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf-8"))
    payload = _b64(json.dumps({"sub": "user-1"}).encode("utf-8"))
    result = parse_jwt(f"{header}.{payload}.sig")
    assert result.header == {"alg": "RS256", "typ": "JWT"}
    assert result.payload == {"sub": "user-1"}
