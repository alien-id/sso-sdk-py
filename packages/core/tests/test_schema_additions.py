"""Schema additions to surface backend-emitted RFC 9068 §2.2 claims."""

from __future__ import annotations

import pytest

from alien_sso.schema import TokenInfo, TokenResponse, UserInfoResponse


def test_token_response_accepts_bearer_token_type():
    """RFC 6750 §4: Bearer is the only scheme this client uses — accept it."""
    tr = TokenResponse.from_json({
        "access_token": "at-abc",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "rt-abc",
    })
    assert tr.token_type == "Bearer"


def test_token_response_accepts_bearer_token_type_case_insensitive():
    """RFC 6749 §5.1: token_type comparison is case-insensitive."""
    tr = TokenResponse.from_json({
        "access_token": "at-abc",
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": "rt-abc",
    })
    assert tr.token_type == "bearer"


def test_token_response_rejects_dpop_token_type():
    """RFC 9449: a DPoP-bound AT requires DPoP-aware request construction
    that this Bearer-only client cannot provide. Reject up-front."""
    with pytest.raises(ValueError, match="Bearer"):
        TokenResponse.from_json({
            "access_token": "at-abc",
            "token_type": "DPoP",
            "expires_in": 3600,
            "refresh_token": "rt-abc",
        })


def test_token_response_rejects_unknown_token_type():
    with pytest.raises(ValueError, match="Bearer"):
        TokenResponse.from_json({
            "access_token": "at-abc",
            "token_type": "MAC",
            "expires_in": 3600,
            "refresh_token": "rt-abc",
        })


def test_token_response_accepts_omitted_refresh_token_and_expires_in():
    """RFC 6749 §5.1 / §6: AS may omit refresh_token (refresh-grant) and
    expires_in. The parser MUST NOT crash on a spec-compliant minimal
    response."""
    tr = TokenResponse.from_json({
        "access_token": "at-only",
        "token_type": "Bearer",
    })
    assert tr.access_token == "at-only"
    assert tr.refresh_token is None
    assert tr.expires_in is None


def test_token_response_rejects_non_int_expires_in():
    with pytest.raises(ValueError, match="expires_in"):
        TokenResponse.from_json({
            "access_token": "at-abc",
            "token_type": "Bearer",
            "expires_in": "3600",
        })


def test_token_response_rejects_non_string_refresh_token():
    with pytest.raises(ValueError, match="refresh_token"):
        TokenResponse.from_json({
            "access_token": "at-abc",
            "token_type": "Bearer",
            "refresh_token": 12345,
        })


def test_token_info_surfaces_client_id_and_jti():
    """RFC 9068 §2.2: AT carries `client_id` and `jti`. Schema must not strip."""
    parsed = TokenInfo.from_json({
        "iss": "https://sso.example.com",
        "sub": "user-1",
        "aud": ["client-y", "https://sso.example.com"],
        "exp": 9999999999,
        "iat": 1700000000,
        "client_id": "client-y",
        "jti": "u-1",
    })
    assert parsed.client_id == "client-y"
    assert parsed.jti == "u-1"


def test_user_info_response_surfaces_aud():
    """Backend `/oauth/userinfo` returns `{sub, aud}` where aud = AT.client_id."""
    parsed = UserInfoResponse.from_json({"sub": "user-1", "aud": "client-y"})
    assert parsed.aud == "client-y"


def test_token_info_client_id_and_jti_are_optional_for_id_tokens():
    """id_tokens don't carry client_id/jti — schema must still parse."""
    parsed = TokenInfo.from_json({
        "iss": "https://sso.example.com",
        "sub": "user-1",
        "aud": "client-y",
        "exp": 9999999999,
        "iat": 1700000000,
    })
    assert parsed.client_id is None
    assert parsed.jti is None


def test_user_info_response_aud_is_optional():
    """Older backends or unbound flows may not return aud — schema tolerates."""
    parsed = UserInfoResponse.from_json({"sub": "user-1"})
    assert parsed.aud is None
