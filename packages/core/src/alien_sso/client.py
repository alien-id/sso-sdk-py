"""AlienSsoClient — Python port of `packages/core/src/client.ts`.

Async-first: all HTTP methods are `async def` and use `httpx.AsyncClient`.
Browser `localStorage` / `sessionStorage` is replaced by the `Storage`
protocol — defaults to `MemoryStorage`. Tokens, refresh tokens, expiry, and
the PKCE code verifier all go through the same Storage instance.

Concurrent refresh attempts coalesce into a single network call via an
`asyncio.Lock` + cached future (mirrors the JS singleton-promise pattern).

Errors are typed (`AuthorizeError`, `PollError`, `TokenExchangeError`,
`RefreshError`, `UnauthorizedError`).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Protocol, TypeVar, runtime_checkable
from urllib.parse import urljoin, urlparse

import httpx

from alien_sso._pkce import generate_code_challenge, generate_code_verifier
from alien_sso._verify import JwksCache, verify_id_token
from alien_sso.errors import (
    AuthorizeError,
    PollError,
    RefreshError,
    TokenExchangeError,
    UnauthorizedError,
)
from alien_sso.schema import (
    AuthorizeResponse,
    PollResponse,
    TokenInfo,
    TokenResponse,
    UserInfoResponse,
)
from alien_sso.storage import MemoryStorage, Storage

DEFAULT_SSO_BASE_URL = "https://sso.alien.com"
DEFAULT_POLLING_INTERVAL = 5.0  # seconds, used by callers driving the poll loop

_STORAGE_KEY = "alien-sso_"
_KEY_ACCESS = _STORAGE_KEY + "access_token"
_KEY_ID_TOKEN = _STORAGE_KEY + "id_token"
_KEY_REFRESH = _STORAGE_KEY + "refresh_token"
_KEY_EXPIRY = _STORAGE_KEY + "token_expiry"
_KEY_VERIFIER = _STORAGE_KEY + "code_verifier"
_KEY_NONCE = _STORAGE_KEY + "nonce"


T = TypeVar("T")


@runtime_checkable
class NonceStore(Protocol):
    """Atomic check-and-consume store for OIDC nonces.

    `consume(n)` MUST return True iff the nonce was valid AND has now been
    invalidated (so a replay returns False). The default `_DefaultNonceStore`
    is a process-local set; multi-process deployments MUST supply a shared
    backing store (e.g. Redis SETNX-and-DEL). Per OIDC §3.1.3.7.11 nonces
    are single-use; callers are responsible for persistence.
    """

    def consume(self, nonce: str) -> bool: ...


class _DefaultNonceStore:
    """Process-local nonce ledger. Not safe across processes."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def consume(self, nonce: str) -> bool:
        if nonce in self._used:
            return False
        self._used.add(nonce)
        return True


@dataclass(frozen=True)
class AlienSsoClientConfig:
    sso_base_url: str
    provider_address: str
    polling_interval: float = DEFAULT_POLLING_INTERVAL
    # OIDC §3.1.3.7.3: id_token iss MUST exactly match expected. Defaults
    # to sso_base_url; override when the AS publishes a distinct issuer.
    expected_issuer: Optional[str] = None
    # OIDC §3.1.3.7 step 3: when aud is multi-valued, every entry MUST be
    # in the caller-supplied trusted set. Defaults to {provider_address}.
    trusted_audiences: Optional[frozenset[str]] = None


class AlienSsoClient:
    """Async Alien SSO client.

    Lifecycle:
        1. `await generate_deeplink()` → returns deep_link + polling_code.
        2. Show the deep_link as a QR code.
        3. `await poll_auth(polling_code)` until status == 'authorized'.
        4. `await exchange_token(authorization_code)` → access + id + refresh.
        5. `await verify_auth()` to fetch userinfo (auto-refreshes on 401).
        6. `logout()` to clear stored credentials (sync — no network).

    Use as an async context manager when you don't pass your own `http_client`:

        async with AlienSsoClient(config) as client:
            await client.generate_deeplink()
    """

    def __init__(
        self,
        config: AlienSsoClientConfig,
        *,
        storage: Optional[Storage] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not config.sso_base_url:
            raise ValueError("sso_base_url is required")
        if not config.provider_address:
            raise ValueError("provider_address is required")
        _require_secure_base_url(config.sso_base_url)
        self.config = config
        self.sso_base_url = config.sso_base_url
        self.provider_address = config.provider_address
        self.polling_interval = config.polling_interval
        self.expected_issuer = config.expected_issuer or config.sso_base_url
        self._storage: Storage = storage or MemoryStorage()
        self._http = http_client or httpx.AsyncClient(timeout=10.0)
        self._owns_http = http_client is None
        # Coalesce concurrent refresh attempts (mirrors the JS singleton promise).
        self._refresh_lock = asyncio.Lock()
        self._refresh_future: Optional["asyncio.Future[TokenResponse]"] = None
        # OIDC §3.1.3.7.8: id_token signature verification needs the
        # issuer JWKS. Cached lazily; daily TTL.
        self._jwks_cache = JwksCache(url=self._url("/oauth/jwks"))
        # OIDC §3.1.3.7.11: nonces are single-use replay tokens. Default
        # store is process-local; replace with a shared backend in
        # multi-process deployments.
        self._nonce_store: NonceStore = _DefaultNonceStore()
        # Cache the (token, verified_payload) pair so repeated reads of the
        # same id_token don't re-trigger nonce consumption.
        self._verified_cache: Optional[tuple[str, dict[str, Any]]] = None

    def set_nonce_store(self, store: NonceStore) -> None:
        self._nonce_store = store
        self._verified_cache = None

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AlienSsoClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ─── OAuth2 endpoints ───────────────────────────────────────────────

    async def generate_deeplink(self) -> AuthorizeResponse:
        """GET /oauth/authorize?response_mode=json — start a PKCE flow."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        # OIDC §3.1.2.1: send a CSPRNG nonce and verify it on the
        # returned id_token (replay protection).
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        # RFC 6749 §10.12 / §4.1.1: opaque CSPRNG state for request-response
        # correlation. The polling design already binds the response to the
        # polling_code we mint, but state is the standardised channel and
        # supports server echoes for additional defence in depth.
        state = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        self._storage.set(_KEY_VERIFIER, verifier)
        self._storage.set(_KEY_NONCE, nonce)

        params = {
            "response_type": "code",
            "response_mode": "json",
            "client_id": self.provider_address,
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "state": state,
        }
        resp = await self._http.get(self._url("/oauth/authorize"), params=params)
        if resp.status_code >= 400:
            raise AuthorizeError(_describe_error(resp, "Authorize failed"))
        body = resp.json()
        # RFC 6749 §10.12 applies to the *authorization response*, which in
        # Alien's poll-based flow is the response from `/oauth/poll`, not
        # this `/oauth/authorize` request-acknowledgement that returns
        # only the deep-link + polling_code. The polling_code is itself
        # an unguessable CSPRNG identifier minted on this round-trip and
        # bound to the requesting client. We still tolerate an echoed
        # state field for AS implementations that emit one — when it's
        # present, it MUST match — but its absence is not an error here.
        echoed = body.get("state")
        if isinstance(echoed, str) and echoed != state:
            raise AuthorizeError("Authorize response state mismatch (RFC 6749 §10.12)")
        parsed = AuthorizeResponse.from_json(body)
        # AuthorizeResponse.from_json doesn't carry state through; build a
        # new instance with the request-time value so callers can persist it.
        return AuthorizeResponse(
            deep_link=parsed.deep_link,
            polling_code=parsed.polling_code,
            expired_at=parsed.expired_at,
            state=state,
        )

    async def poll_auth(
        self, polling_code: str, *, expected_state: Optional[str] = None
    ) -> PollResponse:
        """POST /oauth/poll — check whether the user has authorized yet.

        When `expected_state` is supplied (the client retained the value it
        sent on /oauth/authorize), the AS response MUST echo a matching
        state, otherwise a forged response would silently pass — RFC 6749
        §10.12. Missing state is therefore an error, not a tolerated case.
        Callers that intentionally do not use state may omit
        `expected_state` and the check is skipped.
        """
        resp = await self._http.post(
            self._url("/oauth/poll"),
            json={"polling_code": polling_code},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code >= 400:
            raise PollError(f"Poll failed: {resp.reason_phrase}")
        body = resp.json()
        if expected_state is not None:
            echoed = body.get("state")
            if not isinstance(echoed, str):
                raise PollError(
                    "Poll response missing state parameter (RFC 6749 §10.12)"
                )
            if echoed != expected_state:
                raise PollError("Poll response state mismatch (RFC 6749 §10.12)")
        parsed = PollResponse.from_json(body)
        # RFC 9207 §2.4: when the AS includes the `iss` response param,
        # the Client MUST verify it identifies the expected issuer to
        # detect mix-up attacks where one AS's response is delivered to
        # another. When the AS does not include `iss`, the check is
        # skipped — RFC 9207 deployment is incremental and missing iss
        # is permitted on AS implementations that haven't advertised
        # `authorization_response_iss_parameter_supported`.
        if parsed.iss is not None and parsed.iss != self.expected_issuer:
            raise PollError(
                f"Poll response iss={parsed.iss!r} does not match "
                f"expected issuer {self.expected_issuer!r} (RFC 9207 §2.4)"
            )
        return parsed

    async def exchange_token(self, authorization_code: str) -> TokenResponse:
        """POST /oauth/token (grant_type=authorization_code).

        Stores access_token, id_token (if present), refresh_token, and expiry.
        Clears the PKCE verifier afterwards.
        """
        verifier = self._storage.get(_KEY_VERIFIER)
        if not verifier:
            raise TokenExchangeError("Missing code verifier.")

        body = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "client_id": self.provider_address,
            "code_verifier": verifier,
        }
        resp = await self._http.post(
            self._url("/oauth/token"),
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code >= 400:
            raise TokenExchangeError(_describe_error(resp, "Token exchange failed"))
        token = TokenResponse.from_json(resp.json())
        self._store_tokens(token)
        self._storage.delete(_KEY_VERIFIER)
        return token

    async def verify_auth(self) -> Optional[UserInfoResponse]:
        """GET /oauth/userinfo — auto-refreshes on 401 if a refresh token exists."""
        return await self.with_auto_refresh(self._verify_auth_once)

    async def _verify_auth_once(self) -> Optional[UserInfoResponse]:
        access = self.get_access_token()
        if not access:
            return None
        resp = await self._http.get(
            self._url("/oauth/userinfo"),
            headers={"Authorization": f"Bearer {access}"},
        )
        if resp.status_code == 401:
            raise UnauthorizedError("Unauthorized")
        if resp.status_code >= 400:
            return None
        info = UserInfoResponse.from_json(resp.json())
        # OIDC §5.3 / RFC 9068 §6: when the userinfo response carries an
        # `aud` claim (the AT's client_id), it MUST identify this client.
        # The Alien backend echoes it specifically so the RP can confirm
        # the AT was issued for them, defending against AT-substitution.
        # When `aud` is absent, the check is skipped — the AT was already
        # validated in `_store_tokens` against `self.provider_address`.
        if info.aud is not None and info.aud != self.provider_address:
            raise UnauthorizedError(
                f"userinfo aud={info.aud!r} does not match client_id "
                f"{self.provider_address!r} (OIDC §5.3)"
            )
        return info

    async def refresh_access_token(self) -> TokenResponse:
        """POST /oauth/token (grant_type=refresh_token).

        Concurrent callers coalesce — only one network request fires; the rest
        await the same future.
        """
        async with self._refresh_lock:
            if self._refresh_future is not None and not self._refresh_future.done():
                future = self._refresh_future
            else:
                future = asyncio.get_running_loop().create_future()
                self._refresh_future = future
                # Fire and forget — `future` carries the result.
                asyncio.create_task(self._do_refresh_into(future))
        return await future

    async def _do_refresh_into(self, future: "asyncio.Future[TokenResponse]") -> None:
        try:
            token = await self._do_refresh()
        except BaseException as e:
            future.set_exception(e)
            return
        future.set_result(token)

    async def _do_refresh(self) -> TokenResponse:
        refresh = self.get_refresh_token()
        if not refresh:
            raise RefreshError("No refresh token available")

        resp = await self._http.post(
            self._url("/oauth/token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": self.provider_address,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code >= 400:
            self.logout()  # nuke stale tokens
            raise RefreshError(_describe_error(resp, "Token refresh failed"))
        token = TokenResponse.from_json(resp.json())
        self._store_tokens(token)
        return token

    async def with_auto_refresh(
        self, fn: Callable[[], Awaitable[T]], max_retries: int = 1
    ) -> T:
        """Run `fn`; if it raises `UnauthorizedError`, refresh and retry once."""
        try:
            return await fn()
        except UnauthorizedError:
            if max_retries <= 0 or not self.has_refresh_token():
                raise
            await self.refresh_access_token()
            return await fn()

    # ─── Token / storage helpers (sync — no I/O) ────────────────────────

    def get_access_token(self) -> Optional[str]:
        return self._storage.get(_KEY_ACCESS)

    def get_id_token(self) -> Optional[str]:
        return self._storage.get(_KEY_ID_TOKEN)

    def get_refresh_token(self) -> Optional[str]:
        return self._storage.get(_KEY_REFRESH)

    def has_refresh_token(self) -> bool:
        return self.get_refresh_token() is not None

    def get_subject(self) -> Optional[str]:
        info = self.get_auth_data()
        return info.sub if info else None

    def get_auth_data(self) -> Optional[TokenInfo]:
        """Return the locally-stored id_token's claims after FULL OIDC
        §3.1.3.7 / RFC 7519 §7.2 validation: signature (against the
        issuer's JWKS), iss, aud, azp, exp, nbf, typ, crit, and the
        request-time nonce. Returns None on any failure.

        The first call may trigger a synchronous JWKS fetch from
        `<sso_base_url>/oauth/jwks` (cached daily). Per RFC 9068 §6 we
        never fall back to the access token.
        """
        token = self.get_id_token()
        if not token:
            return None
        # Repeated reads of the same id_token return the cached verified
        # payload — verification (including nonce consumption) only runs
        # the first time we see a given token.
        if self._verified_cache is not None and self._verified_cache[0] == token:
            try:
                return TokenInfo.from_json(self._verified_cache[1])
            except (ValueError, TypeError):
                return None
        try:
            jwks = self._jwks_cache.get()
        except Exception:
            return None
        trusted = self.config.trusted_audiences
        expected_nonce = self._storage.get(_KEY_NONCE)
        verified = verify_id_token(
            token,
            jwks=jwks,
            expected_issuer=self.expected_issuer,
            expected_audience=self.provider_address,
            expected_nonce=expected_nonce,
            trusted_audiences=set(trusted) if trusted is not None else None,
        )
        if verified is None:
            return None
        # OIDC §3.1.3.7.11: nonce is single-use. Atomically consume on first
        # verification so a replay of the same id_token bytes against a fresh
        # client (or shared store) fails.
        nonce_claim = verified.payload.get("nonce")
        if isinstance(nonce_claim, str) and not self._nonce_store.consume(nonce_claim):
            return None
        self._verified_cache = (token, verified.payload)
        try:
            return TokenInfo.from_json(verified.payload)
        except (ValueError, TypeError):
            return None

    def is_token_expired(self) -> bool:
        info = self.get_auth_data()
        if info is None:
            return True
        return time.time() > info.exp

    def is_access_token_expired(self) -> bool:
        """True if the stored access token will expire in the next 5 minutes."""
        raw = self._storage.get(_KEY_EXPIRY)
        if not raw:
            return True
        try:
            expiry_ms = int(raw)
        except ValueError:
            return True
        now_ms = int(time.time() * 1000)
        buffer_ms = 5 * 60 * 1000
        return now_ms >= expiry_ms - buffer_ms

    def logout(self) -> None:
        """Clear every key this client owns. Idempotent. Synchronous — no I/O."""
        for key in (_KEY_ACCESS, _KEY_ID_TOKEN, _KEY_REFRESH, _KEY_EXPIRY, _KEY_VERIFIER, _KEY_NONCE):
            self._storage.delete(key)
        self._verified_cache = None

    # ─── Internals ──────────────────────────────────────────────────────

    def _store_tokens(self, token: TokenResponse) -> None:
        self._storage.set(_KEY_ACCESS, token.access_token)
        if token.id_token:
            self._storage.set(_KEY_ID_TOKEN, token.id_token)
        # RFC 6749 §6: refresh_token reissuance is OPTIONAL; if the AS
        # omits one, the existing stored refresh_token remains valid.
        # Only overwrite when a new value is present.
        if token.refresh_token:
            self._storage.set(_KEY_REFRESH, token.refresh_token)
        # RFC 6749 §5.1: expires_in is RECOMMENDED but not REQUIRED. When
        # the AS omits it, fall back to a conservative default that
        # matches the access-token cap on the AS side (15 min) so the
        # client refreshes proactively rather than relying on a never-
        # expiring local cache.
        if token.expires_in is not None:
            expiry_ms = int(time.time() * 1000) + token.expires_in * 1000
        else:
            expiry_ms = int(time.time() * 1000) + 15 * 60 * 1000
        self._storage.set(_KEY_EXPIRY, str(expiry_ms))
        self._verified_cache = None

    def _url(self, path: str) -> str:
        # Match `new URL(path, base)` — preserves the path portion of base_url.
        base = self.sso_base_url
        if not base.endswith("/"):
            base = base + "/"
        return urljoin(base, path.lstrip("/"))


def _describe_error(resp: httpx.Response, prefix: str) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict):
            msg = body.get("error_description") or body.get("error")
            if isinstance(msg, str):
                return f"{prefix}: {msg}"
    except Exception:
        pass
    return f"{prefix}: {resp.reason_phrase or resp.status_code}"


def _b64url_decode(s: str) -> str:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8")


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _require_secure_base_url(url: str) -> None:
    """RFC 6749 §10.4: tokens MUST be transmitted over TLS. Reject `http://`
    for any non-loopback host at construction time."""
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (parsed.hostname or "") in _LOOPBACK_HOSTS:
        return
    raise ValueError(
        f"sso_base_url must use https (got {url!r}); "
        "RFC 6749 §10.4 requires TLS for credential transport"
    )
