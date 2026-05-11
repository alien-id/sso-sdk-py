# alien-sso

Python OAuth2 PKCE client for [Alien SSO](https://alien.org). Port of
[`@alien-id/sso`](https://www.npmjs.com/package/@alien-id/sso).

OIDC-compatible authentication with blockchain and TEE backing. The browser
`localStorage` / `sessionStorage` requirement of the JS package is replaced
with a pluggable `Storage` protocol so it works in CLIs, daemons, web apps,
and notebooks alike.

## Install

```bash
pip install alien-sso
```

## Quick start

```python
import asyncio
from alien_sso import AlienSsoClient, AlienSsoClientConfig, FileStorage

async def main():
    async with AlienSsoClient(
        AlienSsoClientConfig(
            sso_base_url="https://sso.alien-api.com",
            provider_address="<your-provider-address>",
        ),
        storage=FileStorage("~/.cache/myapp/sso.json"),
    ) as client:
        # 1. Start a flow — show deep_link as a QR code
        auth = await client.generate_deeplink()
        print("Open in Alien app:", auth.deep_link)

        # 2. Poll until the user authorizes
        while True:
            poll = await client.poll_auth(auth.polling_code)
            if poll.status.value == "authorized":
                break
            if poll.status.value in ("rejected", "expired"):
                raise SystemExit(f"flow failed: {poll.status.value}")
            await asyncio.sleep(client.polling_interval)

        # 3. Exchange the code for tokens
        await client.exchange_token(poll.authorization_code)

        # 4. Use it
        info = await client.verify_auth()  # auto-refreshes on 401
        print("logged in as", info.sub)

asyncio.run(main())
```

Want sync? Wrap the calls in `asyncio.run(...)` — there is no separate sync
client. (FastAPI / Starlette / aiohttp / async Django / NiceGUI all run
inside an event loop already; Flask 3 supports async routes too.)

## Storage backends

- `MemoryStorage()` — process-local, thread-safe (the default).
- `FileStorage(path)` — JSON on disk (mode 0o600). Useful for CLI agents that
  should survive restarts.
- Implement the `Storage` protocol (`get`, `set`, `delete`, `clear`) for
  Redis / encrypted DB / etc.

## API surface

Async (HTTP):

| Method | Description |
| --- | --- |
| `await generate_deeplink()` | Start a PKCE flow. Returns `deep_link`, `polling_code`, `expired_at`. |
| `await poll_auth(polling_code)` | Returns `PollResponse(status, authorization_code?)`. |
| `await exchange_token(code)` | Exchange the authorization code for access + id + refresh tokens. |
| `await verify_auth()` | GET `/oauth/userinfo`. Auto-refreshes on 401. |
| `await refresh_access_token()` | Force-refresh. Concurrent callers coalesce on a single network call. |
| `await with_auto_refresh(fn)` | Wrap any awaitable: refresh + retry once on `UnauthorizedError`. |
| `await aclose()` / `async with` | Close the underlying `httpx.AsyncClient`. |

Sync (no I/O — pure storage / JWT decode):

| Method | Description |
| --- | --- |
| `get_access_token()` / `get_id_token()` / `get_refresh_token()` | Stored token accessors. |
| `get_auth_data()` | Decode + validate the JWT payload (audience-checked). |
| `get_subject()` | `sub` claim shorthand. |
| `is_token_expired()` | True if the JWT `exp` is in the past. |
| `is_access_token_expired()` | True if the access token expires within 5 min. |
| `logout()` | Clear every key this client owns. |

## Errors

- `AuthorizeError` — `/oauth/authorize` returned non-2xx.
- `PollError` — `/oauth/poll` returned non-2xx.
- `TokenExchangeError` — code → token failed (or no PKCE verifier in storage).
- `RefreshError` — refresh failed; tokens have been cleared.
- `UnauthorizedError` — userinfo returned 401 (auto-refresh hook).

All inherit from `AlienSsoError`.

## Differences from the JS package

- **Async-first.** All HTTP methods are `async def` (`httpx.AsyncClient`).
  No sync HTTP client is shipped — `asyncio.run(...)` if you need one-shot
  sync invocation from a CLI.
- `localStorage` + `sessionStorage` → unified pluggable `Storage`.
- Singleton refresh-promise → `asyncio.Lock` + cached future coalescing.
- Plain `Error` → typed exception hierarchy.
- Zod schemas → frozen dataclasses with `from_json` constructors.

## License

MIT.
