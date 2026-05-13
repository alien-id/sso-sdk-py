# alien-sso-agent-id

> Verify inbound RFC 9449 (OAuth 2.0 DPoP) requests from Alien-bound agents in
> any Python service. One runtime dependency: `cryptography`.

The Alien agent sends two HTTP headers to your service:

```
Authorization: DPoP <access_token>      ← Alien at+jwt, signed by SSO
DPoP:          <proof JWT>              ← EdDSA, signed by the agent's own key
```

This library walks the [RFC 9449 §4.3](https://www.rfc-editor.org/rfc/rfc9449#section-4.3)
verification checklist, the [RFC 7800 §3.1](https://www.rfc-editor.org/rfc/rfc7800#section-3.1)
/ [RFC 9449 §6.1](https://www.rfc-editor.org/rfc/rfc9449#section-6.1) `cnf.jkt`
proof-of-possession binding, and the [RFC 9068 §4](https://www.rfc-editor.org/rfc/rfc9068#section-4)
access-token claim checks. On success, you can trust the `sub` (the human
owner) and `jkt` (the agent's DPoP key thumbprint) — both transitively signed
by the SSO and the agent respectively.

## Install

```bash
pip install alien-sso-agent-id
# Optional FastAPI helper:
pip install "alien-sso-agent-id[fastapi]"
```

Requires Python 3.11+.

## Quick start

```python
from alien_sso_agent_id import (
    VerifyDPoPOptions,
    fetch_alien_jwks,
    verify_dpop_request,
)

# Fetch the SSO's JWKS once at startup. Cache it; refresh every few hours.
JWKS = fetch_alien_jwks()

def handle(req) -> tuple[int, dict]:
    result = verify_dpop_request(
        {
            "method": req.method,
            "url": str(req.url),
            "headers": dict(req.headers),
        },
        VerifyDPoPOptions(jwks=JWKS),
    )
    if not result.ok:
        return 401, {"error": result.error}  # set WWW-Authenticate: DPoP …
    # result.sub                — human owner's AlienID address (signed by SSO)
    # result.jkt                — agent's Ed25519 key thumbprint (RFC 7638)
    # result.access_token_claims, result.proof_claims — raw decoded JWT payloads
    return 200, {"owner": result.sub}
```

That's the full integration for a service that wants to accept any agent on
the Alien network. `expected_issuer` defaults to `https://sso.alien-api.com`
and `expected_audience` defaults to that same value — see
[Federated audience](#federated-audience) for the rationale and when to
override.

The verifier needs the *full* request: method, URL, and headers. It uses these
to compare the proof's `htm` and `htu` claims against the actual request
(RFC 9449 §4.3 steps 8–9).

## Federated audience

The Alien SSO mints every access token with `aud = [client_id, issuer]`. By
default the verifier checks that `aud` contains `expected_issuer` — i.e. the
token was minted by the Alien SSO at all. This is the "federated audience"
pattern: every Alien-aware service treats the SSO issuer URL as its own
audience identifier, so one agent identity works against the whole network
with no per-service configuration.

The default is also defense-in-depth on top of the existing `typ == at+jwt`
check: an `id+jwt` from the same SSO has `aud = client_id` only (no issuer),
so even if the `typ` check were ever weakened the federated-audience default
would reject it.

Override `expected_audience` only when you specifically want to *narrow*
acceptance:

```python
# Scope to agents bound to your own OAuth client only:
VerifyDPoPOptions(jwks=JWKS, expected_audience="YOUR_CLIENT_ID")

# Scope to an RFC 8707 resource indicator (when SSO/agent support lands):
VerifyDPoPOptions(jwks=JWKS, expected_audience="https://your.service/api")

# Skip the audience check entirely (test fixtures only):
VerifyDPoPOptions(jwks=JWKS, expected_audience=False)
```

## API

### `verify_dpop_request(req, opts)`

`req` is a mapping with three keys:

| Key | Type | Description |
| --- | --- | --- |
| `method` | `str` | HTTP method, e.g. `"GET"`. Must match the proof's `htm` (case-sensitive). |
| `url` | `str` | Full request URL including scheme/host/path. Compared to the proof's `htu` after both sides strip query and fragment. |
| `headers` | `Mapping[str, str \| list[str]]` | Must include exactly one `authorization: DPoP <at>` and exactly one `dpop: <proof>`. |

`opts` is a `VerifyDPoPOptions` dataclass:

| Field | Type | Description |
| --- | --- | --- |
| `jwks` | `JWKS` | Pre-fetched JWKS from the SSO (see `fetch_alien_jwks`). |
| `expected_issuer` | `str \| None` | Defaults to `https://sso.alien-api.com`. Override for staging/self-hosted SSO. |
| `expected_audience` | `str \| Literal[False] \| None` | Defaults to `expected_issuer` (federated audience). Pass a string to scope to a specific OAuth `client_id` or RFC 8707 resource. Pass `False` to skip (test fixtures only). |
| `proof_max_age_sec` | `int` | DPoP proof freshness window. Default `30`. |
| `clock_skew_sec` | `int` | Clock skew applied to access-token `exp`. Default `30`. |
| `jti_store` | `DPoPJtiStore \| None` | Replay-protection store. Default: in-memory dict scoped to this import (capped at 10,000 entries). |

**On success returns `VerifyDPoPSuccess`:**

```python
@dataclass(frozen=True)
class VerifyDPoPSuccess:
    sub: str                          # owner sub (from at+jwt)
    jkt: str                          # RFC 7638 thumbprint of the agent's DPoP key
    access_token_claims: dict
    proof_claims: dict
    ok: bool = True
```

**On failure returns `VerifyDPoPFailure`:**

```python
@dataclass(frozen=True)
class VerifyDPoPFailure:
    code: str    # machine-readable, e.g. "jkt_mismatch"
    error: str   # human-readable
    ok: bool = False
```

### `fetch_alien_jwks(sso_base_url="https://sso.alien-api.com")`

Fetch the JWKS from the Alien SSO server. Callers should cache the result.

Returns a `JWKS` (TypedDict with a `keys` list of `JWK` entries).

### `DPoPJtiStore`

Pluggable Protocol for proof-replay protection (RFC 9449 §11.1):

```python
class DPoPJtiStore(Protocol):
    def has(self, jti: str) -> bool: ...
    def add(self, jti: str, iat: int) -> None: ...
```

The default in-memory store is single-process and capped at 10,000 entries.
For multi-instance deployments, back it with Redis/Memcached so a captured
proof can't be replayed against a different worker.

## Framework examples

### FastAPI

```python
from fastapi import Depends, FastAPI

from alien_sso_agent_id import VerifyDPoPSuccess, fetch_alien_jwks
from alien_sso_agent_id.fastapi import build_require_dpop

app = FastAPI()
require_dpop = build_require_dpop(jwks=fetch_alien_jwks())

@app.get("/me")
def me(auth: VerifyDPoPSuccess = Depends(require_dpop)):
    return {"sub": auth.sub, "jkt": auth.jkt}
```

`build_require_dpop` emits 401 with
`WWW-Authenticate: DPoP error="invalid_token", error_description="<code>"` on
every verification failure.

### Flask

```python
from flask import Flask, request, jsonify, g
from alien_sso_agent_id import VerifyDPoPOptions, fetch_alien_jwks, verify_dpop_request

app = Flask(__name__)
JWKS = fetch_alien_jwks()

@app.before_request
def require_dpop():
    result = verify_dpop_request(
        {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
        },
        VerifyDPoPOptions(jwks=JWKS),
    )
    if not result.ok:
        resp = jsonify(error=result.error)
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = f'DPoP error="{result.code}"'
        return resp
    g.agent = result
```

### Starlette

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from alien_sso_agent_id import VerifyDPoPOptions, fetch_alien_jwks, verify_dpop_request

JWKS = fetch_alien_jwks()

class DPoPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        result = verify_dpop_request(
            {
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
            },
            VerifyDPoPOptions(jwks=JWKS),
        )
        if not result.ok:
            return JSONResponse(
                {"error": result.error},
                status_code=401,
                headers={"WWW-Authenticate": f'DPoP error="{result.code}"'},
            )
        request.state.agent = result
        return await call_next(request)

app = Starlette(middleware=[Middleware(DPoPMiddleware)])
```

If your service sits behind a reverse proxy (ALB, Cloudflare, nginx), trust
`X-Forwarded-Proto` and `X-Forwarded-Host` to reconstruct the URL the agent
actually addressed — otherwise `htu` comparison will fail.

## Access control patterns

### Any owner-bound agent

```python
if not result.ok:
    raise HTTPException(401, detail=result.error)
# result.sub is guaranteed by the SSO's signature.
```

### Allow-list by agent key

```python
ALLOWED_JKTS = {"wEf6o2ux8sBAUG4oQYhP284gfpZwUJMTxXDPH5XxthY", ...}
if result.jkt not in ALLOWED_JKTS:
    raise HTTPException(403, detail="Agent not authorized")
```

### Allow-list by owner

```python
ALLOWED_OWNERS = {"00000003...", "00000003..."}
if result.sub not in ALLOWED_OWNERS:
    raise HTTPException(403, detail="Owner not authorized")
```

## How it works

Every fact the service trusts is signed either by the SSO (over standard
RFC 9068 access-token claims) or by the agent (over the per-request RFC 9449
DPoP proof). There is no parallel envelope: no `ownerBinding`, no
`idTokenHash`, no agent-issued attestation of `sub`. The cnf-binding ties the
SSO-attested owner to the per-request proof-of-possession.

## Error codes

`result.code` values map to RFC 9449 / RFC 9068 / RFC 6750 categories. Stable
across releases; new values may be added. Codes match the JS package verbatim
so cross-language callers can compare for equality.

| Code | RFC | Meaning |
| --- | --- | --- |
| `missing_authorization` | RFC 9449 §4.3 step 1 | Missing or duplicate `Authorization` header |
| `invalid_scheme` | RFC 9449 §7.1 | Not `Authorization: DPoP <token>` |
| `missing_dpop` | RFC 9449 §4.3 step 1 | Missing or duplicate `DPoP` header |
| `malformed_proof` | §4.3 step 2 | DPoP value is not a well-formed JWS |
| `bad_proof_typ` | §4.3 step 4 | `typ` ≠ `dpop+jwt` |
| `bad_proof_alg` | §4.3 step 5 | `alg` ≠ `EdDSA` (Alien agent keys are Ed25519) |
| `missing_proof_jwk` / `bad_proof_jwk` | §4.3 step 6 | Header `jwk` missing or not OKP/Ed25519 |
| `private_in_proof_jwk` | §4.3 step 6 | Proof leaks the private `d` member |
| `bad_proof_signature` | §4.3 step 7 | Signature does not verify with the embedded `jwk` |
| `bad_proof_htm` | §4.3 step 8 | `htm` ≠ request method |
| `bad_proof_htu` | §4.3 step 9 | `htu` ≠ request URL (query/fragment stripped) |
| `bad_proof_iat` / `stale_proof` / `future_proof` | §4.3 step 11 | Proof `iat` is malformed or outside the freshness window |
| `missing_proof_jti` / `replayed_proof_jti` | §4.3 step 12 + §11.1 | Proof lacks `jti` or it's been seen before |
| `bad_proof_ath` | §4.3 step 10 | `ath` ≠ SHA-256(access_token) |
| `malformed_access_token` | RFC 9068 §4 | Access-token is not a well-formed JWS |
| `bad_access_token_typ` | RFC 9068 §4 | Access-token `typ` ≠ `at+jwt` |
| `bad_access_token_alg` | RFC 9068 §4 | Access-token `alg` ≠ `RS256` |
| `unknown_access_token_kid` | RFC 7515 | Access-token's `kid` not in the JWKS |
| `bad_access_token_signature` / `access_token_sig_error` | RFC 7515 | Access-token signature fails verification |
| `bad_access_token_iss` | RFC 7519 §4.1.1 | `iss` ≠ `expected_issuer` |
| `bad_access_token_aud` | RFC 7519 §4.1.3 | `aud` does not include `expected_audience` |
| `expired_access_token` | RFC 7519 §4.1.4 | Access-token `exp` is in the past |
| `missing_access_token_sub` | RFC 7519 §4.1.2 | Access-token has no `sub` claim |
| `missing_cnf_jkt` | RFC 7800 §3.1 | Access-token has no `cnf.jkt` (not DPoP-bound) |
| `jkt_mismatch` | RFC 9449 §6.1 | `cnf.jkt` ≠ thumbprint of the proof's `jwk` |

## Caveats

- **Pre-fetched JWKS.** `fetch_alien_jwks()` does not cache. Call it at
  startup, hold the result, refresh every few hours. The SSO rotates signing
  keys infrequently.
- **Reverse proxies.** If your service runs behind a load balancer or CDN,
  reconstruct the URL the agent actually addressed (using
  `X-Forwarded-Proto` / `X-Forwarded-Host`) — otherwise the `htu` comparison
  will reject every request.
- **jti replay store.** The default in-memory store is single-process. Inject
  a shared `jti_store` for multi-instance deployments so a captured proof
  can't be replayed against a different worker.
- **Clock sync.** The 30-second default freshness window assumes loosely
  synchronized clocks. Tighten via `proof_max_age_sec` / `clock_skew_sec` if
  you have stricter NTP, widen if you have flakier clocks.

## Additional resources

- [Alien Agent ID docs](https://docs.alien.org/agent-id-guide/introduction)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 7800 — Proof-of-Possession Key Semantics for JWTs](https://www.rfc-editor.org/rfc/rfc7800)

## License

MIT.
