# alien-sso-agent-id

> Verify Alien Agent ID tokens in Python services. Ed25519 signature
> verification, full owner chain verification via Alien SSO. Python port of
> [`@alien-id/sso-agent-id`](https://www.npmjs.com/package/@alien-id/sso-agent-id).

---

## Install

```bash
pip install alien-sso-agent-id
# or, with the FastAPI dependency wired up:
pip install "alien-sso-agent-id[fastapi]"
```

Requires Python 3.11+ and `cryptography` (the only runtime dep).

## Quick start

Verify an agent's identity **and** that their claimed owner is real:

```python
from alien_sso_agent_id import (
    fetch_alien_jwks,
    verify_agent_request_with_owner,
    VerifyOwnerOptions,
)

# Fetch JWKS at startup and cache it
JWKS = fetch_alien_jwks()

# In your request handler — `req` can be any object with a `.headers` mapping
result = verify_agent_request_with_owner(req, VerifyOwnerOptions(jwks=JWKS))
if not result.ok:
    return 401, {"error": result.error}

# result.fingerprint           — stable agent identity
# result.owner                 — human owner's AlienID address
# result.owner_verified        — True: cryptographically proven via Alien SSO
# result.issuer                — "https://sso.alien-api.com"
```

This verifies the full trust chain: agent key → owner binding → id_token →
Alien SSO JWKS → verified human. The `owner` field is not just self-asserted
— it's backed by the SSO server's RS256 signature.

## Basic verification (no owner proof)

```python
from alien_sso_agent_id import verify_agent_request

result = verify_agent_request(req)
if not result.ok:
    return 401, {"error": result.error}
# result.owner_verified is False — do not trust result.owner for access control
```

## API

| Function | Purpose |
| --- | --- |
| `verify_agent_token(token_b64, opts=None)` | Verify a base64url-JSON token string. |
| `verify_agent_token_with_owner(token_b64, opts)` | Verify a token + owner chain against the supplied JWKS. |
| `verify_agent_request(req, opts=None)` | Pull the token from `req.headers.authorization` and verify. |
| `verify_agent_request_with_owner(req, opts)` | Same, with full owner-chain verification. |
| `fetch_alien_jwks(sso_base_url=...)` | Fetch the JWKS from the SSO server. Cache the result. |

The `req` argument accepts anything with a `headers` mapping — Starlette
`Request`, Flask `request`, raw `dict`s, etc.

### Options

```python
from alien_sso_agent_id import VerifyOptions, VerifyOwnerOptions

verify_agent_token(token, VerifyOptions(max_age_ms=60_000, clock_skew_ms=10_000))
verify_agent_token_with_owner(token, VerifyOwnerOptions(jwks=JWKS, max_age_ms=60_000))
```

| Option | Default | Description |
| --- | --- | --- |
| `max_age_ms` | `300000` (5 min) | Reject tokens older than this. |
| `clock_skew_ms` | `30000` (30 sec) | Allow tokens this far in the future. |

## FastAPI

```python
from fastapi import Depends, FastAPI
from alien_sso_agent_id import AgentIdentity, fetch_alien_jwks
from alien_sso_agent_id.fastapi import build_require_agent

app = FastAPI()
JWKS = fetch_alien_jwks()
require_agent = build_require_agent(jwks=JWKS, owner_required=True)

@app.get("/me")
def me(ident: AgentIdentity = Depends(require_agent)):
    return {"fingerprint": ident.fingerprint, "owner": ident.owner}
```

## How it works

```text
Agent ─signs payload with Ed25519─► Service ─verifies sig + freshness
                                          │
                                          └► (optional) verify owner binding,
                                             id_token RS256 signature against
                                             Alien SSO JWKS, sub == owner.
```

The token is **self-contained**: it carries the agent's public key and the
full owner-proof chain, so verification needs no database lookup, no key
exchange, and no pre-registration.

## Error reference

Identical to the JS package — error strings are preserved verbatim so you can
share log filters and access-control rules across implementations:
`Invalid token encoding`, `Unsupported token version: N`,
`Token expired (age: Ns)`, `Invalid public key in token`,
`Fingerprint does not match public key`, `Signature verification failed`,
`Missing field: ownerBinding`, `Missing field: idToken`,
`Owner binding signature verification failed`,
`Owner binding agent fingerprint mismatch`,
`Owner binding ownerSessionSub mismatch`,
`id_token hash does not match owner binding`,
`id_token signature verification failed`,
`id_token sub does not match token owner`.

## License

MIT.
