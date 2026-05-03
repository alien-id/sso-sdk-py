# Alien SSO SDK for Python

Python port of [`@alien-id/sso-sdk-js`](https://github.com/alien-id/sso-sdk-js).
A `uv` workspace with one package per domain.

| Package | PyPI | What it does |
| --- | --- | --- |
| [`alien-sso-agent-id`](packages/agent-id) | `alien-sso-agent-id` | Verify Alien Agent ID tokens (Ed25519 + RS256 owner chain). Sync — pure crypto. |
| [`alien-sso`](packages/core) | `alien-sso` | Async OAuth2 PKCE client for Alien SSO — deeplink, poll, exchange, refresh, JWT parse. |
| [`alien-sso-solana`](packages/solana) | `alien-sso-solana` | Async Solana wallet linking + sync PDA derivation + sync attestation transaction building. |
| [`alien-sso-jinja`](packages/jinja-ui) | `alien-sso-jinja` | Async framework-agnostic SSR sign-in button + QR modal (Jinja templates + tiny vanilla JS). Replaces the JS `@alien-id/sso-react` package. |

HTTP-touching code is `async def`; CPU-only code (verification, PDA
derivation, transaction building, JWT decoding) is sync.

Each package has its own `README.md` and ships independently.

## Layout

```
packages/
├── agent-id/    — alien_sso_agent_id   (port of @alien-id/sso-agent-id)
├── core/        — alien_sso             (port of @alien-id/sso)
├── solana/      — alien_sso_solana      (port of @alien-id/sso-solana)
└── jinja-ui/    — alien_sso_jinja       (replacement for @alien-id/sso-react + sso-solana-react)
```

## Develop

```bash
uv sync
uv run pytest
```

Per-package tests:

```bash
uv run pytest packages/agent-id
uv run pytest packages/core
uv run pytest packages/solana
```

## License

MIT — see [LICENSE](LICENSE).
