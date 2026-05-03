"""Alien SSO — Solana wallet linking + attestations.

Python port of `@alien-id/sso-solana`. Mirrors the JS API surface, with the
following adjustments:

- Ed25519 native-program instruction is built by hand (solders doesn't ship a
  helper) — the format is the documented Solana ed25519-verify layout.
- `build_create_attestation_transaction` accepts the on-chain
  `program_state_data` as raw bytes rather than taking a `Connection`. Fetch
  it yourself with whatever RPC client you prefer (`solana-py`, raw httpx,
  etc.) — see the README for an example.
"""

from alien_sso_solana.client import (
    AlienSolanaSsoClient,
    AlienSolanaSsoClientConfig,
)
from alien_sso_solana.errors import AlienSolanaSsoError
from alien_sso_solana.pda import (
    derive_attestation_pda,
    derive_credential_pda,
    derive_credential_signer_pda,
    derive_program_state_pda,
    derive_schema_pda,
    derive_session_entry_pda,
    derive_session_registry_pda,
    derive_solana_entry_pda,
)
from alien_sso_solana.schema import (
    SolanaAttestationRequest,
    SolanaAttestationResponse,
    SolanaLinkRequest,
    SolanaLinkResponse,
    SolanaPollRequest,
    SolanaPollResponse,
    SolanaPollStatus,
)

__all__ = [
    "AlienSolanaSsoClient",
    "AlienSolanaSsoClientConfig",
    "AlienSolanaSsoError",
    "SolanaAttestationRequest",
    "SolanaAttestationResponse",
    "SolanaLinkRequest",
    "SolanaLinkResponse",
    "SolanaPollRequest",
    "SolanaPollResponse",
    "SolanaPollStatus",
    "derive_attestation_pda",
    "derive_credential_pda",
    "derive_credential_signer_pda",
    "derive_program_state_pda",
    "derive_schema_pda",
    "derive_session_entry_pda",
    "derive_session_registry_pda",
    "derive_solana_entry_pda",
]
