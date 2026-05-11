"""AlienSolanaSsoClient — Python port of `packages/solanaCore/src/client.ts`.

The HTTP methods (`generate_deeplink`, `poll_auth`, `get_attestation`) are
async — they hit the SSO server. The transaction-building method
(`build_create_attestation_message`) is synchronous since it's pure CPU; pass
the on-chain ProgramState bytes you fetched yourself, e.g. with `solana-py`:

    from solana.rpc.api import Client
    rpc = Client("https://api.devnet.solana.com")
    state_pda, _ = derive_program_state_pda(client.credential_signer_program_id)
    program_state_data = rpc.get_account_info(state_pda).value.data

Returns an unsigned `solders.message.Message` ready for the caller to wrap in
a `Transaction`, sign, and send.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.sysvar import INSTRUCTIONS as SYSVAR_INSTRUCTIONS

from alien_sso_solana._ed25519_program import create_ed25519_verify_instruction
from alien_sso_solana.errors import AlienSolanaSsoError
from alien_sso_solana.pda import (
    derive_attestation_pda,
    derive_credential_signer_pda,
    derive_program_state_pda,
    derive_session_entry_pda,
    derive_session_registry_pda,
    derive_solana_entry_pda,
)
from alien_sso_solana.schema import (
    SolanaAttestationResponse,
    SolanaLinkResponse,
    SolanaPollResponse,
)

DEFAULT_SSO_BASE_URL = "https://sso.alien-api.com"
DEFAULT_POLLING_INTERVAL = 5.0

DEFAULT_CREDENTIAL_SIGNER_PROGRAM_ID = "9cstDz8WWRAFaq1vVpTjfHz6tjgh6SJaqYFeZWi1pFHG"
DEFAULT_SESSION_REGISTRY_PROGRAM_ID = "DeHa6pyZ2CFSbQQiNMm7FgoCXqmkX6tXG77C4Qycpta6"
DEFAULT_SAS_PROGRAM_ID = "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG"

# create_attestation Anchor discriminator (first 8 bytes of sighash).
_CREATE_ATTESTATION_DISCRIMINATOR = bytes([49, 24, 67, 80, 12, 249, 96, 239])

# `ProgramState` account layout (bytes after the 8-byte discriminator):
#   0..32   oracle_pubkey
#   32..64  credential_pda      ← needed
#   64..96  schema_pda          ← needed
#   96..    (event_authority, authority, session_registry — unused here)
_DISCRIMINATOR_LEN = 8

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


@dataclass(frozen=True)
class AlienSolanaSsoClientConfig:
    sso_base_url: str
    provider_address: str
    polling_interval: float = DEFAULT_POLLING_INTERVAL
    credential_signer_program_id: str = DEFAULT_CREDENTIAL_SIGNER_PROGRAM_ID
    sas_program_id: str = DEFAULT_SAS_PROGRAM_ID
    session_registry_program_id: str = DEFAULT_SESSION_REGISTRY_PROGRAM_ID


class AlienSolanaSsoClient:
    """Synchronous Alien Solana SSO client."""

    def __init__(
        self,
        config: AlienSolanaSsoClientConfig,
        *,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not config.sso_base_url:
            raise ValueError("sso_base_url is required")
        _require_secure_base_url(config.sso_base_url)
        if not config.provider_address:
            raise ValueError("provider_address is required")
        self.config = config
        self.sso_base_url = config.sso_base_url
        self.provider_address = config.provider_address
        self.polling_interval = config.polling_interval
        self.credential_signer_program_id = Pubkey.from_string(
            config.credential_signer_program_id
        )
        self.sas_program_id = Pubkey.from_string(config.sas_program_id)
        self.session_registry_program_id = Pubkey.from_string(
            config.session_registry_program_id
        )
        self._http = http_client or httpx.AsyncClient(timeout=10.0)
        self._owns_http = http_client is None

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AlienSolanaSsoClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    # ─── HTTP endpoints ─────────────────────────────────────────────────

    async def generate_deeplink(self, solana_address: str) -> SolanaLinkResponse:
        """POST /solana/link — start the wallet link flow."""
        resp = await self._http.post(
            self._url("/solana/link"),
            json={"solana_address": solana_address},
            headers=self._headers(),
        )
        if resp.status_code >= 400:
            raise AlienSolanaSsoError(f"GenerateLinkDeeplink failed: {resp.reason_phrase}")
        return SolanaLinkResponse.from_json(resp.json())

    async def poll_auth(self, polling_code: str) -> SolanaPollResponse:
        """POST /solana/poll — check whether the user has signed yet."""
        resp = await self._http.post(
            self._url("/solana/poll"),
            json={"polling_code": polling_code},
            headers=self._headers(),
        )
        if resp.status_code >= 400:
            raise AlienSolanaSsoError(f"Poll failed: {resp.reason_phrase}")
        return SolanaPollResponse.from_json(resp.json())

    async def get_attestation(self, solana_address: str) -> Optional[str]:
        """POST /solana/attestation. Returns the session address, or None on 404."""
        resp = await self._http.post(
            self._url("/solana/attestation"),
            json={"solana_address": solana_address},
            headers=self._headers(),
        )
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise AlienSolanaSsoError(f"GetAttestation failed: {resp.reason_phrase}")
        return SolanaAttestationResponse.from_json(resp.json()).session_address

    # ─── Transaction building ───────────────────────────────────────────

    def build_create_attestation_message(
        self,
        *,
        program_state_data: bytes,
        payer_public_key: Pubkey,
        session_address: str,
        oracle_signature: bytes,
        oracle_public_key: Pubkey,
        timestamp: int,
        expiry: int,
        recent_blockhash: Optional[object] = None,
    ) -> Message:
        """Build the create-attestation message (Ed25519 verify + create_attestation).

        Pass `recent_blockhash` (a `solders.hash.Hash`) when you have one, or
        leave it None to get a Message you can finalize later.
        """
        if len(program_state_data) < _DISCRIMINATOR_LEN + 96:
            raise AlienSolanaSsoError("ProgramState account too small")

        body = program_state_data[_DISCRIMINATOR_LEN:]
        credential_address = Pubkey(body[32:64])
        schema_address = Pubkey(body[64:96])

        program_state_pda, _ = derive_program_state_pda(self.credential_signer_program_id)
        credential_signer_pda, _ = derive_credential_signer_pda(self.credential_signer_program_id)
        session_registry_pda, _ = derive_session_registry_pda(self.session_registry_program_id)
        session_entry_pda, _ = derive_session_entry_pda(
            session_address, self.session_registry_program_id
        )
        solana_entry_pda, _ = derive_solana_entry_pda(
            payer_public_key, self.session_registry_program_id
        )
        attestation_pda, _ = derive_attestation_pda(
            credential_address, schema_address, payer_public_key, self.sas_program_id
        )

        oracle_message = (
            session_address.encode("utf-8")
            + str(payer_public_key).encode("utf-8")
            + struct.pack("<q", timestamp)
        )

        ed25519_ix = create_ed25519_verify_instruction(
            public_key=bytes(oracle_public_key),
            message=oracle_message,
            signature=oracle_signature,
        )

        data = self._serialize_create_attestation(
            session_address, oracle_signature, expiry, timestamp
        )

        create_ix = Instruction(
            program_id=self.credential_signer_program_id,
            accounts=[
                AccountMeta(pubkey=program_state_pda, is_signer=False, is_writable=False),
                AccountMeta(pubkey=credential_signer_pda, is_signer=False, is_writable=False),
                AccountMeta(pubkey=payer_public_key, is_signer=True, is_writable=True),
                AccountMeta(pubkey=credential_address, is_signer=False, is_writable=False),
                AccountMeta(pubkey=schema_address, is_signer=False, is_writable=False),
                AccountMeta(pubkey=attestation_pda, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.sas_program_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_INSTRUCTIONS, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.session_registry_program_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=session_registry_pda, is_signer=False, is_writable=True),
                AccountMeta(pubkey=session_entry_pda, is_signer=False, is_writable=True),
                AccountMeta(pubkey=solana_entry_pda, is_signer=False, is_writable=True),
            ],
            data=data,
        )

        if recent_blockhash is not None:
            return Message.new_with_blockhash([ed25519_ix, create_ix], payer_public_key, recent_blockhash)  # type: ignore[arg-type]
        return Message.new_with_blockhash([ed25519_ix, create_ix], payer_public_key, _ZERO_HASH)

    # ─── Internals ──────────────────────────────────────────────────────

    @staticmethod
    def _serialize_create_attestation(
        session_address: str,
        oracle_signature: bytes,
        expiry: int,
        timestamp: int,
    ) -> bytes:
        sa = session_address.encode("utf-8")
        return (
            _CREATE_ATTESTATION_DISCRIMINATOR
            + struct.pack("<I", len(sa))
            + sa
            + bytes(oracle_signature)
            + struct.pack("<q", expiry)
            + struct.pack("<q", timestamp)
        )

    def _url(self, path: str) -> str:
        base = self.sso_base_url
        if not base.endswith("/"):
            base = base + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-PROVIDER-ADDRESS": self.provider_address,
        }


# Build a placeholder hash for the message-without-blockhash case. The caller
# is expected to overwrite this before sending.
from solders.hash import Hash as _Hash

_ZERO_HASH = _Hash.default()
