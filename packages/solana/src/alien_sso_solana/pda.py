"""PDA derivation helpers — port of `packages/solanaCore/src/pda.ts`.

Each helper returns `(Pubkey, bump)` for the corresponding seed pattern.
"""

from __future__ import annotations

from solders.pubkey import Pubkey


def derive_program_state_pda(credential_program_id: Pubkey) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address([b"program_state"], credential_program_id)


def derive_credential_signer_pda(credential_program_id: Pubkey) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address([b"credential_signer"], credential_program_id)


def derive_session_registry_pda(session_registry_program_id: Pubkey) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address([b"session_registry"], session_registry_program_id)


def derive_session_entry_pda(
    session_address: str, session_registry_program_id: Pubkey
) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address(
        [b"session", session_address.encode("utf-8")],
        session_registry_program_id,
    )


def derive_solana_entry_pda(
    wallet_public_key: Pubkey, session_registry_program_id: Pubkey
) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address(
        [b"solana", bytes(wallet_public_key)],
        session_registry_program_id,
    )


def derive_attestation_pda(
    credential: Pubkey,
    schema: Pubkey,
    nonce: Pubkey,
    sas_program_id: Pubkey,
) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address(
        [b"attestation", bytes(credential), bytes(schema), bytes(nonce)],
        sas_program_id,
    )


def derive_credential_pda(
    authority: Pubkey, name: str, sas_program_id: Pubkey
) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address(
        [b"credential", bytes(authority), name.encode("utf-8")],
        sas_program_id,
    )


def derive_schema_pda(
    credential: Pubkey, name: str, version: int, sas_program_id: Pubkey
) -> tuple[Pubkey, int]:
    if not (0 <= version <= 255):
        raise ValueError("schema version must fit in u8")
    return Pubkey.find_program_address(
        [b"schema", bytes(credential), name.encode("utf-8"), bytes([version])],
        sas_program_id,
    )
