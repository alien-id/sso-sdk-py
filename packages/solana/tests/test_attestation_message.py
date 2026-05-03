"""End-to-end-ish test for `build_create_attestation_message`.

We synthesize a minimal ProgramState account, call into the builder, and
verify that the returned Message contains exactly the two instructions we
expect (Ed25519 verify + create_attestation), with the correct program IDs
and account counts.
"""

from __future__ import annotations

import struct

from solders.pubkey import Pubkey

from alien_sso_solana import AlienSolanaSsoClient, AlienSolanaSsoClientConfig
from alien_sso_solana._ed25519_program import ED25519_PROGRAM_ID

PAYER = Pubkey.from_string("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
ORACLE = Pubkey.from_string("9MWmtcNw78r9pmTsbqsZ8aw9w1J4StPhU1J6kpKfqkj1")
CREDENTIAL = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
SCHEMA = Pubkey.from_string("So11111111111111111111111111111111111111112")


def _fake_program_state() -> bytes:
    # 8-byte discriminator + oracle (32) + credential (32) + schema (32) +
    # event_authority (32) + authority (32) + session_registry (32)
    return (
        bytes(8)
        + bytes(ORACLE)
        + bytes(CREDENTIAL)
        + bytes(SCHEMA)
        + bytes(32) * 3
    )


def test_builds_message_with_two_instructions():
    cfg = AlienSolanaSsoClientConfig(
        sso_base_url="http://sso.test",
        provider_address="00000001000000000000000000000000",
    )
    client = AlienSolanaSsoClient(cfg)

    msg = client.build_create_attestation_message(
        program_state_data=_fake_program_state(),
        payer_public_key=PAYER,
        session_address="11111111111111111111111111111111",
        oracle_signature=bytes(64),
        oracle_public_key=ORACLE,
        timestamp=1700000000,
        expiry=1800000000,
    )

    assert len(msg.instructions) == 2
    ed25519_ix = msg.instructions[0]
    create_ix = msg.instructions[1]

    # The Message normalizes program ids into account_keys and replaces the
    # Instruction's program_id with the index. Look it up.
    keys = list(msg.account_keys)
    assert keys[ed25519_ix.program_id_index] == ED25519_PROGRAM_ID
    assert keys[create_ix.program_id_index] == client.credential_signer_program_id

    # The create_attestation instruction must reference the 13 accounts the
    # JS SDK passes.
    assert len(create_ix.accounts) == 13

    # The instruction data must start with the Anchor discriminator.
    assert bytes(create_ix.data)[:8] == bytes([49, 24, 67, 80, 12, 249, 96, 239])

    # And carry the correct expiry / timestamp at the tail.
    data = bytes(create_ix.data)
    expiry = struct.unpack_from("<q", data, len(data) - 16)[0]
    timestamp = struct.unpack_from("<q", data, len(data) - 8)[0]
    assert expiry == 1800000000
    assert timestamp == 1700000000


def test_rejects_program_state_too_small():
    import pytest
    from alien_sso_solana import AlienSolanaSsoError

    cfg = AlienSolanaSsoClientConfig(
        sso_base_url="http://sso.test", provider_address="prov"
    )
    client = AlienSolanaSsoClient(cfg)
    with pytest.raises(AlienSolanaSsoError):
        client.build_create_attestation_message(
            program_state_data=b"too small",
            payer_public_key=PAYER,
            session_address="x",
            oracle_signature=bytes(64),
            oracle_public_key=ORACLE,
            timestamp=0,
            expiry=0,
        )
