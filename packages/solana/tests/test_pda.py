"""PDA derivation parity tests.

The JS SDK has no PDA tests checked in (the package's `test` script just runs
`jest --passWithNoTests`), so we use solders' deterministic
`find_program_address` to assert the expected outputs. If anything ever
re-derives the seeds, this test catches the drift.
"""

from __future__ import annotations

from solders.pubkey import Pubkey

from alien_sso_solana import (
    derive_attestation_pda,
    derive_credential_pda,
    derive_credential_signer_pda,
    derive_program_state_pda,
    derive_schema_pda,
    derive_session_entry_pda,
    derive_session_registry_pda,
    derive_solana_entry_pda,
)

CREDENTIAL_SIGNER = Pubkey.from_string("9cstDz8WWRAFaq1vVpTjfHz6tjgh6SJaqYFeZWi1pFHG")
SAS = Pubkey.from_string("22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG")
SESSION_REGISTRY = Pubkey.from_string("DeHa6pyZ2CFSbQQiNMm7FgoCXqmkX6tXG77C4Qycpta6")


def _equiv(seeds: list[bytes], program: Pubkey) -> Pubkey:
    addr, _ = Pubkey.find_program_address(seeds, program)
    return addr


def test_program_state():
    addr, _ = derive_program_state_pda(CREDENTIAL_SIGNER)
    assert addr == _equiv([b"program_state"], CREDENTIAL_SIGNER)


def test_credential_signer():
    addr, _ = derive_credential_signer_pda(CREDENTIAL_SIGNER)
    assert addr == _equiv([b"credential_signer"], CREDENTIAL_SIGNER)


def test_session_registry():
    addr, _ = derive_session_registry_pda(SESSION_REGISTRY)
    assert addr == _equiv([b"session_registry"], SESSION_REGISTRY)


def test_session_entry():
    sa = "session-id-1"
    addr, _ = derive_session_entry_pda(sa, SESSION_REGISTRY)
    assert addr == _equiv([b"session", sa.encode("utf-8")], SESSION_REGISTRY)


def test_solana_entry():
    wallet = Pubkey.from_string("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
    addr, _ = derive_solana_entry_pda(wallet, SESSION_REGISTRY)
    assert addr == _equiv([b"solana", bytes(wallet)], SESSION_REGISTRY)


def test_attestation():
    cred = Pubkey.from_string("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
    schema = Pubkey.from_string("9MWmtcNw78r9pmTsbqsZ8aw9w1J4StPhU1J6kpKfqkj1")
    nonce = Pubkey.from_string("11111111111111111111111111111111")
    addr, _ = derive_attestation_pda(cred, schema, nonce, SAS)
    assert addr == _equiv(
        [b"attestation", bytes(cred), bytes(schema), bytes(nonce)],
        SAS,
    )


def test_credential():
    auth = Pubkey.from_string("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
    addr, _ = derive_credential_pda(auth, "alien-credential", SAS)
    assert addr == _equiv(
        [b"credential", bytes(auth), b"alien-credential"], SAS
    )


def test_schema():
    cred = Pubkey.from_string("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
    addr, _ = derive_schema_pda(cred, "session", 1, SAS)
    assert addr == _equiv(
        [b"schema", bytes(cred), b"session", bytes([1])], SAS
    )


def test_schema_rejects_out_of_range_version():
    cred = Pubkey.from_string("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
    import pytest
    with pytest.raises(ValueError):
        derive_schema_pda(cred, "session", 256, SAS)
