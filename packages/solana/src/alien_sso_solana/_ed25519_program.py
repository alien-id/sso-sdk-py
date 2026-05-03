"""Build a Solana ed25519-verify native-program instruction by hand.

`solders` doesn't export an ed25519 program helper, so we encode the well-known
fixed layout ourselves. Mirrors `Ed25519Program.createInstructionWithPublicKey`
from `@solana/web3.js`.

Layout (single signature):

    offset 0     : num_signatures (u8) = 1
    offset 1     : padding (u8)        = 0
    offset 2..4  : signature_offset (u16 LE)
    offset 4..6  : signature_instruction_index (u16 LE) = 0xFFFF (current ix)
    offset 6..8  : public_key_offset (u16 LE)
    offset 8..10 : public_key_instruction_index (u16 LE) = 0xFFFF
    offset 10..12: message_data_offset (u16 LE)
    offset 12..14: message_data_size (u16 LE)
    offset 14..16: message_instruction_index (u16 LE) = 0xFFFF
    offset 16..48: public_key (32 bytes)
    offset 48..112: signature (64 bytes)
    offset 112.. : message bytes
"""

from __future__ import annotations

import struct

from solders.instruction import Instruction
from solders.pubkey import Pubkey

ED25519_PROGRAM_ID = Pubkey.from_string("Ed25519SigVerify111111111111111111111111111")

_PUBKEY_LEN = 32
_SIGNATURE_LEN = 64
_HEADER_LEN = 16
_PUBKEY_OFFSET = _HEADER_LEN
_SIGNATURE_OFFSET = _PUBKEY_OFFSET + _PUBKEY_LEN
_INSTRUCTION_DATA_INDEX = 0xFFFF


def create_ed25519_verify_instruction(
    *,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> Instruction:
    if len(public_key) != _PUBKEY_LEN:
        raise ValueError(f"public_key must be {_PUBKEY_LEN} bytes")
    if len(signature) != _SIGNATURE_LEN:
        raise ValueError(f"signature must be {_SIGNATURE_LEN} bytes")

    message_offset = _SIGNATURE_OFFSET + _SIGNATURE_LEN
    data = bytearray(message_offset + len(message))

    # Header
    data[0] = 1  # num_signatures
    data[1] = 0  # padding
    struct.pack_into(
        "<HHHHHHH",
        data,
        2,
        _SIGNATURE_OFFSET,
        _INSTRUCTION_DATA_INDEX,
        _PUBKEY_OFFSET,
        _INSTRUCTION_DATA_INDEX,
        message_offset,
        len(message),
        _INSTRUCTION_DATA_INDEX,
    )

    data[_PUBKEY_OFFSET:_PUBKEY_OFFSET + _PUBKEY_LEN] = public_key
    data[_SIGNATURE_OFFSET:_SIGNATURE_OFFSET + _SIGNATURE_LEN] = signature
    data[message_offset:message_offset + len(message)] = message

    return Instruction(program_id=ED25519_PROGRAM_ID, accounts=[], data=bytes(data))
