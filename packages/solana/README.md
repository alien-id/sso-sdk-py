# alien-sso-solana

Python port of [`@alien-id/sso-solana`](https://www.npmjs.com/package/@alien-id/sso-solana).
Solana wallet linking, PDA derivation, and create-attestation transaction
building for Alien SSO.

## Install

```bash
pip install alien-sso-solana
```

Pulls in `solders` (PyO3 bindings to Rust) for Pubkey/Instruction/Message
types and `httpx` for the SSO HTTP calls.

## Quick start

```python
import asyncio
from alien_sso_solana import (
    AlienSolanaSsoClient,
    AlienSolanaSsoClientConfig,
    derive_program_state_pda,
)
from solders.keypair import Keypair
from solana.rpc.api import Client as RpcClient   # solana-py, optional

async def main():
    cfg = AlienSolanaSsoClientConfig(
        sso_base_url="https://sso.alien.com",
        provider_address="<your-provider>",
    )
    payer = Keypair()

    async with AlienSolanaSsoClient(cfg) as sso:
        # 1. Start a wallet-link flow
        link = await sso.generate_deeplink(str(payer.pubkey()))
        print("Open in Alien app:", link.deep_link)

        # 2. Poll until authorized
        while True:
            poll = await sso.poll_auth(link.polling_code)
            if poll.status.value == "authorized":
                break
            await asyncio.sleep(sso.polling_interval)

        # 3. Build the create-attestation message (sync — pure CPU).
        #    Fetch the on-chain ProgramState account using whatever Solana RPC
        #    client you prefer — here, solana-py:
        rpc = RpcClient("https://api.mainnet-beta.solana.com")
        state_pda, _ = derive_program_state_pda(sso.credential_signer_program_id)
        state_data = rpc.get_account_info(state_pda).value.data

        msg = sso.build_create_attestation_message(
            program_state_data=state_data,
            payer_public_key=payer.pubkey(),
            session_address=poll.session_address,
            oracle_signature=bytes.fromhex(poll.oracle_signature),
            oracle_public_key=...,           # parse poll.oracle_public_key
            timestamp=poll.timestamp,
            expiry=poll.timestamp + 3600,
            recent_blockhash=rpc.get_latest_blockhash().value.blockhash,
        )

        # 4. Sign + send
        from solders.transaction import Transaction
        tx = Transaction([payer], msg, msg.recent_blockhash)
        rpc.send_transaction(tx)

asyncio.run(main())
```

## API

### Client

Async (HTTP):

| Method | Description |
| --- | --- |
| `await generate_deeplink(solana_address)` | POST `/solana/link`. Returns deep link + polling code. |
| `await poll_auth(polling_code)` | POST `/solana/poll`. Returns oracle signature + session address. |
| `await get_attestation(solana_address)` | POST `/solana/attestation`. Returns the session address, or None on 404. |
| `await aclose()` / `async with` | Close the underlying `httpx.AsyncClient`. |

Sync (no I/O — pure CPU):

| Method | Description |
| --- | --- |
| `build_create_attestation_message(...)` | Build the unsigned `solders.message.Message` containing the Ed25519 verify + create_attestation instructions. |

### PDA helpers

`derive_program_state_pda`, `derive_credential_signer_pda`,
`derive_session_registry_pda`, `derive_session_entry_pda`,
`derive_solana_entry_pda`, `derive_attestation_pda`,
`derive_credential_pda`, `derive_schema_pda`. All return
`(Pubkey, bump)` and call `Pubkey.find_program_address` with the same seeds
used by the Solana programs.

## Differences from the JS package

- **Async HTTP** via `httpx.AsyncClient`. The transaction-building helper is
  sync since it does no I/O — calling `await` on pure CPU work is just noise.
- `build_create_attestation_message` takes the on-chain `ProgramState`
  bytes directly instead of a web3.js `Connection`. The library is therefore
  RPC-agnostic — bring your own `solana-py`, raw `httpx`, async client, etc.
- Returns a `Message`, not a `Transaction` — so you control signers and
  blockhash. Wrap it with `Transaction([payer], msg, blockhash)`.
- The Ed25519 native-program instruction is built manually (solders doesn't
  ship a helper). Layout matches `@solana/web3.js`'s
  `Ed25519Program.createInstructionWithPublicKey`.

## License

MIT.
