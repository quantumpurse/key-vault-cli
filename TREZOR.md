# Trezor Safe hardware signer (emulator-first)

QuantumPurse can hold a wallet's SPHINCS+ key on a Trezor Safe device instead of
in the software vault. The wallet builds a CKB transaction as usual, streams it
to the device, the device recomputes the signing message and signs with
SPHINCS+, and the wallet fills the returned witness lock and broadcasts. The key
never leaves the device.

This first cut targets the **firmware emulator** and a **single-sig CKB
transfer**. See *Status* below for what is and isn't implemented yet.

## What works

- **Connect a Trezor as a new watch-only wallet.** Setup screen → *Connect
  Trezor*. Addresses are imported from the device (each confirmed on-device);
  the app stores no seed.
- **Send CKB from a device wallet.** The transfer's sign step streams the tx to
  the device; confirm on the device and it broadcasts. Works in the GUI and in
  the CLI (`qpv2 ... transfer` on a device wallet).
- **New account** on a device wallet imports the next derivation index from the
  device.

## Status

| Area | State |
|---|---|
| Single-sig transfer (GUI + CLI) | Implemented |
| Transport: emulator (UDP) + USB | UDP wired; USB present but only emulator exercised |
| Nervos DAO via device | Not yet (software vault only) |
| Trezor as a multisig co-signer | Not supported — firmware only signs its own single-sig lock |
| Bluetooth (THP v2) | Not implemented — future milestone |
| Standalone `qpv2 trezor` subcommands | Deferred (create the wallet in the GUI) |

Trezor support is always compiled in; there is no cargo feature flag. On hosts
without system `libusb`, `rusb` builds a vendored copy from source, so no extra
system package is required to build.

## Device / emulator requirements

The firmware must be the `ckb-sphincsplus-dev` branch (it implements the
`CKBSphincsPlus*` messages). The device/emulator must have:

- **Passphrase disabled.**
- A **BIP-39** (not SLIP-39) **extended mnemonic** whose length matches the
  variant's security level: 36 words for `sha2-128s` (the default), 54 for
  192-bit, 72 for 256-bit.

Firmware limits: ≤256 inputs, ≤256 outputs, ≤64 cell deps, account index ≤1e6.

## Running the emulator

From `_handy/trezor-firmware/core` (needs the firmware build toolchain —
scons, a Python env via `uv`/`poetry`, SDL2, and the embedded Rust toolchain):

```sh
cd _handy/trezor-firmware/core
make build_unix        # build the emulator (one-time; heavy)
./emu.py               # run it — listens on UDP 127.0.0.1:21324 (debug: 21325)
```

Load a compatible seed on the emulator (passphrase off) before testing, e.g.
via the firmware's `trezorctl` (`python/src/trezorlib`).

## Verifying the signer against the emulator

With the emulator running, the integration tests prove the pipe end-to-end.
They are `#[ignore]`d by default and auto-confirm on-device prompts over the
debug link, so they need no manual clicking. They are seed-agnostic (they verify
parity of whatever key the emulator holds) and need no on-chain funds:

```sh
cargo test -p trezor-signer --test emulator -- --ignored --nocapture
```

- `get_address_parity` — the device's lock_args match the wallet's own
  derivation (proves transport + protobuf + key derivation).
- `sign_transfer_verifies` — a synthetic transfer is signed on the device and
  the signature verifies against the host-computed `CKB_TX_MESSAGE_ALL` digest
  (proves device digest == host digest and that the signature is valid).

## GUI walkthrough (end-to-end test)

1. Run the emulator (above) with a passphrase-off, 36-word (`sha2-128s`) seed.
2. Launch the GUI, pick the `sha2-128s` variant, click **Connect Trezor**;
   confirm the address export on the emulator. A watch-only wallet appears.
3. Point the app at a CKB **Testnet** RPC. For a real transfer the account needs
   testnet CKB; the signing itself is already proven by the tests regardless.
4. Send a small transfer, confirm it on the emulator, and watch it broadcast.

## Implementation map

- `crates/trezor-signer` — device discovery, `get_address`, and the streaming
  `sign_tx` state machine (a Rust port of the firmware's `ckb.py` host loop).
- `vendor/trezor-client` — the vendored Trezor host client (Protocol v1 + the
  generated CKB protobuf bindings).
- `ckb-node::fetch_prev_txs` — supplies full previous transactions for the
  device's trustless capacity check.
- `qpv2-core`: `AuthMethod::Trezor`, `KeyVault::create_device_wallet` /
  `is_device_backed` (watch-only, V1 single-sig convention).
- GUI: `transactor::sign_and_send_with_trezor`, `wallet::create_wallet_with_trezor`.
