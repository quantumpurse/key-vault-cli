# Trezor Safe hardware signer

QuantumPurse can hold a wallet's SPHINCS+ key on a Trezor Safe device instead of in the software vault. The wallet builds a CKB transaction as usual, streams it to the device, the device recomputes the signing message and signs with SPHINCS+, and the wallet fills the returned witness lock and broadcasts. The key
never leaves the device.

The signer talks THP v2 (encrypted Noise session) over two transports: **USB** to a physical device and **UDP loopback** to the firmware emulator. `open()` prefers a plugged-in USB Trezor and falls back to the emulator; set `QPV2_TREZOR_EMULATOR=1` to force the emulator even with a device plugged in.

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
| Transport: USB (physical device) + UDP (emulator) | Implemented, THP-only |
| THP pairing | CodeEntry (CPace); QR / NFC not implemented. The device's first advertised method is taken, which is always CodeEntry — skip-pairing is accepted only if a device lists it first |
| Pairing credentials | Stored per device; later connections skip pairing |
| Nervos DAO via device | Implemented for single-sig wallets |
| Trezor as a multisig co-signer | Not supported — firmware only signs its own single-sig lock |
| Bluetooth | Not implemented — future milestone |
| Standalone `qpv2 trezor` subcommands | Deferred (create the wallet in the GUI) |

Trezor support is always compiled in; there is no cargo feature flag. On hosts
without system `libusb`, `rusb` builds a vendored copy from source, so no extra
system package is required to build.

## Connecting a physical device (USB)

The device must run the `ckb-sphincsplus-dev` firmware branch (see below) and
be plugged in over USB. On Linux, install the
[Trezor udev rules](https://trezor.io/learn/a/udev-rules) first, or opening the
device fails with a permission error. Close Trezor Suite while QuantumPurse is
using the device — only one application can claim the USB interface.

**First connection — pairing.** Production firmware requires authenticated THP
pairing. QuantumPurse implements the CodeEntry method: confirm the connection
on the device, then type the 6-digit code the device displays into the prompt
(a terminal prompt in the CLI, a pinentry dialog in the GUI). The code proves
both ends of the encrypted channel are talking to each other (CPace PAKE);
a mistyped code aborts with no side effects — just reconnect and retry.

After pairing, the host requests a credential and stores it in
`<data_dir>/quantum-purse/trezor-credentials.json` together with the host's
static X25519 key. Later connections present it during the handshake and skip
pairing: instead of the code, the device just shows a quick "Connect?"
confirmation to tap (the firmware only issues silent-autoconnect credentials
in a later session, not at pairing time). Deleting the file only means pairing
again on next connect. The credential is not a wallet secret: it authorizes
connecting, while every address export and signature still requires
confirmation on the device.

A quick connectivity check without touching any wallet:

```sh
cargo run -p trezor-connect --example usb_probe
```

It lists visible devices, opens a THP session (running pairing if needed), and
exits. The emulator pairs the same way a physical device does: dev builds also
advertise skip-pairing, but we take the first advertised method — CodeEntry —
because skip-pairing yields no credential and would make the device ask to pair
on every single connect.

## Device / emulator requirements

The firmware must be the `ckb-sphincsplus-dev` branch (it implements the `CKBSphincsPlus*` messages). The device/emulator must have:

- **Passphrase disabled.**
- A **BIP-39** (not SLIP-39) **extended mnemonic** whose length matches the
  variant's security level: 36 words for `sha2-128s` (the default), 54 for
  192-bit, 72 for 256-bit.

Firmware limits: ≤256 inputs, ≤256 outputs, ≤64 cell deps, account index ≤1e6.

## Running the emulator

From `_handy/trezor-firmware/core` (needs the firmware build toolchain — scons, a Python env via `uv`/`poetry`, SDL2, and the embedded Rust toolchain):

```sh
cd _handy/trezor-firmware/core
make build_unix        # build the emulator (one-time; heavy)
./emu.py               # run it — listens on UDP 127.0.0.1:21324 (debug: 21325)
```

Load a compatible seed on the emulator (passphrase off) before testing, e.g.
via the firmware's `trezorctl` (`python/src/trezorlib`).

## Verifying the signer against the emulator

With the emulator running, the integration tests prove the pipe end-to-end. They are `#[ignore]`d by default and auto-confirm on-device prompts over the debug link, so they need no manual clicking — but they call `open_emulator()`, which passes `NoInteraction`, so **the emulator must already be paired**: pair once by hand (the GUI, or the `thp_get_address` example) and the stored credential keeps every later run unattended. They are seed-agnostic (they verify parity of whatever key the emulator holds) and need no on-chain funds:

```sh
cargo test -p trezor-connect --test emulator -- --ignored --nocapture
```

- `get_address_parity` — the device's lock_args match the wallet's own derivation (proves transport + protobuf + key derivation).
- `sign_transfer_verifies` — a synthetic transfer is signed on the device and the signature verifies against the host-computed `CKB_TX_MESSAGE_ALL` digest (proves device digest == host digest and that the signature is valid).

## GUI walkthrough (end-to-end test)

1. Run the emulator (above) with a passphrase-off, 36-word (`sha2-128s`) seed.
2. Launch the GUI, pick the `sha2-128s` variant, click **Connect Trezor**; confirm the address export on the emulator. A watch-only wallet appears.
3. Point the app at a CKB **Testnet** RPC. For a real transfer the account needs testnet CKB; the signing itself is already proven by the tests regardless.
4. Send a small transfer, confirm it on the emulator, and watch it broadcast.

## Implementation map

- `crates/trezor-connect` — device discovery, `get_address`, and the streaming `sign_tx` state machine (a Rust port of the firmware's `ckb.py` host loop). Inside it, `thp/transport.rs` holds the USB/UDP packet transports, `thp/pairing.rs` the CodeEntry flow and credential store, and `thp/cpace.rs` the CPace255 PAKE (ported from trezorlib, pinned against its test vectors).
- `vendor/trezor-firmware` — the firmware fork, as a git submodule pinned to a commit on `ckb-sphincsplus-dev`. Both Trezor path dependencies come from inside it, so the protocol code and the firmware that speaks it can never drift apart:
  - `rust/trezor-thp` — the THP channel state machine (framing, Noise handshake, ACK/retransmit); the connector drives it through `thp/client.rs`.
  - `rust/trezor-client` — the Trezor host client (Protocol v1 + the generated CKB protobuf bindings, re-exported flat as `trezor_client::protos::*`).
  - `common/protob/*.proto` — the canonical message definitions both sides are generated from.

  Syncing a protobuf change is now a submodule bump: generate in the fork (`rust/trezor-client/scripts/build_protos`, then `build_messages` — a message missing from the latter has no wire id and cannot be sent through the typed `call()`), push, then `git -C vendor/trezor-firmware fetch && git checkout <sha>` here and commit the moved gitlink. Nothing is copied into this repo.

  Note for fresh clones and CI: `git submodule update --init vendor/trezor-firmware` is required before building. Do **not** use `--recursive` — the fork carries fourteen nested submodules (micropython, the STM32 HALs) that nothing here needs.
- `ckb-node::fetch_hardware_signing_context` — supplies full previous transactions, their committed block hashes, and DAO header dependencies for the device's trustless capacity and compensation checks.
- `qpv2-core`: `AuthMethod::Trezor`, `KeyVault::create_device_wallet` / `is_hardware_wallet` (watch-only). Device accounts use the `Standard` single-sig convention — header `[0x80, 0x01, 0x01, 0x01, flag]`, matching the firmware's `_MULTISIG_HEADER`; `TREZOR_CONVENTION` in `trezor-connect/src/device.rs` is the single source for it, passed into `create_device_wallet` so the wallet record cannot disagree with its accounts.
- GUI: `transactor::sign_and_send_with_trezor`, `wallet::create_wallet_with_trezor`.
