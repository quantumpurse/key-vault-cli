# Backlog

## Refactoring

- [ ] **Unify the two RPC retry helpers into one primitive in `ckb-node`.** `qpv2-gui/src/fetcher.rs::retry_bounded` (history sync: 8 attempts, exponential backoff to a 30s cap, retries on `Err` *and* `Ok(None)` because the light client may not have fetched the item yet, gives up with `None`) and `ckb-node/src/wallet_helpers/tx_builder/signing.rs::get_transaction_with_retry` (signing path: 4 attempts, ~3s total, retries `Err` only — a user is waiting and not-found is definitive there) are the same loop with different policies. Move one parameterized helper next to `QpClient` in `ckb-node::client` — `retry_bounded(policy, tag, f) -> Result<Option<T>, E>` with named presets (`RetryPolicy::SYNC`, `RetryPolicy::SIGNING`) encoding attempts, backoff, and whether `Ok(None)` retries — and adapt both call sites. The return type preserves the last error (the signing path shows it to the user; the fetcher discards it). While at it, put the `get_header` calls in `fetch_hardware_signing_context` behind the same helper: today they have no retry at all, so during DAO phase-2 signing a single dropped RPC request aborts the flow that `get_transaction_with_retry` exists to protect.
- [ ] **Stop exposing `qpv2-core::constants` as public.** The module was made `pub` so the GUI can access CKB code hash/hash type constants for balance queries. Instead, expose a helper (e.g. `lock_script_info(is_mainnet)`) in `qpv2_core::utilities` and revert to `mod constants`. This avoids leaking internal crypto constants like `SALT_LENGTH`, `ENC_SCRYPT`, and `VAULT_ENC_KEY_HKDF_INFO`.

## Architecture

- [ ] **Consider migrating GUI background I/O to tokio.** Balance fetching currently uses `std::thread` + `mpsc` channel. If the app grows to need more concurrent I/O (transaction broadcasting, node health polling, WebSocket subscriptions), a tokio runtime would provide structured concurrency and multiplexed I/O on fewer threads. Would require switching `reqwest` from `blocking` feature to async in `ckb-node`.

## Performance

- [ ] **Batch-fetch all account balances in one RPC round-trip.** `fetch_all_balances` currently loops N accounts sequentially, each calling `get_cells_capacity`. Use `QpClient::batch_rpc` to send all N `get_cells_capacity` calls in a single HTTP POST. Trade-off: results arrive all-at-once instead of streaming per-account, but the polling interval already refreshes them together.
- [ ] **Cache CKB addresses instead of recomputing every frame.** `lock_args_to_address` is called inside the `show_accounts_tab` render loop, re-encoding addresses on every repaint. Store computed addresses in a cache, recompute only on unlock, network toggle, or new account creation.

## FIDO2

- [ ] **Support built-in user verification (UV) for FIDO2 devices.** Devices with on-board biometrics (YubiKey Bio fingerprint) or on-device PIN entry (keypads/buttons) handle user verification internally — no host-side PIN is needed. Detect device UV capability at registration/assertion time and skip the PIN prompt when the device supports internal UV. Currently only the clientPin path is implemented (PIN entered on host, sent encrypted to device).

## Trezor

- [ ] **One synced source for all Trezor bindings: submodule the firmware fork, drop the copies.** Trezor protobuf/protocol code currently lives in three places with three different provenances, and only one of them has a sync procedure. Two steps, in order:

  **(a) Delete `crates/trezor-signer/src/thp/pb/`.** Its six files are byte-identical copies of `vendor/trezor-thp/examples/host-cli/pb/` — Trezor's *example* bindings, carried into `crates/` by the THP port (`b2d000e`); nothing in this repo generates them (no `build.rs`, no `protobuf-codegen`). They are stale: protoc 3.19.6 vs the vendored crate's 31.1, and `messages_thp.rs` still declares `ThpMessageType_Failure = 3`, a variant the current `messages-thp.proto` has removed and reserved (`reserved 0 to 19`). Meanwhile `vendor/trezor-client` ships `messages_thp`, `messages_common` and `messages_management` **ungated** (see the `modules!` list in `protos/mod.rs`), so the same protos compile twice and the next proto change will land in the synced copy while silently skipping this one. Repoint the handful of `pb::` imports in `thp/{mod,pairing,client}.rs` at `trezor_client::protos` (same proto source, so type names should line up).

  **(b) Replace the vendored crates with a submodule.** `vendor/trezor-client` is a strict 50-file subset of the fork's `rust/trezor-client` (byte-identical except `Cargo.toml`, whose header documents the three local edits) and `vendor/trezor-thp` is identical to `rust/trezor-thp` — both from the same monorepo, so one submodule of `quantumpurse/trezor-firmware` (branch `ckb-sphincsplus-dev`, `shallow = true`) covers both crates plus the proto sources and generation scripts. Add the submodule (precedent: five already in `.gitmodules`), point the path deps at `<submodule>/rust/{trezor-client,trezor-thp}`, add it to the root workspace `exclude`, delete both `vendor/trezor-*` copies, and retire the untracked `_handy/trezor-firmware` checkout — proto sync becomes "bump the submodule SHA" and `TREZOR.md`'s copy-three-files procedure goes away. The `rusb` `vendored` edit is already redundant (`trezor-signer` enables the feature itself; unification covers the transitive copy); the dropped inner `[workspace]` needs a build test — if cargo trips on the nested workspace, fix with a small commit to the fork. Trade-offs: clone weight (shallow mitigates), CI submodule init (already required for `vendor/ckb`), and the host pins to an exact firmware commit — desirable for a hardware-wallet protocol.
- [ ] **Skip `fetch_input_cells` for hardware wallets.** The Trezor arm at `qpv2-gui/src/poller.rs:42` passes `input_cells` to `sign_and_send_with_trezor`, which ignores them (`_input_cells`) — the device recomputes the signing message from full previous transactions it fetches itself. The four build threads in `transactor.rs` (`:184`, `:294`, `:367`, `:436`) fetch them anyway, one RPC per input, wasted. Fix: capture `KeyVault::is_hardware_wallet(wallet_id)` before each spawn and pass `Vec::new()` instead of fetching. Trivial waste — latency only, no correctness impact.
- [ ] **Show connect feedback on the Trezor buttons during the blocking connect.** Clicking Connect Trezor (or add-account on a device wallet) gives no visual sign while `open()` blocks the UI thread — the screen freezes on the pre-click frame for the ~2s probe (or longer with pairing). Blocking in the click handler can never show feedback: egui is immediate-mode, so the frame handling the click is presented only after `update()` returns. Fix with a one-frame deferral: on click, record the intent in a `pending_trezor_connect: Option<...>` field and render the button as "CONNECTING…" (disabled); at the top of the next `update()`, `take()` the field and run the blocking connect while the connecting frame sits on screen (add the field to the end-of-frame repaint condition so the next frame is guaranteed). Subsumed by the worker-thread entry below if that lands first.
- [ ] **Move wallet-creation `trezor_signer::open()` calls off the UI thread.** `create_wallet_with_trezor` and the add-account flow (`qpv2-gui/src/wallet.rs`) call `open()` synchronously in the egui event handler, freezing the window for the whole connect — pairing, the on-device "Connect?" tap, and any timeout. The signing path already does this right (worker thread + mpsc + poller, `transactor.rs`); wallet creation needs the same plumbing plus a "connecting…" state. Less urgent now that a dead transport fails in ~2s (connect probe timeout) instead of 60s, but a first-time pairing still blocks the UI for as long as the user takes to type the code.
- [ ] **Bind a device wallet to the device that created it.** `open()` picks a transport by availability — first USB device on the bus, else the emulator — and pairing state is only consulted afterwards, inside the Noise handshake, against whichever device answered. Since the credential store holds entries for many devices, a *different* paired Trezor connects silently. Nothing records which device a wallet belongs to (`AuthMethod::Trezor` stores no device identity), so with an emulator-seeded wallet and a physical device plugged in: signing fails safely (the firmware finds no input matching its own lock args, `sign_sphincs_tx.py:411`, though the message is confusing), but **account import does not** — `wallet.rs:602-618` stores whatever address the picked device returns, silently mixing a second seed's account into the wallet; `get_address`'s parity check only validates the device against its own pubkey. Fix: store the device's static public key (already known at pairing) in `AuthMethod::Trezor`, have `open()` take an expected identity and reject a mismatch with a clear message, and use the existing-but-unused `list_devices()` / `open_device()` for explicit selection when several are present — documenting that `DeviceLocation::Usb`'s bus/address pair is only valid until replug, so a `DeviceInfo` must be used promptly, never persisted. Related to the skip-pairing entry under Security — both stem from there being no pinned device identity.
- [ ] **Collapse `sign_tx` / `sign_tx_with_context` into one method taking a chain-context struct.** The legacy wrapper (`trezor-signer/src/stream.rs`) delegates with an empty committed-block map and empty header list, so a DAO phase-2 withdrawal passed to `sign_tx` compiles fine and fails only at runtime in `conv.rs` ("previous transaction has no committed block hash"). No current caller misroutes — the CLI helper is transfer-only, the GUI passes the full context — but the trap sits exactly where future CLI DAO-on-Trezor work would step. Define the context struct in `qpv2-core` (`ckb-node`'s `HardwareSigningContext` can't be named by `trezor-signer` — sibling crates), have `fetch_hardware_signing_context` return it, and pass it whole. Also removes both `#[allow(clippy::too_many_arguments)]`.
- [ ] **Request the autoconnect credential upgrade on the first credential session.** Initial pairing must request `autoconnect=false` (the firmware rejects `true` in the same session, `apps/thp/pairing.py`), but on a later session whose handshake was authenticated by the stored credential, the firmware validates it, shows a one-time confirmation, and issues an `autoconnect=true` replacement — after which the per-connection "Connect?" tap disappears. QuantumPurse never asks (`finish_credential_phase` sends only `ThpEndRequest`), so the tap persists forever; Trezor Suite has exactly this call (`connect/src/api/thpGetCredentials.ts`).
- [x] **Regenerate the vendored `trezor-client` message registry to cover `CKBTxAckHeader`.** Done: `messages.rs` and `messages/generated.rs` synced from the firmware repo's own regenerated bindings (verified additive-only), and `stream.rs`'s hardcoded `MSG_CKB_TX_ACK_HEADER` constant plus the `call_with_type` bypass removed — the header ack now goes through the typed `call()` like every other message.
- [ ] **Parse `QPV2_TREZOR_EMULATOR` by value, or document it as presence-only.** `device.rs::open` gates the USB scan on `is_none()`, so `=0`, `=false`, and empty all force the emulator; `TREZOR.md` only shows `=1`.
- [ ] **Minor polish.** (1) Five `expect()` panic sites in library paths (four `getrandom::fill`, one `serde_json::to_vec_pretty` in `thp/pairing.rs`, `thp/cpace.rs`, `thp/mod.rs`) — all practically unreachable (OS RNG failure / in-memory serialization of plain data), but they kill the GUI's signing worker instead of returning `TrezorSignerError`. (2) `list_devices` always advertises the emulator endpoint without probing — intentional (a probe costs a full THP connect) but it lists candidate endpoints, not live devices; rename or document before any device-picker UI consumes it. (3) The pinentry pairing prompt masks the 6-digit code even though the device displays it; a visible field would reduce mistype aborts (subjective — the mistype error message and safe-reconnect docs already soften it). (4) `DeviceInfo.model` and `TrezorDevice::model()` are hardcoded strings ("Trezor" / "Trezor Safe"), never read from the device, yet the GUI displays them as fact — wire the real model from the THP device properties or drop them.

## Security

- [ ] **Accept THP skip-pairing only when deliberately connecting to the emulator.** `trezor-signer`'s `run_pairing` selects `SkipPairing` whenever the peer advertises it, on any transport, and has no transport knowledge (the type is erased into `Box<dyn Transport>` before `ThpSession::connect`). The advertised `pairing_methods` cannot be tampered with in-line — they are bound into the Noise prologue on both sides (`vendor/trezor-thp/src/channel/noise.rs` / `device.rs`), so stripping CodeEntry from a genuine device fails the handshake — but a *fake endpoint* (rogue process or substituted device) completes its own valid handshake, advertises skip, and is accepted with no user authentication; on first contact there is no pinned device identity, and CodeEntry is precisely what authenticates the endpoint. Stored credentials mitigate only for already-known devices. Reference hosts do not gate by transport either; instead Trezor Suite declares its supported methods as CodeEntry only (`trezor-suite/packages/suite/src/support/extraDependencies.ts`). Mirror that: make the host's accepted pairing methods explicit per connection — CodeEntry (plus stored credential) for physical devices, `SkipPairing` only for the emulator path.
- [ ] **Verify header contents when building DAO phase-2 withdrawals.** The entitled compensation is computed from node-supplied header contents (the AR values in the `dao` field), but header *contents* are not committed in the signing message — only their hashes via `header_deps`. A malicious RPC endpoint returning a real block hash with doctored AR fields makes the builder set the withdrawal output too low; the shortfall becomes fee (burned to the miner) under a perfectly valid signature, because every value the message commits is truthful. Exposure is bounded to the compensation delta — the principal is the input cell's capacity, which the message does commit, so a lie there invalidates the signature on-chain. Transfers are not affected for the same reason. Fix: at build time, re-serialize each fetched header and check its hash against the hash being placed in `header_deps` (the same check `fetch_hardware_signing_context` does at sign time) — a fabricated-content header cannot survive it. The light-client backend also closes this structurally (headers verified by PoW), so scope the check to the full-node / public-RPC backends.
- [ ] **Implement re-validation before signing.** Add a validation step between transaction build and SPHINCS+ signing to verify inputs are still live and transaction parameters match user intent — guards against TOCTOU races between build and sign.
- [ ] **Patch `pinentry` crate's `BufReader` so its scratch buffer zeroizes on drop.** In `pinentry-0.8.0/src/assuan.rs`, `Connection::input` is a `BufReader<ChildStdout>` (line 50) whose internal `Vec<u8>` receives the password bytes via `read_line` (line 142). The crate explicitly zeroizes every other plaintext copy (the `line` String, the `DataLine` `SecretString`, the percent-decoded `Cow`, the concat buffer), but `BufReader` has no zeroizing `Drop`, and `Connection`'s `Drop` impl (lines 190–205) doesn't reach in to scrub it. Net: one freed-but-not-zeroed page per password prompt — readable from freed-memory snapshots until the allocator reuses it. Fix paths: (1) upstream PR to `str4d/pinentry-rs` adding a zeroizing reader newtype around `BufReader` (preferred — benefits every consumer), or (2) fork the crate into `vendor/` and apply the patch with a path dep. Today's leak is ~1 fragment per prompt vs egui's ~5+, so accepted; revisit if we move to higher-frequency password prompts.

## Upstream

- [ ] **ckb-sdk RPC timeout.** ckb-sdk's plain client constructors build
  HTTP clients with no timeout (`reqwest::Client::new()`), so a node that
  accepts a connection but never responds blocks the calling thread
  indefinitely. We inject `ckb_node::client::RPC_TIMEOUT` everywhere the
  SDK allows (`with_builder`, `DefaultCellCollector::new_with_timeout`,
  public client fields), but the three `LightClient*` tx-building helpers
  (`light_client_impls.rs`) have private fields and no timeout
  constructor, so LC-backend transaction building still makes untimed
  calls. Fix path: upstream PR to `nervosnetwork/ckb-sdk-rust` adding
  `new_with_timeout` to those helpers (precedent: `DefaultCellCollector`
  already has one, and the SDK itself injects timeouts internally in
  `default_impls.rs:337`); `with_builder` is also undocumented there —
  worth a doc PR alongside. Interim: risk accepted — tx building is
  user-initiated and visible, unlike the silent poller wedge this
  timeout work fixed.

## Chain / Sync

- [x] **Reorg handling for tx history.** Records with fewer than 24 confirmations are provisional (memory-only, rebuilt every sync). Records at or past that depth are final and persisted. The confirmed watermark is file-derived, so the provisional window is always re-fetched. Reorged-away txs simply don't appear in the batch; reorg-moved txs come back at their new block.
- [x] **Cancellable tx-history sync thread.** Bounded retries (8 attempts, exponential backoff) replace the infinite retry loop. On give-up the sync aborts, rolls back to the last saved snapshot, and yields the single-flight slot so a later tick retries from current chain state.
- [ ] **Show pending transactions from the tx pool.** The dashboard's PENDING state is unreachable — the indexer only returns mined transactions and nothing creates pending records locally. On full node / public RPC backends, query `get_raw_tx_pool`, resolve each hash with `get_transaction`, match outputs against the wallet's lock args, and stream matching entries as `TxRecord { is_pending: true, block_number: 0 }`. The existing reconcile already retains pending rows and replaces them when the mined version arrives. Light client has no local mempool so this is full node / public RPC only.


# KNOWN BUGS

## Co-signer does not verify signing message independently

**Status:** Open

**Problem:** The co-signer signing flow (both GUI `cosign_sign_request` and CLI `msig sign`) signs the `signing_message` from the `SigningRequest` JSON without recomputing it from `unsigned_tx` + `input_cells`. A malicious initiator could craft a valid transaction (e.g., sending funds to an attacker address) while displaying fake metadata ("10 CKB to Alice"). The co-signer signs the real transaction without knowing what it does. On-chain verification passes because the signature matches the actual transaction.

**Fix:** Before signing, reconstruct `TransactionView` from `unsigned_tx`, convert `input_cells` from hex back to packed types, call `compute_signing_message`, and compare with the stated `signing_message`. Refuse to sign if they differ.

## SigningRequest uses serde_json::Value for unsigned_tx

**Status:** Open

**Problem:** `SigningRequest.unsigned_tx` is typed as `serde_json::Value` instead of `ckb_jsonrpc_types::Transaction`. This loses type safety and requires an extra `serde_json::from_value` conversion when deserializing. The `Value` type was chosen to avoid adding `ckb-jsonrpc-types` to `qpv2-core`, but that crate is already pulled in transitively.

**Fix:** Change `unsigned_tx` to `ckb_jsonrpc_types::Transaction` and `input_cells` to `Vec<(ckb_jsonrpc_types::CellOutput, ckb_jsonrpc_types::JsonBytes)>`. Add `ckb-jsonrpc-types` as a direct dependency of `qpv2-core`.

## assemble_multisig_witness is in the wrong crate

**Status:** Open

**Problem:** `assemble_multisig_witness` lives in `ckb-node` but does pure in-memory witness assembly — no node interaction, no RPC. Callers write `ckb_node::assemble_multisig_witness(...)` which is semantically wrong. It also forces the function to use `NodeManagerError::RpcError` for validation errors that have nothing to do with RPC.

**Fix:** Move `assemble_multisig_witness` to `qpv2-core` alongside `MultisigConfig` where it belongs. It only depends on `MultisigConfig`, `ckb_fips205_utils`, and the signer data — all already in `qpv2-core`.

## Multisig signing state inconsistent on wallet switch

**Status:** Open

**Problem:** On wallet switch (`wallet.rs:225`), `tx_status` is reset to `Idle`, which destroys `AwaitingCoSigners` state — the unsigned transaction, signing request, and all collected signatures are lost. Meanwhile, `cosign_response_json` and `cosign_request_json` are never cleared, so a co-signer response from wallet A lingers when switching to wallet B.

**Fix:** On wallet switch, also clear `cosign_response_json` and `cosign_request_json`. Optionally warn the user before switching if `AwaitingCoSigners` is active with collected signatures.

## lock_script_args manually reconstructs flag byte

**Status:** Open

**Problem:** `MultisigConfig::lock_script_args()` in `types.rs:172` manually computes the param flag with `(signer.variant as u8) << 1` instead of using `ckb_fips205_utils::construct_flag(param_id, false)` which does the same thing. `construct_flag` is the canonical implementation used by the lock script and by `assemble_multisig_witness`. Duplicating the bit logic risks divergence.

**Fix:** Use `construct_flag(param_id, false)` in `lock_script_args()` to match `assemble_multisig_witness` and the on-chain lock script.

## raw_sign returns public key unnecessarily

**Status:** Open

**Problem:** `KeyVault::raw_sign()` returns `(Vec<u8>, Vec<u8>)` — a tuple of (signature, public_key). The public key is derived from the private key during signing, but every account already stores its public key in `config.signers[0].pubkey`. Callers use the returned pubkey only to look up the signer index in the multisig config, which they could do directly from the account's stored pubkey.

**Fix:** Change `raw_sign` to return `Result<Vec<u8>, String>` (signature only). Callers that need the pubkey should read it from the account's config instead of relying on the signing function to extract it from the private key.

## CKB amount parsed via f64 loses precision

**Status:** Fixed 2026-06-11 — `qpv2_core::utilities::parse_ckb_to_shannons`
(integer split/pad/checked arithmetic, unit-tested) now backs all six
sites; the CLI clap `amount` args changed from `f64` to `String` so the
value is never a float anywhere between argv and shannons.

Reassessed 2026-06-11; confirmed and worse than first written:

**Problem:** Both CLI and GUI parse CKB amounts through `f64`, multiply by
`1e8`, and truncate with `as u64`. Empirical sweep: roughly 5–7% of all
valid 8-decimal amounts convert off by one shannon. Minimal repro:
`"0.00000003"` parses to 2 shannons (`0.00000003 * 1e8 = 2.999...`) — a
33% relative error on that amount. (The example originally cited here,
`0.29999999`, happens to round exactly and does NOT reproduce; the
mechanism is right, the witness value was wrong.)

Second failure mode: at amounts ≥ ~45M CKB (approaching 2^53 shannons)
the f64 rounding can go **up** as well as down — e.g. `"90216076.29597175"`
converts to one shannon MORE than typed, i.e. the wallet would silently
send more than the user asked.

Affected sites (all four CLI sites take `amount: f64` directly as a clap
arg, so precision is lost at argument parsing — the fix there must also
change the arg type to `String`):
- CLI `crates/qpv2-cli/src/main.rs`: `handle_transfer`,
  `handle_msig_build_transfer`, `handle_dao_deposit`,
  `handle_msig_build_dao` (deposit arm).
- GUI `crates/qpv2-gui/src/transactor.rs`: `transfer_async`,
  `dao_deposit_async`.

CLI list-output formatting (`capacity as f64 / 1e8`) is the same class
but display-only; the GUI display path already uses integer `ckb_split`.

**Fix:** Parse the amount string directly into shannons using integer
arithmetic (split on `.`, pad fraction to 8 digits, combine with
checked u64 arithmetic; reject more than 8 fraction digits instead of
silently truncating). Same approach as CCC's `fixedPointFrom`. Put one
shared `parse_ckb_to_shannons(&str) -> Result<u64, String>` in
`qpv2-core` so CLI and GUI use identical parsing, and switch the CLI
clap args from `f64` to `String`.

## Submitter does not verify signatures before broadcasting

**Status:** Open

**Problem:** `handle_msig_submit` in the CLI (and `submit_multisig_transaction` in the GUI) checks that the response count matches threshold and that signing messages match, but never verifies that each signature is actually valid against the corresponding signer's public key. Garbage signatures pass all CLI/GUI validation and only fail on-chain.

A malicious co-signer could repeatedly submit invalid signatures to delay a legitimate transaction. In time-sensitive scenarios (e.g., DAO withdrawal before maturity deadline), this could cause the user to miss the window and lose DAO interest.

**Fix:** Before assembling the witness, verify each `(signer_index, signature)` pair against the signer's public key from `multisig_config.signers[signer_index]` using `KeyVault::raw_verify`. Reject invalid signatures before broadcasting.
