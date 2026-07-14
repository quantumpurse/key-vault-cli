//! Integration tests that drive a LIVE Trezor emulator.
//!
//! `#[ignore]`d by default so `cargo test` stays green without a device. To run:
//! start the emulator from `_handy/trezor-firmware/core` (`make build_unix &&
//! ./emu.py`) with a passphrase-disabled seed, then:
//!
//! ```sh
//! cargo test -p trezor-signer --test emulator -- --ignored --nocapture
//! ```
//!
//! The tests auto-confirm on-device prompts over the debug link (emulator only),
//! and are seed-agnostic: they verify parity of whatever key the emulator holds,
//! so no specific mnemonic and no on-chain funds are required.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{Byte32, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use qpv2_core::types::{MultisigConfig, SpxVariant};
use trezor_client::protos::{
    debug_link_decision::DebugButton, DebugLinkDecision, DebugLinkGetState, DebugLinkState,
};
use trezor_signer::TREZOR_CONVENTION;

/// Continuously press "YES" on the emulator's debug link while `f` runs, so
/// device confirmation screens (address export, transfer approval) auto-confirm.
fn with_auto_approve<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let mut debuglink = trezor_client::find_devices(true)
        .into_iter()
        .find(|t| t.model == trezor_client::Model::TrezorEmulator)
        .expect("no debug emulator found (is the emulator running?)")
        .connect()
        .expect("connect to debug emulator");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let mut decision = DebugLinkDecision::new();
    decision.set_button(DebugButton::YES);

    std::thread::scope(|scope| {
        scope.spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                let _ = debuglink.send_message(decision.clone());
                let _ = debuglink.call(
                    DebugLinkGetState::new(),
                    Box::new(|_, m: DebugLinkState| Ok(m)),
                );
            }
        });
        let res = f();
        stop.store(true, Ordering::Relaxed);
        res
    })
}

/// Testnet lock script for a set of lock args.
fn testnet_lock(lock_args: &[u8]) -> Script {
    let code_hash_hex = qpv2_core::constants::CKB_TESTNET_CODE_HASH.trim_start_matches("0x");
    let code_hash = Byte32::from_slice(&hex::decode(code_hash_hex).unwrap()).unwrap();
    let hash_type: ckb_types::packed::Byte = ScriptHashType::Data1.into();
    Script::new_builder()
        .code_hash(code_hash)
        .hash_type(hash_type)
        .args(Bytes::from(lock_args.to_vec()).pack())
        .build()
}

/// `get_address` returns a well-formed SPHINCS+ address whose lock_args the
/// wallet reproduces locally (the parity check runs inside `get_address`).
#[test]
#[ignore = "requires a running Trezor emulator at 127.0.0.1:21324"]
fn get_address_parity() {
    let mut dev = trezor_signer::open().expect("connect to emulator");
    let addr = with_auto_approve(|| {
        dev.get_address(0, SpxVariant::Sha2128S, false, false)
            .expect("get_address(0, Sha2128S, testnet)")
    });

    assert_eq!(addr.variant, SpxVariant::Sha2128S as u32);
    assert_eq!(addr.pubkey.len(), 32, "sha2-128s pubkey length");
    assert_eq!(addr.lock_args.len(), 32, "lock_args length");
    assert!(
        addr.address.starts_with("ckt"),
        "expected a testnet address, got {}",
        addr.address
    );

    println!("device model : {}", dev.model());
    println!("account 0 addr: {}", addr.address);
    println!("lock_args     : {}", hex::encode(&addr.lock_args));
}

/// Sign a synthetic testnet transfer on the device and verify the returned
/// signature against the host-computed CKB_TX_MESSAGE_ALL digest. This proves
/// device digest == host digest and that the signature is valid — without funds
/// or a node.
#[test]
#[ignore = "requires a running Trezor emulator at 127.0.0.1:21324"]
fn sign_transfer_verifies() {
    let variant = SpxVariant::Sha2128S;
    let mut dev = trezor_signer::open().expect("connect to emulator");

    let (signed, digest, pubkey) = with_auto_approve(|| {
        let addr = dev
            .get_address(0, variant, false, false)
            .expect("get_address");
        let lock = testnet_lock(&addr.lock_args);
        let config = MultisigConfig::single_sig(variant, addr.pubkey.clone(), TREZOR_CONVENTION);
        let signing_lock_size = config.max_witness_lock_size();

        // Synthetic previous tx: one output locked to our account.
        let prev_output = CellOutput::new_builder()
            .capacity(Capacity::bytes(1000).unwrap().pack())
            .lock(lock.clone())
            .build();
        let prev_tx = TransactionBuilder::default()
            .output(prev_output.clone())
            .output_data(Bytes::new().pack())
            .build();
        let prev_hash = prev_tx.hash();

        // Unsigned transfer spending that output back to the same lock.
        let input = CellInput::new_builder()
            .previous_output(OutPoint::new(prev_hash.clone(), 0))
            .build();
        let send_output = CellOutput::new_builder()
            .capacity(Capacity::bytes(999).unwrap().pack())
            .lock(lock)
            .build();
        let placeholder = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; signing_lock_size])).pack())
            .build();
        let unsigned = TransactionBuilder::default()
            .input(input)
            .output(send_output)
            .output_data(Bytes::new().pack())
            .witness(placeholder.as_bytes().pack())
            .build();

        let input_cells = vec![(prev_output, Bytes::new())];
        let mut prev_txs: HashMap<H256, TransactionView> = HashMap::new();
        prev_txs.insert(prev_hash.unpack(), prev_tx);

        let digest = ckb_node::compute_signing_message(&unsigned, &input_cells, 0)
            .expect("compute_signing_message");
        let signed = dev
            .sign_tx(
                0,
                variant,
                false,
                &unsigned,
                signing_lock_size,
                &prev_txs,
                &[0],
            )
            .expect("sign_tx on device");
        (signed, digest, addr.pubkey)
    });

    // Witness lock = [0x80,0x00,0x01,0x01,flag] || pubkey(32) || signature.
    let lock_blob = signed.witness_lock;
    assert!(
        lock_blob.len() > 5 + 32,
        "witness lock too short: {}",
        lock_blob.len()
    );
    assert_eq!(&lock_blob[5..5 + 32], pubkey.as_slice(), "witness pubkey");
    let sig = &lock_blob[5 + 32..];

    let ok = qpv2_core::KeyVault::raw_verify(variant, &pubkey, &digest, sig).expect("raw_verify");
    assert!(ok, "device signature must verify against the host digest");
    println!(
        "sign_tx OK: {}-byte witness lock; signature verifies",
        lock_blob.len()
    );
}
