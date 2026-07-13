//! Integration tests that drive a LIVE Trezor emulator.
//!
//! These are `#[ignore]`d by default so `cargo test` stays green without a
//! device. To run them, start the emulator from `_handy/trezor-firmware/core`
//! (`make build_unix && ./emu.py`) with a passphrase-disabled seed, then:
//!
//! ```sh
//! cargo test -p trezor-signer --test emulator -- --ignored --nocapture
//! ```
//!
//! The tests are seed-agnostic: they verify parity of whatever key the emulator
//! holds, so no specific mnemonic or on-chain funds are required.

use qpv2_core::types::SpxVariant;

/// `get_address` must return a well-formed SPHINCS+ address whose lock_args the
/// wallet can reproduce locally. `TrezorDevice::get_address` performs the
/// lock_args parity check internally, so a successful call already proves that
/// device key derivation matches the wallet's.
#[test]
#[ignore = "requires a running Trezor emulator at 127.0.0.1:21324"]
fn get_address_parity() {
    let mut dev = trezor_signer::open().expect("connect to emulator");
    let addr = dev
        .get_address(0, SpxVariant::Sha2128S, false, false)
        .expect("get_address(0, Sha2128S, testnet)");

    assert_eq!(addr.variant, SpxVariant::Sha2128S as u32);
    // sha2-128s: 32-byte public key, 32-byte lock args.
    assert_eq!(addr.pubkey.len(), 32, "pubkey length");
    assert_eq!(addr.lock_args.len(), 32, "lock_args length");
    assert!(
        addr.address.starts_with("ckt"),
        "expected a testnet (ckt...) address, got {}",
        addr.address
    );

    println!("device model : {}", dev.model());
    println!("account 0 addr: {}", addr.address);
    println!("lock_args     : {}", hex::encode(&addr.lock_args));
    println!("pubkey        : {}", hex::encode(&addr.pubkey));
}
