//! Manual THP smoke test: connect (USB device if plugged in, else the
//! emulator) and export account 0.
//!
//!   RUST_LOG=info cargo run -p trezor-signer --example thp_get_address
//!
//! Confirm the address export on the device/emulator when prompted.

use qpv2_core::types::SpxVariant;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    println!("connecting to Trezor over THP...");
    let mut device = trezor_signer::open(&mut trezor_signer::StdinPairing).expect("connect");
    println!("connected: {}", device.model());
    println!("requesting account 0 address (confirm on the emulator)...");
    let addr = device
        .get_address(0, SpxVariant::Sha2128S, false, false)
        .expect("get_address");
    println!("address : {}", addr.address);
    println!("lock_args: {}", hex::encode(&addr.lock_args));
    println!("pubkey  : {}", hex::encode(&addr.pubkey));
    println!("OK: lock_args parity check passed inside get_address.");
}
