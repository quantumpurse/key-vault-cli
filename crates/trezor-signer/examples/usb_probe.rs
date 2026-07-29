//! Real-device bring-up probe: enumerate transports, then run the THP
//! bring-up (channel allocation → Noise handshake → skip-pairing) against the
//! first device `open()` picks — USB if plugged in, emulator otherwise. No
//! address export, no signing; it only proves the encrypted session comes up.
//!
//!   RUST_LOG=debug cargo run -p trezor-signer --example usb_probe

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    println!("visible devices:");
    for info in trezor_signer::list_devices() {
        println!("  - {} ({:?})", info.label, info.location);
    }

    println!("opening THP session...");
    match trezor_signer::open(&mut trezor_signer::StdinPairing) {
        Ok(device) => println!("OK: THP session established with {}", device.model()),
        Err(e) => {
            println!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}
