//! Round-trips a throwaway key through the Windows TPM.
//!
//! **Windows only.** The `keychain` API this calls is platform-agnostic,
//! so anywhere else it would quietly probe the Secure Enclave or the Linux
//! TPM instead — a different backend reporting under a Windows name. Off
//! Windows it refuses to run rather than answer a question nobody asked.
//!
//! Exercises the same store/retrieve/delete path wallet creation uses,
//! without touching a real wallet: it uses wallet id `u32::MAX` and can
//! clean up everything it created. Each step prompts for the PIN through
//! pinentry, exactly as a real unlock does.
//!
//!     cargo run -p keychain --example windows_tpm_probe
//!
//! Splitting it across two processes additionally proves the sealed blob
//! survives on disk and reopens in a fresh process — the thing a user
//! actually depends on when unlocking a wallet the next day:
//!
//!     cargo run -p keychain --example windows_tpm_probe -- store
//!     cargo run -p keychain --example windows_tpm_probe -- retrieve
//!     cargo run -p keychain --example windows_tpm_probe -- clean
//!
//! **Always finish with `-- clean`.** Between `store` and `clean` a wallet
//! directory named `4294967295` exists, and leaving it there breaks new
//! wallet creation — see `refuse_if_present` below.
//!
//! Note this probe cannot tell you whether the provider is performing
//! genuine TPM sealing rather than an RSA wrap — that question is settled
//! by the `seal_is_not_rsa` test in `tpm_windows.rs`, and the whole
//! post-quantum claim rests on it. Run that too:
//!
//!     cargo test -p keychain --lib -- --ignored --nocapture

#[cfg(target_os = "windows")]
const WALLET_ID: u32 = u32::MAX;

/// Names the backend that would have been probed, so the refusal reads as
/// a deliberate guard rather than a build that went wrong.
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!(
        "REFUSED: windows_tpm_probe runs on Windows only; this is {}. \
         Here it would exercise {}, not the Windows TPM.",
        std::env::consts::OS,
        keychain::display_name()
    );
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
fn main() {
    let secret: Vec<u8> = (0u8..32).collect();

    match std::env::args().nth(1).as_deref() {
        Some("store") => {
            store(&secret);
            println!("\nNow run `-- retrieve` in a fresh process.");
        }
        Some("retrieve") => {
            retrieve(&secret);
            println!("\nRemember to run `-- clean`.");
        }
        Some("clean") => {
            cleanup();
            println!("Cleaned up.");
        }
        Some(other) => {
            eprintln!("Unknown mode {other:?}; expected store, retrieve or clean.");
            std::process::exit(2);
        }
        None => {
            store(&secret);
            retrieve(&secret);
            cleanup();
            println!("\n{} works.", keychain::display_name());
        }
    }
}

/// Refuses to run if the throwaway wallet directory is already present.
///
/// `u32::MAX` is not a reserved id — it is an ordinary wallet directory
/// name, and `next_wallet_id()` computes `max + 1` (`db/wallets.rs:56`).
/// Leaving one behind therefore overflows the allocator: a panic in debug,
/// and in release a wrap to 0 that collides with the first real wallet.
/// Refusing here means the only way to reach that state is to skip
/// `-- clean`, which every message below insists on.
#[cfg(target_os = "windows")]
fn refuse_if_present() {
    if let Ok(dir) = qpv2_core::db::get_wallet_dir(WALLET_ID) {
        if dir.exists() {
            eprintln!(
                "REFUSED: {} already exists. Run `-- clean` first — leaving it \
                 in place breaks wallet id allocation.",
                dir.display()
            );
            std::process::exit(2);
        }
    }
}

#[cfg(target_os = "windows")]
fn store(secret: &[u8]) {
    refuse_if_present();
    println!("store_key (seals to the TPM; asks you to set a PIN)...");
    if let Err(e) = keychain::store_key(WALLET_ID, secret) {
        eprintln!("      FAILED: {}", e);
        cleanup();
        std::process::exit(1);
    }
    println!("      ok");
}

#[cfg(target_os = "windows")]
fn retrieve(secret: &[u8]) {
    println!("retrieve_key (unseals; asks for the same PIN)...");
    match keychain::retrieve_key(WALLET_ID, "unseal the probe key") {
        Ok(got) if got.as_ref() == secret => println!("      ok — round-trip matches"),
        Ok(_) => {
            eprintln!("      FAILED: unsealed bytes differ from what was stored");
            cleanup();
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("      FAILED: {}", e);
            cleanup();
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "windows")]
fn cleanup() {
    if let Err(e) = keychain::delete_key(WALLET_ID) {
        eprintln!("delete_key FAILED: {}", e);
    }
    if let Ok(dir) = qpv2_core::db::get_wallet_dir(WALLET_ID) {
        let _ = std::fs::remove_dir(dir);
    }
}
