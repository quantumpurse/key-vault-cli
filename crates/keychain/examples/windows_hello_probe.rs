//! Round-trips a throwaway key through the Windows TPM.
//!
//! **Windows only.** The `keychain` API this calls is platform-agnostic,
//! so anywhere else it would quietly probe the Secure Enclave or the Linux
//! TPM instead — a different backend reporting under a Windows name. Off
//! Windows it refuses to run rather than answer a question nobody asked.
//!
//! Exercises the same store/retrieve/delete path wallet creation uses,
//! without touching a real wallet: it uses wallet id `u32::MAX` and can
//! clean up everything it created.
//!
//!     cargo run -p keychain --example windows_hello_probe
//!
//! The whole round trip in one process cannot tell you whether unlocking
//! really demands a gesture, because the gesture taken while the key was
//! created may still be cached. Split it across two processes to see
//! what a user actually gets when unlocking a wallet later:
//!
//!     cargo run -p keychain --example windows_hello_probe -- store
//!     cargo run -p keychain --example windows_hello_probe -- retrieve
//!     cargo run -p keychain --example windows_hello_probe -- clean

#[cfg(target_os = "windows")]
const WALLET_ID: u32 = u32::MAX;

/// Names the backend that would have been probed, so the refusal reads as
/// a deliberate guard rather than a build that went wrong.
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!(
        "REFUSED: windows_hello_probe runs on Windows only; this is {}. \
         Here it would exercise {}, not Windows Hello.",
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
            store(&secret); // Second call re-uses the key instead of creating it.
            retrieve(&secret);
            cleanup();
            println!("\n{} works.", keychain::display_name());
        }
    }
}

#[cfg(target_os = "windows")]
fn store(secret: &[u8]) {
    println!("store_key (creates the TPM key on first run, may prompt)...");
    if let Err(e) = keychain::store_key(WALLET_ID, secret) {
        eprintln!("      FAILED: {}", e);
        cleanup();
        std::process::exit(1);
    }
    println!("      ok");
}

#[cfg(target_os = "windows")]
fn retrieve(secret: &[u8]) {
    println!("retrieve_key (Windows Hello prompt expected)...");
    let started = std::time::Instant::now();
    match keychain::retrieve_key(WALLET_ID) {
        Ok(got) if got.as_ref() == secret => {
            // A gesture cannot be answered in a few milliseconds, so the
            // elapsed time says whether a human was really in the loop.
            println!(
                "      ok — round-trip matches, took {:?}",
                started.elapsed()
            );
        }
        Ok(_) => {
            eprintln!("      FAILED: decrypted bytes differ from what was stored");
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
