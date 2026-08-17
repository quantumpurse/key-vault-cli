//! Multi-platform credential storage.
//!
//! Stores and retrieves a 32-byte AES-256 encryption key using
//! the platform's native credential store:
//! - macOS: Data Protection Keychain with Touch ID biometric gating.
//! - Windows: TPM seal/unseal via the Platform Crypto Provider, PIN-gated.
//! - Linux: TPM seal/unseal via `tss-esapi`, PIN-gated.
//!
//! Optionally provides FIDO2 hardware key authentication via
//! the `fido2` feature flag.

// Only the macOS backend namespaces its items by service and account;
// both TPM backends locate their sealed blob by file path instead.
#[cfg(target_os = "macos")]
pub(crate) const SERVICE: &str = "quantumpurse";
#[cfg(target_os = "macos")]
pub(crate) fn account_name(wallet_id: u32) -> String {
    format!("vault-encryption-key-{}", wallet_id)
}
pub(crate) const KEY_LEN: usize = 32;

pub mod hw_backed;
#[cfg(feature = "fido2")]
pub use hw_backed::fido2;
pub use hw_backed::{delete_key, retrieve_key, store_key};

pub fn display_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Touch ID (Keychain)"
    }
    #[cfg(target_os = "windows")]
    {
        "TPM"
    }
    #[cfg(target_os = "linux")]
    {
        "TPM"
    }
}

pub fn short_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Touch ID"
    }
    #[cfg(target_os = "windows")]
    {
        "TPM"
    }
    #[cfg(target_os = "linux")]
    {
        "TPM"
    }
}
