#[cfg(feature = "fido2")]
pub mod fido2;

#[cfg(target_os = "macos")]
mod secure_enclave;
#[cfg(target_os = "macos")]
pub use secure_enclave::{delete_key, retrieve_key, store_key};

#[cfg(target_os = "windows")]
mod tpm_lockout_windows;
#[cfg(target_os = "windows")]
mod tpm_windows;
#[cfg(target_os = "windows")]
pub use tpm_windows::{delete_key, retrieve_key, store_key};

#[cfg(target_os = "linux")]
mod tpm_linux;
#[cfg(target_os = "linux")]
pub use tpm_linux::{delete_key, retrieve_key, store_key};
