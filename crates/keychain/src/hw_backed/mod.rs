#[cfg(feature = "fido2")]
pub mod fido2;

#[cfg(target_os = "macos")]
mod secure_enclave;
#[cfg(target_os = "macos")]
pub use secure_enclave::{delete_key, retrieve_key, store_key};

#[cfg(target_os = "windows")]
mod windows_tpm;
#[cfg(target_os = "windows")]
pub use windows_tpm::{delete_key, retrieve_key, store_key};

#[cfg(target_os = "linux")]
mod linux_tpm;
#[cfg(target_os = "linux")]
pub use linux_tpm::{delete_key, retrieve_key, store_key};
