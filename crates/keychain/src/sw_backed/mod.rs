/// This module is currently not used, but could be
/// useful in some cases that require less security.
#[cfg(target_os = "linux")]
mod linux_secret_service;
#[cfg(target_os = "linux")]
pub use linux_secret_service::{delete_key, retrieve_key, store_key};

#[cfg(target_os = "windows")]
mod windows_dpapi;
#[cfg(target_os = "windows")]
pub use windows_dpapi::{delete_key, retrieve_key, store_key};
