//! Windows Hello + TPM credential storage via Microsoft Passport KSP.
//!
//! Stores the 32-byte vault encryption key by wrapping it with an
//! RSA-2048 key held in the TPM via the Microsoft Passport Key Storage
//! Provider. Decryption triggers a Windows Hello biometric/PIN prompt.
//!
//! The wrapped ciphertext (~256 bytes) is persisted to disk alongside
//! the wallet files. The RSA private key never leaves the TPM.

use crate::{account_name, KEY_LEN, SERVICE};
use qpv2_core::SecureVec;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{NTE_BAD_KEYSET, NTE_USER_CANCELLED};
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
    NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE,
    NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PERSIST_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SILENT_FLAG,
};

const WRAPPED_KEY_FILE: &str = "wrapped_key.bin";

fn passport_provider() -> Vec<u16> {
    "Microsoft Passport Key Storage Provider"
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

fn key_name(wallet_id: u32) -> Vec<u16> {
    format!("{}/{}", SERVICE, account_name(wallet_id))
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

fn wrapped_key_path(wallet_id: u32) -> Result<PathBuf, String> {
    qpv2_core::db::get_wallet_dir(wallet_id)
        .map(|d| d.join(WRAPPED_KEY_FILE))
        .map_err(|e| e.to_string())
}

fn status_to_err(status: i32, context: &str) -> String {
    if status == NTE_USER_CANCELLED {
        "Cancelled.".to_string()
    } else {
        format!("{}: SECURITY_STATUS 0x{:08X}.", context, status as u32)
    }
}

fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

struct ProvHandle(NCRYPT_PROV_HANDLE);

impl Drop for ProvHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

struct KeyHandle(NCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

fn open_provider() -> Result<ProvHandle, String> {
    let provider = passport_provider();
    let mut hprov: NCRYPT_PROV_HANDLE = 0;
    let status = unsafe { NCryptOpenStorageProvider(&mut hprov, provider.as_ptr(), 0) };
    if status != 0 {
        return Err(status_to_err(
            status,
            "Failed to open Microsoft Passport Key Storage Provider. \
			 Ensure Windows Hello is configured",
        ));
    }
    Ok(ProvHandle(hprov))
}

fn require_hardware_backed(hkey: NCRYPT_KEY_HANDLE) -> Result<(), String> {
    let mut impl_type: u32 = 0;
    let mut result_len: u32 = 0;
    let status = unsafe {
        NCryptGetProperty(
            hkey,
            NCRYPT_IMPL_TYPE_PROPERTY,
            &mut impl_type as *mut u32 as *mut u8,
            std::mem::size_of::<u32>() as u32,
            &mut result_len,
            0,
        )
    };
    if status != 0 {
        return Err(status_to_err(
            status,
            "Failed to query key implementation type",
        ));
    }
    if impl_type & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
        return Err(
            "Hardware-backed key storage requires TPM 2.0. Your system does not \
             have a compatible TPM, or Windows Hello is not configured to use it."
                .to_string(),
        );
    }
    Ok(())
}

fn open_or_create_key(hprov: NCRYPT_PROV_HANDLE, wallet_id: u32) -> Result<KeyHandle, String> {
    let name = key_name(wallet_id);
    let mut hkey: NCRYPT_KEY_HANDLE = 0;

    let status = unsafe { NCryptOpenKey(hprov, &mut hkey, name.as_ptr(), 0, 0) };
    if status == 0 {
        let key = KeyHandle(hkey);
        require_hardware_backed(key.0)?;
        return Ok(key);
    }
    if status != NTE_BAD_KEYSET {
        return Err(status_to_err(status, "Failed to open existing key"));
    }

    let status = unsafe {
        NCryptCreatePersistedKey(
            hprov,
            &mut hkey,
            BCRYPT_RSA_ALGORITHM,
            name.as_ptr(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to create RSA key in TPM"));
    }

    let key = KeyHandle(hkey);

    // Set key length to 2048 bits.
    let key_length: u32 = 2048;
    let prop_length = to_utf16("Length");
    let status = unsafe {
        NCryptSetProperty(
            key.0,
            prop_length.as_ptr(),
            &key_length as *const u32 as *const u8,
            4,
            NCRYPT_PERSIST_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to set key length"));
    }

    // Require Windows Hello authentication on every key use.
    let prop_cache_type = to_utf16("NgcCacheType");
    let cache_type: u32 = 1; // AUTH_MANDATORY_FLAG
    let status = unsafe {
        NCryptSetProperty(
            key.0,
            prop_cache_type.as_ptr(),
            &cache_type as *const u32 as *const u8,
            4,
            NCRYPT_PERSIST_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to set cache type"));
    }

    // Require PIN/biometric gesture.
    let prop_gesture = to_utf16("PinCacheIsGestureRequired");
    let gesture_required: u32 = 1;
    let status = unsafe {
        NCryptSetProperty(
            key.0,
            prop_gesture.as_ptr(),
            &gesture_required as *const u32 as *const u8,
            4,
            NCRYPT_PERSIST_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to set gesture requirement"));
    }

    // Per-session UI hint, not a persisted key property — flag is 0
    // intentionally (not NCRYPT_PERSIST_FLAG).
    let prop_context = to_utf16("Use Context");
    let context_msg = to_utf16("Unlock Quantum Purse wallet");
    let status = unsafe {
        NCryptSetProperty(
            key.0,
            prop_context.as_ptr(),
            context_msg.as_ptr() as *const u8,
            (context_msg.len() * 2) as u32,
            0,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to set UI context message"));
    }

    let status = unsafe { NCryptFinalizeKey(key.0, 0) };
    if status != 0 {
        return Err(status_to_err(status, "Failed to finalize key"));
    }

    if let Err(e) = require_hardware_backed(key.0) {
        let handle = key.0;
        std::mem::forget(key);
        unsafe { NCryptDeleteKey(handle, 0) };
        return Err(e);
    }

    Ok(key)
}

fn oaep_padding() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: ptr::null_mut(),
        cbLabel: 0,
    }
}

pub fn store_key(wallet_id: u32, key: &[u8]) -> Result<(), String> {
    if key.len() != KEY_LEN {
        return Err(format!("Expected {KEY_LEN}-byte key, got {}.", key.len()));
    }

    let prov = open_provider()?;
    let hkey = open_or_create_key(prov.0, wallet_id)?;

    let padding = oaep_padding();

    // First call: get required output size.
    let mut cipher_len: u32 = 0;
    let status = unsafe {
        NCryptEncrypt(
            hkey.0,
            key.as_ptr(),
            key.len() as u32,
            &padding as *const _ as *const _,
            ptr::null_mut(),
            0,
            &mut cipher_len,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to determine ciphertext size"));
    }

    // Second call: encrypt.
    let mut ciphertext = vec![0u8; cipher_len as usize];
    let mut actual_len: u32 = 0;
    let status = unsafe {
        NCryptEncrypt(
            hkey.0,
            key.as_ptr(),
            key.len() as u32,
            &padding as *const _ as *const _,
            ciphertext.as_mut_ptr(),
            cipher_len,
            &mut actual_len,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to encrypt key"));
    }
    ciphertext.truncate(actual_len as usize);

    let path = wrapped_key_path(wallet_id)?;
    std::fs::write(&path, &ciphertext)
        .map_err(|e| format!("Failed to write {}: {}.", WRAPPED_KEY_FILE, e))?;

    Ok(())
}

pub fn retrieve_key(wallet_id: u32) -> Result<SecureVec, String> {
    let prov = open_provider()?;
    let name = key_name(wallet_id);
    let mut hkey: NCRYPT_KEY_HANDLE = 0;

    // Open without NCRYPT_SILENT_FLAG so Windows Hello prompt fires.
    let status = unsafe { NCryptOpenKey(prov.0, &mut hkey, name.as_ptr(), 0, 0) };
    if status != 0 {
        return Err(status_to_err(status, "Failed to open key"));
    }
    let hkey = KeyHandle(hkey);

    let path = wrapped_key_path(wallet_id)?;
    let ciphertext =
        std::fs::read(&path).map_err(|e| format!("Failed to read {}: {}.", WRAPPED_KEY_FILE, e))?;

    let padding = oaep_padding();

    // Single decrypt call. RSA-2048 plaintext ≤ 256 bytes; skipping
    // the size-probe avoids a potential duplicate Windows Hello prompt.
    let mut plaintext = vec![0u8; 256];
    let mut actual_len: u32 = 0;
    let status = unsafe {
        NCryptDecrypt(
            hkey.0,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            &padding as *const _ as *const _,
            plaintext.as_mut_ptr(),
            256,
            &mut actual_len,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Decryption failed"));
    }
    plaintext.truncate(actual_len as usize);

    // Move into a zeroizing buffer before validating, so the
    // length-mismatch path can't drop the decrypted key in the clear.
    let plaintext = SecureVec::from_vec(plaintext);
    if plaintext.len() != KEY_LEN {
        return Err(format!(
            "Decrypted {}-byte key, expected {KEY_LEN}.",
            plaintext.len()
        ));
    }

    Ok(plaintext)
}

pub fn delete_key(wallet_id: u32) -> Result<(), String> {
    let prov = open_provider()?;
    let name = key_name(wallet_id);
    let mut hkey: NCRYPT_KEY_HANDLE = 0;

    let status = unsafe { NCryptOpenKey(prov.0, &mut hkey, name.as_ptr(), 0, 0) };
    if status == NTE_BAD_KEYSET {
        // Key doesn't exist — nothing to delete from TPM.
    } else if status != 0 {
        return Err(status_to_err(status, "Failed to open key for deletion"));
    } else {
        // NCryptDeleteKey frees the handle on success.
        let status = unsafe { NCryptDeleteKey(hkey, 0) };
        if status != 0 {
            unsafe { NCryptFreeObject(hkey) };
            return Err(status_to_err(status, "Failed to delete key"));
        }
    }

    let path = wrapped_key_path(wallet_id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("Failed to remove {}: {}.", WRAPPED_KEY_FILE, e)),
    }

    Ok(())
}
