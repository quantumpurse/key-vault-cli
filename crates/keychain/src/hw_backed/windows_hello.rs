//! Windows Hello + TPM credential storage via Microsoft Passport KSP.
//!
//! Stores the 32-byte vault encryption key by wrapping it with an
//! RSA-2048 key held in the TPM via the Microsoft Passport Key Storage
//! Provider. Decryption triggers a Windows Hello biometric/PIN prompt.
//!
//! The wrapped ciphertext (~256 bytes) is persisted to disk alongside
//! the wallet files. The RSA private key never leaves the TPM.
//!
//! # Why Passport, out of the four Windows key storage providers
//!
//! | Provider                          | Key in hardware | Auth per use          |
//! |-----------------------------------|-----------------|-----------------------|
//! | Microsoft Software KSP            | no, DPAPI files | none                  |
//! | Microsoft Smart Card KSP          | yes             | yes, needs a card     |
//! | Microsoft Platform Crypto Provider| yes, TPM        | a PIN you build yourself |
//! | Microsoft Passport KSP  (this)    | yes, TPM        | Windows Hello gesture |
//!
//! Platform Crypto Provider reaches the same TPM and would avoid every
//! Passport quirk this file works around — the SID-prefixed key name,
//! `NTE_NO_KEY`, the rejected `NCRYPT_PERSIST_FLAG`, `NgcKeyImplType`,
//! PKCS#1 padding, the decrypt usage flag. It can gate a key too, with a
//! usage-auth PIN set through `NCRYPT_PIN_PROPERTY` or
//! `NCRYPT_PCP_USAGEAUTH_PROPERTY` and covered by the TPM's dictionary
//! attack protection. What it does not give is the authentication
//! *experience*: no biometrics, and the PIN is ours to define, collect,
//! prompt for and support. A wallet that invents its own PIN scheme has
//! taken on the part of this problem the OS already solved.
//!
//! Passport instead reuses the Hello enrolment the user already has —
//! face, fingerprint, or their existing PIN — with Windows drawing the
//! prompt and the TPM rate-limiting it. Its awkward API is the price of
//! that. Smart Card KSP needs hardware most users lack; the FIDO2 auth
//! method covers those who have it.
//!
//! That advantage is only real while the gesture is genuinely enforced,
//! which rests on two undocumented properties — see `NgcCacheType` in
//! `open_or_create_key` and the `gesture_is_enforced` test.

use crate::{account_name, KEY_LEN, SERVICE};
use qpv2_core::SecureVec;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, HANDLE, HWND, NTE_BAD_KEYSET, NTE_NO_KEY,
    NTE_USER_CANCELLED,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, BCRYPT_RSA_ALGORITHM, NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_IMPL_HARDWARE_FLAG,
    NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY,
    NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    NCRYPT_WINDOW_HANDLE_PROPERTY,
};
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow;

const WRAPPED_KEY_FILE: &str = "wrapped_key.bin";

fn passport_provider() -> Vec<u16> {
    "Microsoft Passport Key Storage Provider"
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

/// When a machine is shared by multiple people, the Passport KSP
/// equires each user's keys to be stored under their own SID.
/// This function retrieves the current user's SID in string form (`S-1-5-21-…`),
/// which is used as the first segment of the key name when creating
/// or accessing keys in the Passport KSP.
///
/// The Passport KSP requires it as the first path segment of every key
/// name; see [`key_name`].
fn current_user_sid() -> Result<String, String> {
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    unsafe {
        let mut raw: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) == 0 {
            return Err(format!("Failed to open process token: {}.", GetLastError()));
        }
        let token = TokenHandle(raw);

        // First call sizes the TOKEN_USER buffer (it fails with
        // ERROR_INSUFFICIENT_BUFFER, which is expected).
        let mut needed: u32 = 0;
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(format!(
                "Failed to size token user info: {}.",
                GetLastError()
            ));
        }

        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(format!(
                "Failed to query token user info: {}.",
                GetLastError()
            ));
        }

        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_str) == 0 {
            return Err(format!(
                "Failed to convert SID to string: {}.",
                GetLastError()
            ));
        }

        let len = (0..).take_while(|&i| *sid_str.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
        LocalFree(sid_str.cast());
        Ok(sid)
    }
}

/// Passport KSP key names are paths whose **first segment must be the
/// owning user's SID** — the provider parses it and rejects anything
/// else with `ERROR_INVALID_SID` (0x80070539). The remaining segments
/// are `<container>/<domain>/<subdomain>/<name>`; Windows' own keys look
/// like `<SID>/<guid>/login.live.com//<id>`. Leaving the container
/// segment empty lets the KSP use the user's default Hello container.
fn key_name(wallet_id: u32) -> Result<Vec<u16>, String> {
    let sid = current_user_sid()?;
    Ok(format!("{}//{}//{}", sid, SERVICE, account_name(wallet_id))
        .encode_utf16()
        .chain(Some(0))
        .collect())
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

/// Treats a status as "there is no key to open".
///
/// `NCryptOpenKey` against the Passport KSP answers `NTE_NO_KEY` for an
/// absent key — not the `NTE_BAD_KEYSET` its documentation lists. That is
/// why widening this check was necessary: with the key name corrected but
/// the old `status != NTE_BAD_KEYSET` test still in place, an absent key
/// would have read as a hard failure and the create path stayed
/// unreachable.
fn key_not_found(status: i32) -> bool {
    status == NTE_NO_KEY || status == NTE_BAD_KEYSET
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

/// Rejects a key that Windows Hello backed with software instead of the
/// TPM.
///
/// The Passport KSP does not implement the standard
/// `NCRYPT_IMPL_TYPE_PROPERTY` ("Impl Type") — asking for it fails with
/// `NTE_NOT_SUPPORTED`. It exposes `NgcKeyImplType` instead, carrying
/// the same `NCRYPT_IMPL_*` flag values. `certutil -csp "Microsoft
/// Passport Key Storage Provider" -key -v` prints it for every key.
fn require_hardware_backed(hkey: NCRYPT_KEY_HANDLE) -> Result<(), String> {
    let property = to_utf16("NgcKeyImplType");
    let mut impl_type: u32 = 0;
    let mut result_len: u32 = 0;
    let status = unsafe {
        NCryptGetProperty(
            hkey,
            property.as_ptr(),
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

/// Sets a DWORD key property.
///
/// Flags are 0, not `NCRYPT_PERSIST_FLAG`: the Passport KSP rejects that
/// flag with `NTE_BAD_FLAGS` (0x80090009). Properties set before
/// `NCryptFinalizeKey` are stored with the key regardless.
fn set_u32_property(
    hkey: NCRYPT_KEY_HANDLE,
    property: *const u16,
    value: u32,
    context: &str,
) -> Result<(), String> {
    let status =
        unsafe { NCryptSetProperty(hkey, property, &value as *const u32 as *const u8, 4, 0) };
    if status != 0 {
        return Err(status_to_err(status, context));
    }
    Ok(())
}

/// Parents the Windows Hello prompt to the calling thread's active
/// window.
///
/// The prompt belongs to a separate Windows process, so with no owner
/// window it cannot raise itself above the app — the foreground lock
/// leaves it blinking in the taskbar instead. `GetActiveWindow` is
/// thread-local, so it can only ever return a window this thread owns;
/// callers off the UI thread get null and the old behaviour.
fn set_window_handle(hkey: NCRYPT_KEY_HANDLE) {
    let hwnd = unsafe { GetActiveWindow() };
    if hwnd.is_null() {
        return;
    }
    unsafe {
        NCryptSetProperty(
            hkey,
            NCRYPT_WINDOW_HANDLE_PROPERTY,
            &hwnd as *const HWND as *const u8,
            std::mem::size_of::<HWND>() as u32,
            0,
        )
    };
}

/// Sets the message Windows Hello shows in its prompt.
///
/// This is a per-session property of the *handle*, not of the stored
/// key, so it has to be set again on every handle whose use triggers a
/// gesture — above all the decrypt handle in [`retrieve_key`], which is
/// the one the user actually reads.
fn set_use_context(hkey: NCRYPT_KEY_HANDLE) -> Result<(), String> {
    let property = to_utf16("Use Context");
    let message = to_utf16("Unlock Quantum Purse wallet");
    let status = unsafe {
        NCryptSetProperty(
            hkey,
            property.as_ptr(),
            message.as_ptr() as *const u8,
            (message.len() * 2) as u32,
            0,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to set UI context message"));
    }
    Ok(())
}

fn open_or_create_key(hprov: NCRYPT_PROV_HANDLE, wallet_id: u32) -> Result<KeyHandle, String> {
    let name = key_name(wallet_id)?;
    let mut hkey: NCRYPT_KEY_HANDLE = 0;

    let status = unsafe { NCryptOpenKey(hprov, &mut hkey, name.as_ptr(), 0, 0) };

    // open existing key successfully, return it.
    if status == 0 {
        let key = KeyHandle(hkey);
        require_hardware_backed(key.0)?;
        return Ok(key);
    }

    // open key failed. Check if no key found.
    if !key_not_found(status) {
        return Err(status_to_err(status, "Failed to open existing key"));
    }

    // let's create a new key.
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
    set_u32_property(
        key.0,
        NCRYPT_LENGTH_PROPERTY,
        2048,
        "Failed to set key length",
    )?;

    // Passport keys are created signing-only. Without this the TPM
    // refuses to unwrap the vault key: NCryptDecrypt fails with
    // NTE_BAD_KEY (0x80090003). Decrypt is the only usage granted —
    // nothing here ever signs with this key.
    set_u32_property(
        key.0,
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_DECRYPT_FLAG,
        "Failed to set key usage",
    )?;

    // Require Windows Hello authentication on every key use.
    let prop_cache_type = to_utf16("NgcCacheType");
    const AUTH_MANDATORY_FLAG: u32 = 1;
    set_u32_property(
        key.0,
        prop_cache_type.as_ptr(),
        AUTH_MANDATORY_FLAG,
        "Failed to set cache type",
    )?;

    // Require PIN/biometric gesture.
    let prop_gesture = to_utf16("PinCacheIsGestureRequired");
    set_u32_property(
        key.0,
        prop_gesture.as_ptr(),
        1,
        "Failed to set gesture requirement",
    )?;

    set_use_context(key.0)?;
    set_window_handle(key.0);

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

    // key has been created. return it.
    Ok(key)
}

pub fn store_key(wallet_id: u32, key: &[u8]) -> Result<(), String> {
    if key.len() != KEY_LEN {
        return Err(format!("Expected {KEY_LEN}-byte key, got {}.", key.len()));
    }

    let prov = open_provider()?;
    let hkey = open_or_create_key(prov.0, wallet_id)?;

    // First call: get required output size.
    let mut cipher_len: u32 = 0;
    // Padding is PKCS#1 v1.5: the TPM key it creates is bound to the PKCS#1 scheme.
    // A padding oracle is not reachable here — every decrypt costs an interactive.
    let status = unsafe {
        NCryptEncrypt(
            hkey.0,
            key.as_ptr(),
            key.len() as u32,
            ptr::null(),
            ptr::null_mut(),
            0,
            &mut cipher_len,
            NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG,
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
            ptr::null(),
            ciphertext.as_mut_ptr(),
            cipher_len,
            &mut actual_len,
            NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(status_to_err(status, "Failed to encrypt key"));
    }
    ciphertext.truncate(actual_len as usize);

    // The wallet directory does not exist yet while a wallet is being
    // created: the vault only creates it when it writes the seed, which
    // happens after this. Create it here rather than earlier so a
    // cancelled gesture leaves nothing behind.
    let path = qpv2_core::db::create_wallet_dir(wallet_id)
        .map_err(|e| e.to_string())?
        .join(WRAPPED_KEY_FILE);
    std::fs::write(&path, &ciphertext)
        .map_err(|e| format!("Failed to write {}: {}.", WRAPPED_KEY_FILE, e))?;

    Ok(())
}

pub fn retrieve_key(wallet_id: u32) -> Result<SecureVec, String> {
    let prov = open_provider()?;
    let name = key_name(wallet_id)?;
    let mut hkey: NCRYPT_KEY_HANDLE = 0;

    // Open without NCRYPT_SILENT_FLAG so Windows Hello prompt fires.
    let status = unsafe { NCryptOpenKey(prov.0, &mut hkey, name.as_ptr(), 0, 0) };
    if status != 0 {
        return Err(status_to_err(status, "Failed to open key"));
    }
    let hkey = KeyHandle(hkey);

    let _ = set_use_context(hkey.0);
    set_window_handle(hkey.0);

    let path = wrapped_key_path(wallet_id)?;
    let ciphertext =
        std::fs::read(&path).map_err(|e| format!("Failed to read {}: {}.", WRAPPED_KEY_FILE, e))?;

    // Single decrypt call. RSA-2048 plaintext ≤ 256 bytes; skipping
    // the size-probe avoids a potential duplicate Windows Hello prompt.
    let mut plaintext = vec![0u8; 256];
    let mut actual_len: u32 = 0;
    let status = unsafe {
        NCryptDecrypt(
            hkey.0,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            ptr::null(),
            plaintext.as_mut_ptr(),
            256,
            &mut actual_len,
            NCRYPT_PAD_PKCS1_FLAG,
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
    let name = key_name(wallet_id)?;
    let mut hkey: NCRYPT_KEY_HANDLE = 0;

    let status = unsafe { NCryptOpenKey(prov.0, &mut hkey, name.as_ptr(), 0, 0) };
    if key_not_found(status) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::NTE_SILENT_CONTEXT;

    /// Proves the stored key really is gesture-gated rather than merely
    /// asked to be. Windows draws the Hello prompt itself, so watching
    /// the screen cannot tell us whether the gesture was *required* or
    /// just offered — but a silent decrypt can: a key with
    /// `NgcCacheType = AUTH_MANDATORY` must refuse to operate without a
    /// UI context. If it succeeds instead, the TPM key is usable with no
    /// authentication at all and the Windows Hello protection is nominal.
    /// A decrypt that *succeeded* is the only thing asserted here.
    ///
    /// A refusal carrying some status other than `NTE_SILENT_CONTEXT` is
    /// printed but not asserted, because it means the key declined for an
    /// unrelated reason — wrong key usage answers `NTE_BAD_KEY`, a
    /// padding or ciphertext mismatch answers something else again.
    /// Asserting the exact status would brand any such bug a gesture
    /// failure and send the reader to the wrong four lines.
    ///
    /// Touches the real TPM and leaves a Hello prompt on screen, so it
    /// is `#[ignore]`d. Run it with:
    ///
    ///     cargo test -p keychain --lib -- --ignored --nocapture
    #[test]
    #[ignore]
    fn gesture_is_enforced() {
        const WALLET: u32 = u32::MAX;
        let secret: Vec<u8> = (0u8..32).collect();

        // Start from nothing. `open_or_create_key` hands back an existing
        // key without reapplying the gesture properties, so one left
        // behind by an aborted run — or by `examples/windows_hello_probe`,
        // which shares this wallet id — would be retested here and keep
        // failing long after the bug that created it was fixed.
        let _ = delete_key(WALLET);

        store_key(WALLET, &secret).expect("store_key");

        let prov = open_provider().expect("open provider");
        let name = key_name(WALLET).expect("key name");
        let mut raw: NCRYPT_KEY_HANDLE = 0;
        let status = unsafe { NCryptOpenKey(prov.0, &mut raw, name.as_ptr(), 0, 0) };
        assert_eq!(status, 0, "open key: 0x{:08X}", status as u32);
        let hkey = KeyHandle(raw);

        // Read the gesture properties back: a KSP that accepted the
        // NCryptSetProperty call may still have dropped the value.
        for property in ["NgcCacheType", "PinCacheIsGestureRequired"] {
            let wide = to_utf16(property);
            let mut value: u32 = 0;
            let mut len: u32 = 0;
            let status = unsafe {
                NCryptGetProperty(
                    hkey.0,
                    wide.as_ptr(),
                    &mut value as *mut u32 as *mut u8,
                    4,
                    &mut len,
                    0,
                )
            };
            println!("{property} = {value} (status 0x{:08X})", status as u32);
        }

        let ciphertext = std::fs::read(wrapped_key_path(WALLET).expect("path")).expect("read");
        let mut plaintext = vec![0u8; 256];
        let mut actual_len: u32 = 0;
        let silent = unsafe {
            NCryptDecrypt(
                hkey.0,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                ptr::null(),
                plaintext.as_mut_ptr(),
                256,
                &mut actual_len,
                NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        println!("silent decrypt -> 0x{:08X}", silent as u32);

        let unauthenticated = silent == 0 && plaintext[..actual_len as usize] == secret[..];
        drop(hkey);
        let _ = delete_key(WALLET);
        let _ = std::fs::remove_dir(qpv2_core::db::get_wallet_dir(WALLET).expect("dir"));

        assert!(
            !unauthenticated,
            "the TPM key decrypted the vault key with no gesture: Windows Hello \
             is not actually gating this wallet"
        );
        if silent != NTE_SILENT_CONTEXT {
            println!(
                "note: refused with 0x{:08X}, not NTE_SILENT_CONTEXT \
                 (0x80090022) — the gesture held, but check key usage and \
                 padding before suspecting the gesture properties",
                silent as u32
            );
        }
    }
}
