//! Windows TPM seal/unseal credential storage via the Platform Crypto Provider.
//!
//! Stores the 32-byte vault encryption key by asking the TPM to seal it,
//! through the Platform Crypto Provider's well-known seal key
//! `TPM_RSA_SRK_SEAL_KEY`. The resulting blob is written to the wallet
//! directory. A PIN is required to seal and to unseal, supplied as the
//! seal password. This mirrors [`tpm_linux`](super::tpm_linux), which
//! seals through `tss-esapi`.

use super::tpm_lockout_windows as lockout;
use crate::KEY_LEN;
use qpv2_core::SecureVec;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{
    NTE_BAD_DATA, NTE_PERM, TPM_20_E_AUTH_FAIL, TPM_20_E_LOCKOUT, TPM_E_AUTHFAIL,
    TPM_E_DEFEND_LOCK_RUNNING, TPM_E_LOCKED_OUT, TPM_E_NOTSEALED_BLOB,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptBuffer, BCryptBufferDesc, NCryptDecrypt, NCryptEncrypt, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, NCRYPTBUFFER_TPM_SEAL_PASSWORD,
    NCRYPTBUFFER_VERSION, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SEALING_FLAG,
    TPM_RSA_SRK_SEAL_KEY,
};

/// Deliberately not the `tpm_sealed_blob.bin` that `tpm_linux.rs` writes.
/// The two formats are incompatible — Linux stores a length-prefixed
/// TPM2B_PRIVATE plus a marshalled public area, this stores an opaque PCP
/// blob — so a data directory carried between platforms should fail to
/// find its file rather than fail to parse someone else's.
const SEALED_BLOB_FILE: &str = "pcp_sealed_blob.bin";

/// TPM 2.0 caps a sealed object's payload at 128 bytes. Our key is 32.
const MAX_SEAL_INPUT: usize = 128;

/// A TPM authorization value is a `TPM2B_AUTH`, capped at the object's
/// name-algorithm digest size — 32 bytes under SHA-256. Passing the PIN's
/// bytes directly would silently truncate anything longer, so the PIN is
/// run through HKDF to exactly that length instead. This also makes the
/// value independent of how the PIN happens to be encoded.
const TPM_AUTH_LEN: usize = 32;

/// Domain separator for the seal authorization value. **Changing this
/// makes every existing sealed blob permanently unopenable**, which is
/// why it carries a version suffix rather than being edited in place.
const TPM_AUTH_HKDF_INFO: &[u8] = b"quantum-purse-v2/tpm-seal-auth/v1";

fn sealed_blob_path(wallet_id: u32) -> Result<PathBuf, String> {
    qpv2_core::db::get_wallet_dir(wallet_id)
        .map(|d| d.join(SEALED_BLOB_FILE))
        .map_err(|e| e.to_string())
}

fn status_to_err(status: i32, context: &str) -> String {
    format!("{}: SECURITY_STATUS 0x{:08X}.", context, status as u32)
}

/// Status codes meaning the TPM rejected the authorization value, which in
/// this module can only mean the PIN was wrong.
///
/// Three codes rather than one because the failure can be reported by any of
/// the layers the call passes through, and which one surfaces is the Platform
/// Crypto Provider's choice, not ours.
///
/// - `NTE_PERM` (`0x80090010`) is NCrypt's "access denied", and is the code
///   observed on TPM 2.0 hardware when the PIN is wrong.
/// - `TPM_20_E_AUTH_FAIL` (`0x8028008E`) is the TPM 2.0 chip's own
///   `TPM_RC_AUTH_FAIL`, raised when the supplied authorization value does not
///   match the one the sealed object was created with.
/// - `TPM_E_AUTHFAIL` (`0x80280001`) is the TPM 1.2 era equivalent, listed
///   defensively and not observed on TPM 2.0 hardware.
const AUTH_FAILED: &[i32] = &[NTE_PERM, TPM_20_E_AUTH_FAIL, TPM_E_AUTHFAIL];

/// Status codes meaning dictionary-attack lockout is in force. While locked
/// out the chip refuses to seal as well as unseal, so a user in this state
/// cannot even create a new wallet.
///
/// - `TPM_20_E_LOCKOUT` (`0x80280921`) is the TPM 2.0 chip's own
///   `TPM_RC_LOCKOUT`, and is the code observed on hardware after repeated
///   wrong PINs.
/// - `TPM_E_LOCKED_OUT` (`0x8029041B`) is the same condition reported from the
///   Platform Crypto Provider's error range rather than the chip's.
/// - `TPM_E_DEFEND_LOCK_RUNNING` (`0x80280803`) is the TPM 1.2 era
///   equivalent, meaning the chip's anti-hammering timer has not yet expired;
///   listed defensively and not observed on TPM 2.0 hardware.
const LOCKED_OUT: &[i32] = &[
    TPM_20_E_LOCKOUT,
    TPM_E_LOCKED_OUT,
    TPM_E_DEFEND_LOCK_RUNNING,
];

/// Explains a lockout and how to leave it, using the chip's own recovery
/// interval when it will report one.
///
/// Takes the state rather than reading it so a caller that has already paid
/// for a TBS round trip does not make a second one.
///
/// The cmdlet is `Unblock-Tpm`, not the `Reset TPM Lockout` wording used by
/// the `tpm.msc` console; naming the console's action would send the user to
/// PowerShell for a command that does not exist. It is also offered
/// conditionally, because Windows has not retained the TPM owner
/// authorization by default since Windows 10 1607, so for many users waiting
/// is the only route. `Clear-Tpm` is deliberately never suggested: it would
/// destroy every sealed blob on the machine, including this wallet's.
fn locked_out_message(state: Option<lockout::LockoutState>) -> String {
    let mut message = String::from("The TPM is locked out after too many wrong PINs.");
    if let Some(state) = state {
        message.push_str(&lockout::wait_sentence(&state));
    }
    message.push_str("`Unblock-Tpm` in an elevated PowerShell clears the lockout now.");
    message
}

/// Reports a failed unseal in terms of what the user did, and what it cost.
///
/// The attempt count comes from the chip rather than from any state this
/// wallet keeps, so it stays correct even though the counter is shared with
/// every other TPM consumer on the machine.
fn unseal_error(status: i32) -> String {
    if LOCKED_OUT.contains(&status) {
        return locked_out_message(lockout::read());
    }

    if AUTH_FAILED.contains(&status) {
        let mut message = String::from("Wrong PIN.");
        if let Some(state) = lockout::read() {
            // The failure that produced this status may have been the one
            // that exhausted the allowance, so describe the lockout it
            // caused rather than promising another try.
            if state.attempts_remaining() == Some(0) {
                return locked_out_message(Some(state));
            }
            message.push_str(&lockout::recorded_failures_sentence(&state));
        }
        // `NTE_PERM` is NCrypt's generic access-denied, and a wrong PIN is only
        // the meaning observed for it here. Keeping the code means a denial
        // this module has mis-attributed is still reportable, rather than
        // being presented to the user as a confident wrong answer.
        message.push_str(&format!(" ({})", status_to_err(status, "unseal")));
        return message;
    }

    if status == TPM_E_NOTSEALED_BLOB {
        // Documented as a corrupt or foreign blob, but observed on hardware
        // as the persistent unseal failure after repeated wrong PINs — it
        // keeps appearing even once the correct PIN is supplied, and clears
        // when the lockout does.
        let mut message = String::from(
            "The TPM refused the sealed blob. After repeated wrong PINs this \
             is the shape a lockout takes, and waiting it out restores \
             access.",
        );
        if let Some(state) = lockout::read() {
            message.push_str(&lockout::wait_sentence(&state));
        }
        message.push_str(
            " If it appears without any wrong PINs, the blob is corrupt or \
             from another machine, and only a seed-phrase restore recovers \
             the wallet.",
        );
        message.push_str(&format!(" ({})", status_to_err(status, "unseal")));
        return message;
    }

    if status == NTE_BAD_DATA {
        return format!(
            "The sealed blob is corrupt, or was sealed by a different machine. \
             A blob is bound to the TPM that produced it and cannot be moved \
             between computers. Restore this wallet from its seed phrase. \
             ({})",
            status_to_err(status, "unseal")
        );
    }

    status_to_err(status, "Failed to unseal key")
}

/// Reports a failed seal.
///
/// Sealing sets the PIN rather than checking one, so an authorization failure
/// here is not a wrong PIN and is left to the generic path. Lockout is the
/// case worth naming: it blocks sealing too, which is how a locked-out chip
/// stops a user creating a fresh wallet to escape the problem.
fn seal_error(status: i32, context: &str) -> String {
    if LOCKED_OUT.contains(&status) {
        return locked_out_message(lockout::read());
    }
    status_to_err(status, context)
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
    let mut hprov: NCRYPT_PROV_HANDLE = 0;
    let status =
        unsafe { NCryptOpenStorageProvider(&mut hprov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) };
    if status != 0 {
        return Err(status_to_err(
            status,
            "Failed to open Microsoft Platform Crypto Provider. \
             Ensure this machine has a TPM 2.0 and that it is enabled in the \
             BIOS/UEFI settings",
        ));
    }
    Ok(ProvHandle(hprov))
}

/// Opens the provider's well-known seal key.
///
/// A pure lookup — the key already exists, owned by the KSP and backed by
/// the TPM's storage root key, so nothing is created and nothing persists
/// afterwards. It takes no wallet id because there is only one such key on
/// the machine, shared by every caller; the returned handle is identical
/// whichever wallet is being sealed.
fn open_seal_key(hprov: NCRYPT_PROV_HANDLE) -> Result<KeyHandle, String> {
    let mut hkey: NCRYPT_KEY_HANDLE = 0;
    let status = unsafe { NCryptOpenKey(hprov, &mut hkey, TPM_RSA_SRK_SEAL_KEY, 0, 0) };
    if status != 0 {
        return Err(status_to_err(status, "Failed to open the TPM seal key"));
    }
    Ok(KeyHandle(hkey))
}

/// Owns the seal authorization value together with the parameter list
/// that points at it.
///
/// Keeping both in one struct is what makes the raw pointer safe: the
/// descriptor is produced by a method borrowing `self`, so it cannot
/// outlive the bytes it references. The value is a `SecureVec`, so it is
/// wiped when this is dropped rather than being handed back to the
/// allocator with the PIN-derived secret still in it.
struct SealAuth {
    value: SecureVec,
    buffers: [BCryptBuffer; 1],
}

impl SealAuth {
    fn new(pin: &str) -> Result<Self, String> {
        if pin.is_empty() {
            return Err("PIN cannot be empty.".to_string());
        }
        let value = qpv2_core::utilities::derive_hkdf_key(
            pin.as_bytes(),
            TPM_AUTH_HKDF_INFO,
            TPM_AUTH_LEN,
        )?;
        // Taken before `value` is moved into the struct: moving a
        // `SecureVec` moves the owning struct, not its heap allocation,
        // so the pointer stays valid.
        let buffers = [BCryptBuffer {
            cbBuffer: TPM_AUTH_LEN as u32,
            BufferType: NCRYPTBUFFER_TPM_SEAL_PASSWORD,
            pvBuffer: value.as_ptr() as *mut core::ffi::c_void,
        }];
        Ok(Self { value, buffers })
    }

    /// Borrows `&self`, not `&mut self`: the provider reads the parameter
    /// list and never writes to it, so no mutable reference is created
    /// and the raw pointer is not derived from a borrow that has already
    /// ended. `pBuffers` is typed `*mut` by the binding regardless.
    fn desc(&self) -> BCryptBufferDesc {
        debug_assert_eq!(self.value.len(), TPM_AUTH_LEN);
        BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: self.buffers.len() as u32,
            pBuffers: self.buffers.as_ptr() as *mut BCryptBuffer,
        }
    }
}

fn seal(hkey: NCRYPT_KEY_HANDLE, key: &[u8], pin: &str) -> Result<Vec<u8>, String> {
    if key.len() > MAX_SEAL_INPUT {
        return Err(format!(
            "Cannot seal {} bytes; the TPM's limit is {MAX_SEAL_INPUT}.",
            key.len()
        ));
    }

    let auth = SealAuth::new(pin)?;
    let desc = auth.desc();
    let desc_ptr = &desc as *const BCryptBufferDesc as *const core::ffi::c_void;

    // First call sizes the output buffer.
    let mut blob_len: u32 = 0;
    let status = unsafe {
        NCryptEncrypt(
            hkey,
            key.as_ptr(),
            key.len() as u32,
            desc_ptr,
            ptr::null_mut(),
            0,
            &mut blob_len,
            NCRYPT_SEALING_FLAG,
        )
    };
    if status != 0 {
        return Err(seal_error(status, "Failed to determine sealed blob size"));
    }

    let mut blob = vec![0u8; blob_len as usize];
    let mut actual_len: u32 = 0;
    let status = unsafe {
        NCryptEncrypt(
            hkey,
            key.as_ptr(),
            key.len() as u32,
            desc_ptr,
            blob.as_mut_ptr(),
            blob_len,
            &mut actual_len,
            NCRYPT_SEALING_FLAG,
        )
    };
    if status != 0 {
        return Err(seal_error(status, "Failed to seal key"));
    }
    blob.truncate(actual_len as usize);

    Ok(blob)
}

fn unseal(hkey: NCRYPT_KEY_HANDLE, blob: &[u8], pin: &str) -> Result<SecureVec, String> {
    let blob_len: u32 = blob
        .len()
        .try_into()
        .map_err(|_| format!("Sealed blob is implausibly large ({} bytes).", blob.len()))?;

    let auth = SealAuth::new(pin)?;
    let desc = auth.desc();
    let desc_ptr = &desc as *const BCryptBufferDesc as *const core::ffi::c_void;

    // Single call with a buffer large enough for any sealable payload, so
    // a wrong PIN costs one TPM authorization failure rather than two.
    let mut plaintext = vec![0u8; MAX_SEAL_INPUT];
    let mut actual_len: u32 = 0;
    let status = unsafe {
        NCryptDecrypt(
            hkey,
            blob.as_ptr(),
            blob_len,
            desc_ptr,
            plaintext.as_mut_ptr(),
            MAX_SEAL_INPUT as u32,
            &mut actual_len,
            NCRYPT_SEALING_FLAG,
        )
    };

    // Take ownership into a zeroizing buffer before inspecting the status:
    // a failing NCryptDecrypt may still have written into `plaintext`, and
    // the error path must not hand those bytes back to the allocator.
    // `SecureVec` derefs to `[u8]` and so has no `truncate`; the full
    // buffer is held here and the key copied out below. Both allocations
    // wipe on drop, so the surplus is never exposed.
    let buffer = SecureVec::from_vec(plaintext);
    if status != 0 {
        return Err(unseal_error(status));
    }

    let unsealed_len = actual_len as usize;
    if unsealed_len != KEY_LEN {
        return Err(format!(
            "Unsealed {unsealed_len}-byte key, expected {KEY_LEN}."
        ));
    }

    // `from_vec` adopts the temporary's allocation rather than copying it,
    // so no unwiped duplicate of the key is left behind.
    Ok(SecureVec::from_vec(buffer[..KEY_LEN].to_vec()))
}

pub fn store_key(wallet_id: u32, key: &[u8]) -> Result<(), String> {
    if key.len() != KEY_LEN {
        return Err(format!("Expected {KEY_LEN}-byte key, got {}.", key.len()));
    }

    let pin = qpv2_core::pinentry::prompt_password_with_confirmation(
        "Set a PIN for your wallet.",
        "PIN:",
        "Confirm PIN:",
        "PINs do not match.",
    )?;

    let prov = open_provider()?;
    let hkey = open_seal_key(prov.0)?;
    let blob = seal(hkey.0, key, &pin)?;

    // The wallet directory does not exist yet while a wallet is being
    // created: the vault only creates it when it writes the seed, which
    // happens after this. Create it here rather than earlier so a
    // cancelled PIN prompt leaves nothing behind.
    let path = qpv2_core::db::create_wallet_dir(wallet_id)
        .map_err(|e| e.to_string())?
        .join(SEALED_BLOB_FILE);
    std::fs::write(&path, &blob)
        .map_err(|e| format!("Failed to write {}: {}.", SEALED_BLOB_FILE, e))?;

    Ok(())
}

pub fn retrieve_key(wallet_id: u32) -> Result<SecureVec, String> {
    let path = sealed_blob_path(wallet_id)?;
    let blob =
        std::fs::read(&path).map_err(|e| format!("Failed to read {}: {}.", SEALED_BLOB_FILE, e))?;

    let pin = qpv2_core::pinentry::prompt_password("Enter your PIN.", "PIN:")?;

    let prov = open_provider()?;
    let hkey = open_seal_key(prov.0)?;
    unseal(hkey.0, &blob, &pin)
}

pub fn delete_key(wallet_id: u32) -> Result<(), String> {
    // Nothing is persisted inside the TPM — the seal key belongs to the
    // provider and is shared — so removing the blob is the whole job.
    let path = sealed_blob_path(wallet_id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed to remove {}: {}.", SEALED_BLOB_FILE, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shows that a different PIN does not recover the sealed key.
    ///
    /// This is the successor to the RSA path's `gesture_is_enforced`, and
    /// it is a better test for a reason worth naming: **RSA encryption
    /// takes no password at all.** If changing the seal password changes
    /// whether the payload comes back, the operation cannot be a plain
    /// public-key wrap.
    ///
    /// What it does *not* establish: that the comparison happened on the
    /// chip, or that the failure was counted against the TPM's
    /// dictionary-attack lockout. Both are expected, neither is proven
    /// here — confirming them needs TPM counters or command tracing.
    ///
    /// Touches the real TPM and produces one deliberate authorization
    /// failure, so it is `#[ignore]`d. Run it with:
    ///
    ///     cargo test -p keychain --lib -- --ignored --nocapture
    #[test]
    #[ignore]
    fn wrong_pin_does_not_unseal() {
        let secret: Vec<u8> = (0u8..32).collect();

        let prov = open_provider().expect("open provider");
        let hkey = open_seal_key(prov.0).expect("open seal key");

        let blob = seal(hkey.0, &secret, "correct-horse").expect("seal");
        println!(
            "sealed {} bytes into a {}-byte blob",
            secret.len(),
            blob.len()
        );

        let right = unseal(hkey.0, &blob, "correct-horse").expect("unseal with correct PIN");
        assert_eq!(right.as_ref(), &secret[..], "round trip did not match");

        let wrong = unseal(hkey.0, &blob, "battery-staple");
        println!("unseal with wrong PIN -> {:?}", wrong.as_ref().err());

        assert!(
            wrong.is_err(),
            "a different PIN recovered the key: the PIN is not gating this wallet"
        );

        // An RSA-2048 ciphertext is exactly the modulus size. Anything
        // else rules out a plain RSA wrap, independently of the capacity
        // test below.
        assert_ne!(
            blob.len(),
            256,
            "the blob is exactly RSA-2048-sized; check whether this provider \
             is really sealing"
        );
    }

    /// Distinguishes TPM sealing from an RSA wrap by input capacity.
    ///
    /// The mechanisms have different maxima, and the probe size has to sit
    /// where they disagree:
    ///
    /// | Mechanism                | Max input |
    /// |--------------------------|-----------|
    /// | TPM sealed object        | 128       |
    /// | RSA-2048 OAEP-SHA256     | 190       |
    /// | RSA-2048 PKCS#1 v1.5     | 245       |
    ///
    /// So the probe must be in `129..=190`: below 129 everything succeeds,
    /// and above 190 an OAEP wrap fails too — which is what the previous
    /// implementation actually used, so a 200-byte probe would have proven
    /// nothing about the case it was meant to rule out.
    ///
    /// Both sizes are sealed for real rather than size-queried, because a
    /// provider may answer a sizing call arithmetically without ever
    /// consulting the TPM.
    ///
    /// The post-quantum claim in this module's header depends on this
    /// passing.
    #[test]
    #[ignore]
    fn seal_is_not_rsa() {
        let prov = open_provider().expect("open provider");
        let hkey = open_seal_key(prov.0).expect("open seal key");

        // Sits between the sealed-object cap and the OAEP cap.
        const PROBE: usize = 160;

        let within = vec![0xABu8; MAX_SEAL_INPUT];
        let beyond = vec![0xABu8; PROBE];

        let probe = |input: &[u8]| -> Result<usize, String> {
            let auth = SealAuth::new("capacity-probe")?;
            let desc = auth.desc();
            let desc_ptr = &desc as *const BCryptBufferDesc as *const core::ffi::c_void;

            let mut len: u32 = 0;
            let status = unsafe {
                NCryptEncrypt(
                    hkey.0,
                    input.as_ptr(),
                    input.len() as u32,
                    desc_ptr,
                    ptr::null_mut(),
                    0,
                    &mut len,
                    NCRYPT_SEALING_FLAG,
                )
            };
            if status != 0 {
                return Err(status_to_err(status, "size query"));
            }

            let mut blob = vec![0u8; len as usize];
            let mut actual: u32 = 0;
            let status = unsafe {
                NCryptEncrypt(
                    hkey.0,
                    input.as_ptr(),
                    input.len() as u32,
                    desc_ptr,
                    blob.as_mut_ptr(),
                    len,
                    &mut actual,
                    NCRYPT_SEALING_FLAG,
                )
            };
            if status != 0 {
                return Err(status_to_err(status, "seal"));
            }
            Ok(actual as usize)
        };

        let within_result = probe(&within);
        let beyond_result = probe(&beyond);

        println!("seal {} bytes -> {:?}", MAX_SEAL_INPUT, within_result);
        println!("seal {} bytes -> {:?}", PROBE, beyond_result);

        assert!(
            within_result.is_ok(),
            "{MAX_SEAL_INPUT} bytes should seal: {:?}",
            within_result.err()
        );
        assert!(
            beyond_result.is_err(),
            "{PROBE} bytes sealed successfully. A TPM sealed object cannot hold \
             more than {MAX_SEAL_INPUT}, so this provider is wrapping rather than \
             sealing — the post-quantum claim in this module's header does not hold."
        );
    }
}
