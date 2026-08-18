//! Windows TPM seal/unseal credential storage via the Platform Crypto Provider.
//!
//! Stores the 32-byte vault encryption key by asking the TPM to seal it,
//! through the Platform Crypto Provider's well-known seal key
//! `TPM_RSA_SRK_SEAL_KEY`. The resulting blob is written to the wallet
//! directory. A PIN is required to seal and to unseal, supplied as the
//! seal password. This mirrors [`linux_tpm`](super::linux_tpm), which
//! seals through `tss-esapi`.
//!
//! # Established facts
//!
//! Each of these is documented by a primary source.
//!
//! - **Sealing is a TPM operation Windows uses in production.** Microsoft:
//!   *"The TPM can also seal and unseal data that is generated outside the
//!   TPM. With sealed key and software, such as BitLocker Drive
//!   Encryption, data can be locked until specific hardware or software
//!   conditions are met."* For BitLocker specifically: *"when Windows
//!   seals the BitLocker key to the TPM, it does it with a PCR 11 value
//!   of 0."*
//!   ([TPM fundamentals], [BitLocker countermeasures])
//!
//! - **How TPM 2.0 protects a sealed object.** The symmetric key and IV
//!   come from `KDFa(hashAlg, seed, "STORAGE", Name, NULL, bits)`, where
//!   `seed` is *"the symmetric seed value in the sensitive area of the
//!   object's parent"* and `Name` identifies the object being encrypted —
//!   so the key is per-object, not per-parent. Integrity is
//!   `HMACnameAlg(HMACkey, encSensitive || Name)` under a separately
//!   derived key, i.e. encrypt-then-MAC. The mode is CFB, and the IV is
//!   generated per operation from the TPM's RNG.
//!   ([`Object_spt.c`] — `ComputeProtectionKeyParms`,
//!   `ComputeOuterIntegrity`, `ProduceOuterWrap`)
//!
//! - **A TPM authorization value is digest-sized.** `TPM2B_AUTH` is a
//!   typedef of `TPM2B_DIGEST`, *"size limited to the same as the digest
//!   structure"* — 32 bytes under SHA-256. This is why [`SealAuth`] runs
//!   the PIN through HKDF instead of passing its bytes directly.
//!   ([`tss2_tpm2_types.h`])
//!
//! - **The previous design put an RSA ciphertext of this key on disk.**
//!   It created an RSA-2048 key through the Microsoft Passport KSP and
//!   encrypted the vault key with its public half. That is recoverable by
//!   factoring the modulus, offline, from a copied file — with no device,
//!   no gesture and no user involvement. It was the only classically
//!   breakable primitive guarding data at rest in this wallet. See the
//!   deletion of `windows_hello.rs` for the code it replaced.
//!
//! - **What dictionary-attack lockout blocks, and what it does not.** In
//!   lockout the TPM returns `TPM_RC_LOCKOUT` *"for an operation that
//!   requires use of a DA protected authValue"*, and an object's authValue is
//!   DA-protected *"unless the object's noDA attribute is SET"* — with `noDA`
//!   SET, *"authorization of the object is not blocked if the TPM is in
//!   lockout"*. The counter is held in NV, and its self-healing decrement
//!   happens only if *"there is no power interruption"*; a non-orderly
//!   shutdown instead increments it by one. So the counter survives reboots,
//!   and a hard power loss costs an attempt rather than saving one.
//!   ([Part 1] 19.8.1-19.8.6, [Part 2] 8.3.3.8)
//!
//! - **The old design's gate was not enforced by the chip.** It relied on
//!   the `NgcCacheType` property in Windows' NGC layer, with no TPM
//!   authorization value on the key. Microsoft: *"TPM 2.0 allows some
//!   keys to be created without an authorization value associated with
//!   them. These keys can be used when the TPM is locked."* The PIN here
//!   is an authorization value, so it is checked by the TPM itself.
//!   ([TPM fundamentals])
//!
//! # Observed on hardware
//!
//! Reproduced on a TPM 2.0 machine. Recorded here rather than above because
//! no primary source accounts for it.
//!
//! - **Repeated wrong PINs lock the chip, and the lockout blocks sealing as
//!   well as unsealing.** A wrong PIN makes `NCryptDecrypt` return
//!   `NTE_PERM`; past the chip's threshold `NCryptEncrypt` fails at its very
//!   first call with `TPM_20_E_LOCKOUT` (`0x80280921`). A user in that state
//!   can neither open an existing wallet nor create a new one.
//!
//!   The specification does not require the second half of this.
//!   `TPM2_Create` authorizes only the parent ([Part 3] Table 19), so sealing
//!   is blocked only if the parent SRK has `noDA` CLEAR, or if the provider
//!   authorizes through a session bound to a DA-protected entity, which
//!   carries lockout with it ([Part 1] 19.8.7). TCG's guidance is that a
//!   shared SRK should *"set the noDA bit"*, which would leave sealing
//!   working ([Provisioning] 7.5.1, Table 1). Microsoft publishes neither its
//!   SRK template nor the PCP command sequence, so which case applies here is
//!   unknown.
//!
//! # Assumptions this module has not verified
//!
//! The post-quantum property claimed above holds **only if** the first
//! item below is true. Until [`tests::seal_is_not_rsa`] passes on real
//! hardware, treat it as an open question rather than a result.
//!
//! - **That the PCP seal key performs TPM sealing at all.** Microsoft
//!   documents neither the operation nor the blob format. The inference
//!   rests on a reported 128-byte input cap, which matches a TPM sealed
//!   object and no RSA padding — but the only public source for that cap
//!   is a third-party writeup, not Microsoft.
//!
//! - **That `NCRYPT_SEALING_FLAG` is the correct flag.** It is not
//!   documented for this use. It is inferred from the existence of the
//!   `NCRYPTBUFFER_TPM_SEAL_*` parameter family, which has no other
//!   consumer.
//!
//! - **Which AES key size protects the blob.** That comes from
//!   Microsoft's SRK template, which is unpublished. The standard TPM 2.0
//!   SRK template specifies AES-128-CFB, so that is the likely answer.
//!   Reading it requires `TPM2_ReadPublic` against the SRK handle.
//!
//! # Consequences worth knowing
//!
//! Windows Hello is gone from this path. Hello lives in the Passport/NGC
//! provider, which creates asymmetric keys; sealing lives in the Platform
//! Crypto Provider below it. The gate is therefore a PIN collected
//! through pinentry, as on Linux, not a biometric prompt drawn by
//! Windows.
//!
//! The seal key is shared, not per-wallet: separation comes from the blob
//! path and the PIN. Moving one wallet's blob into another's directory and
//! supplying the matching PIN will unseal it; the mismatch is caught one
//! layer up when the key fails to authenticate that wallet's seed.
//! [`linux_tpm`](super::linux_tpm) has the same property.
//!
//! The parent is itself an RSA key — hence the constant's name, and
//! `linux_tpm` builds an RSA-2048 SRK too. That key is the parent's
//! identity; per the derivation above it is not what protects the blob,
//! and factoring it would not yield the sealed contents.
//!
//! The lockout counter belongs to the chip, not to this wallet, and is
//! shared with every other consumer of DA-protected objects on the machine.
//! `NCRYPTBUFFER_TPM_SEAL_NO_DA_PROTECTION` is not used, for two independent
//! reasons. It would remove DA protection from the sealed object, and that
//! rate limiting is what makes a short PIN safe against exhaustive search.
//! It also would not restore sealing during a lockout even if that were
//! wanted, because `noDA` on the child says nothing about the parent whose
//! authorization `TPM2_Create` actually requires. What the lockout costs the
//! user is reported by [`windows_tpm_lockout`](super::windows_tpm_lockout)
//! instead.
//!
//! [Part 1]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
//! [Part 2]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
//! [Part 3]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
//! [Provisioning]: https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
//! [TPM fundamentals]: https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals
//! [BitLocker countermeasures]: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures
//! [`Object_spt.c`]: https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/Object/Object_spt.c
//! [`tss2_tpm2_types.h`]: https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h

use super::windows_tpm_lockout as lockout;
use crate::KEY_LEN;
use qpv2_core::SecureVec;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{
    NTE_BAD_DATA, NTE_PERM, TPM_20_E_AUTH_FAIL, TPM_20_E_LOCKOUT, TPM_E_AUTHFAIL,
    TPM_E_DEFEND_LOCK_RUNNING, TPM_E_LOCKED_OUT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptBuffer, BCryptBufferDesc, NCryptDecrypt, NCryptEncrypt, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, NCRYPTBUFFER_TPM_SEAL_PASSWORD,
    NCRYPTBUFFER_VERSION, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SEALING_FLAG,
    TPM_RSA_SRK_SEAL_KEY,
};

/// Deliberately not the `tpm_sealed_blob.bin` that `linux_tpm.rs` writes.
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
    let mut message = String::from(
        "The TPM is locked out after too many wrong PINs. It will not unseal or \
         seal, so existing wallets cannot be opened and new ones cannot be created.",
    );
    if let Some(state) = state {
        message.push_str(&lockout::heal_rate_sentence(state.interval));
    }
    message.push_str(
        " If the TPM owner authorization is available, `Unblock-Tpm` in an \
         elevated PowerShell clears the lockout now; otherwise it has to be \
         waited out.",
    );
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
            match state.attempts_remaining() {
                // The failure that produced this status was the one that
                // exhausted the allowance, so describe the lockout it caused
                // rather than promising another try.
                Some(0) => return locked_out_message(Some(state)),
                Some(remaining) => message.push_str(&format!(
                    " {} attempt{} remaining before the TPM locks out.{}",
                    remaining,
                    if remaining == 1 { "" } else { "s" },
                    lockout::heal_rate_sentence(state.interval),
                )),
                None => {}
            }
        }
        // `NTE_PERM` is NCrypt's generic access-denied, and a wrong PIN is only
        // the meaning observed for it here. Keeping the code means a denial
        // this module has mis-attributed is still reportable, rather than
        // being presented to the user as a confident wrong answer.
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
             Ensure this machine has a TPM 2.0 and it is enabled in firmware",
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
