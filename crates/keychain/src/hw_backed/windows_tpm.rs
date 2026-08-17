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
//! - **The old design's gate was not enforced by the chip.** It relied on
//!   the `NgcCacheType` property in Windows' NGC layer, with no TPM
//!   authorization value on the key. Microsoft: *"TPM 2.0 allows some
//!   keys to be created without an authorization value associated with
//!   them. These keys can be used when the TPM is locked."* The PIN here
//!   is an authorization value, so it is checked by the TPM itself.
//!   ([TPM fundamentals])
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
//! - **That failed PINs count against dictionary-attack lockout.**
//!   `NCRYPTBUFFER_TPM_SEAL_NO_DA_PROTECTION` exists, which implies
//!   sealed objects are DA-protected by default and this module
//!   deliberately does not opt out — but that is an inference from a
//!   constant's name.
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
//! [TPM fundamentals]: https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals
//! [BitLocker countermeasures]: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures
//! [`Object_spt.c`]: https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/Object/Object_spt.c
//! [`tss2_tpm2_types.h`]: https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h

use crate::KEY_LEN;
use qpv2_core::SecureVec;
use std::path::PathBuf;
use std::ptr;
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
        return Err(status_to_err(
            status,
            "Failed to determine sealed blob size",
        ));
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
        return Err(status_to_err(status, "Failed to seal key"));
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
        return Err(status_to_err(
            status,
            "Failed to unseal key — wrong PIN, a blob from another machine, \
             or the TPM is locked out after repeated wrong PINs",
        ));
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
