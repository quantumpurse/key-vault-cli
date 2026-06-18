//! Linux TPM seal/unseal credential storage via `tss-esapi`.
//!
//! Stores the 32-byte vault encryption key by sealing it under the
//! TPM's Storage Root Key (SRK) with `TPM2_Create`. The SRK is
//! deterministic — the same well-known RSA-2048 template always
//! produces the same primary key on the same TPM. The sealed blobs
//! (Private + Public) are persisted to disk alongside the wallet files.
//!
//! On unlock, the SRK is recreated, the blobs are loaded with
//! `TPM2_Load`, and `TPM2_Unseal` returns the 32 bytes. The key never
//! leaves the TPM in plaintext except during the unseal operation, and
//! the sealed blob is useless on another machine.
//!
//! A PIN is required for both seal and unseal. The PIN is set as the
//! TPM object's authValue during `TPM2_Create` and verified on-chip
//! during `TPM2_Unseal`. Failed PIN attempts count toward the TPM's
//! dictionary attack lockout. The caller collects the PIN (via
//! pinentry or terminal input) and passes it in.
//!
//! Requires `/dev/tpmrm0` (kernel resource manager).

use crate::KEY_LEN;
use qpv2_core::SecureVec;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyRsa,
        PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, SensitiveData,
        SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    Context,
};

const SEALED_BLOB_FILE: &str = "tpm_sealed_blob.bin";

fn sealed_blob_path(wallet_id: u32) -> Result<PathBuf, String> {
    qpv2_core::db::get_wallet_dir(wallet_id)
        .map(|d| d.join(SEALED_BLOB_FILE))
        .map_err(|e| e.to_string())
}

fn open_context() -> Result<Context, String> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")
        .map_err(|e| format!("Failed to configure TCTI: {}.", e))?;
    Context::new(tcti).map_err(|e| format!("Failed to connect to TPM: {}.", e))
}

fn srk_template() -> Public {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("SRK attributes");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_256_CFB,
                RsaKeyBits::Rsa2048,
                RsaExponent::default(),
            )
            .build()
            .expect("SRK RSA parameters"),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("SRK public template")
}

fn sealed_object_template() -> Public {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .expect("sealed object attributes");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .expect("sealed object public template")
}

fn create_srk(context: &mut Context) -> Result<KeyHandle, String> {
    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, srk_template(), None, None, None, None)
        })
        .map(|r| r.key_handle)
        .map_err(|e| format!("Failed to create SRK: {}.", e))
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
    let auth =
        Auth::try_from(pin.as_bytes().to_vec()).map_err(|e| format!("Invalid PIN: {}.", e))?;

    let mut context = open_context()?;
    let srk_handle = create_srk(&mut context)?;
    let result = seal_to_srk(&mut context, srk_handle, key, auth, wallet_id);
    context.flush_context(srk_handle.into()).ok();
    result
}

fn seal_to_srk(
    context: &mut Context,
    srk_handle: KeyHandle,
    key: &[u8],
    auth: Auth,
    wallet_id: u32,
) -> Result<(), String> {
    let sensitive = SensitiveData::try_from(key.to_vec())
        .map_err(|e| format!("Invalid sensitive data: {}.", e))?;

    let result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(
                srk_handle,
                sealed_object_template(),
                Some(auth),
                Some(sensitive),
                None,
                None,
            )
        })
        .map_err(|e| format!("Failed to seal key: {}.", e))?;

    let private_bytes: Vec<u8> = result.out_private.to_vec();
    let public_bytes = result
        .out_public
        .marshall()
        .map_err(|e| format!("Failed to marshal public blob: {}.", e))?;

    write_sealed_blob(&sealed_blob_path(wallet_id)?, &private_bytes, &public_bytes)
}

pub fn retrieve_key(wallet_id: u32) -> Result<SecureVec, String> {
    let (private_bytes, public_bytes) = read_sealed_blob(&sealed_blob_path(wallet_id)?)?;

    let private =
        Private::try_from(private_bytes).map_err(|e| format!("Invalid private blob: {}.", e))?;
    let public =
        Public::unmarshall(&public_bytes).map_err(|e| format!("Invalid public blob: {}.", e))?;

    let pin = qpv2_core::pinentry::prompt_password("Enter your PIN.", "PIN:")?;
    let auth =
        Auth::try_from(pin.as_bytes().to_vec()).map_err(|e| format!("Invalid PIN: {}.", e))?;

    let mut context = open_context()?;
    let srk_handle = create_srk(&mut context)?;
    let result = load_and_unseal(&mut context, srk_handle, private, public, auth);
    context.flush_context(srk_handle.into()).ok();
    result
}

fn load_and_unseal(
    context: &mut Context,
    srk_handle: KeyHandle,
    private: Private,
    public: Public,
    auth: Auth,
) -> Result<SecureVec, String> {
    let loaded = context
        .execute_with_nullauth_session(|ctx| ctx.load(srk_handle, private, public))
        .map_err(|e| format!("Failed to load sealed object: {}.", e))?;

    context
        .tr_set_auth(loaded.into(), auth)
        .map_err(|e| format!("Failed to set auth: {}.", e))?;

    let unseal_result = context
        .execute_with_nullauth_session(|ctx| ctx.unseal(loaded.into()))
        .map_err(|e| format!("Failed to unseal key: {}.", e));
    context.flush_context(loaded.into()).ok();
    let recovered = unseal_result?;

    // Wrap the unsealed key before validating, so the length-mismatch
    // path can't drop it in the clear.
    let bytes = SecureVec::from_vec(recovered.value().to_vec());
    if bytes.len() != KEY_LEN {
        return Err(format!(
            "Unsealed {}-byte key, expected {KEY_LEN}.",
            bytes.len()
        ));
    }

    Ok(bytes)
}

pub fn delete_key(wallet_id: u32) -> Result<(), String> {
    let path = sealed_blob_path(wallet_id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed to remove {}: {}.", SEALED_BLOB_FILE, e)),
    }
}

// ── Blob I/O ──
// Binary format: [u32 LE: private_len][private bytes][public bytes]

fn write_sealed_blob(path: &Path, private: &[u8], public: &[u8]) -> Result<(), String> {
    let mut buf = Vec::with_capacity(4 + private.len() + public.len());
    buf.extend_from_slice(&(private.len() as u32).to_le_bytes());
    buf.extend_from_slice(private);
    buf.extend_from_slice(public);
    std::fs::write(path, &buf).map_err(|e| format!("Failed to write {}: {}.", SEALED_BLOB_FILE, e))
}

fn read_sealed_blob(path: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let data =
        std::fs::read(path).map_err(|e| format!("Failed to read {}: {}.", SEALED_BLOB_FILE, e))?;
    if data.len() < 4 {
        return Err("Sealed blob file is too small.".to_string());
    }
    let private_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + private_len {
        return Err("Sealed blob file is corrupted.".to_string());
    }
    let private = data[4..4 + private_len].to_vec();
    let public = data[4 + private_len..].to_vec();
    if public.is_empty() {
        return Err("Sealed blob file is missing public portion.".to_string());
    }
    Ok((private, public))
}
