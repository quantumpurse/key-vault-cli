use crate::{account_name, KEY_LEN, SERVICE};
use qpv2_core::SecureVec;
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options,
    AccessControlOptions, PasswordOptions,
};

fn protected_opts(wallet_id: u32) -> PasswordOptions {
    let account = account_name(wallet_id);
    let mut opts = PasswordOptions::new_generic_password(SERVICE, &account);
    opts.use_protected_keychain();
    opts.set_access_synchronized(Some(false));
    opts
}

fn map_err(e: security_framework::base::Error) -> String {
    match e.code() {
        -128 => "Cancelled.".to_string(),
        -25293 => "Touch ID authentication failed.".to_string(),
        -25300 => "Keychain key not found.".to_string(),
        -25308 => "Keychain interaction not allowed.".to_string(),
        -34018 => "Touch ID is unavailable in this build: its entitlements are not authorised \
             by a provisioning profile (-34018). Use an official release, or build \
             locally with --profile."
            .to_string(),
        code => format!("Keychain error ({}): {}", code, e),
    }
}

pub fn store_key(wallet_id: u32, key: &[u8]) -> Result<(), String> {
    if key.len() != KEY_LEN {
        return Err(format!("Expected {KEY_LEN}-byte key, got {}", key.len()));
    }
    if let Err(e) = delete_generic_password_options(protected_opts(wallet_id)) {
        if e.code() != -25300 {
            return Err(map_err(e));
        }
    }
    let mut opts = protected_opts(wallet_id);
    opts.set_access_control_options(AccessControlOptions::BIOMETRY_CURRENT_SET);
    set_generic_password_options(key, opts).map_err(map_err)
}

pub fn retrieve_key(wallet_id: u32) -> Result<SecureVec, String> {
    let bytes = generic_password(protected_opts(wallet_id)).map_err(map_err)?;
    let secure = SecureVec::from_vec(bytes);
    if secure.len() != KEY_LEN {
        return Err(format!(
            "Keychain returned {}-byte key, expected {KEY_LEN}",
            secure.len()
        ));
    }
    Ok(secure)
}

/// Delete the encryption key from the Keychain.
pub fn delete_key(wallet_id: u32) -> Result<(), String> {
    delete_generic_password_options(protected_opts(wallet_id)).map_err(map_err)
}
