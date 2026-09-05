//! The seal authorization value both TPM backends derive from the PIN.
//!
//! Shared so Windows and Linux accept exactly the same PINs and turn them
//! into exactly the same value.

use qpv2_core::SecureVec;

/// A TPM authorization value is a `TPM2B_AUTH`, capped at the object's
/// name-algorithm digest size, 32 bytes under SHA-256. Handing over the
/// PIN's bytes directly would truncate or reject anything longer, so the
/// PIN is run through HKDF to exactly that length instead. This also makes
/// the value independent of how the PIN happens to be encoded.
pub(crate) const TPM_AUTH_LEN: usize = 32;

/// Domain separator for the seal authorization value. **Changing this
/// makes every existing sealed blob permanently unopenable**, which is why
/// it carries a version suffix rather than being edited in place.
pub(crate) const TPM_AUTH_HKDF_INFO: &[u8] = b"quantum-purse-v2/tpm-seal-auth/v1";

/// Turns the PIN into the value the chip checks.
pub(crate) fn derive_seal_auth(pin: &str) -> Result<SecureVec, String> {
    if pin.is_empty() {
        return Err("PIN cannot be empty.".to_string());
    }
    qpv2_core::utilities::derive_hkdf_key(pin.as_bytes(), TPM_AUTH_HKDF_INFO, TPM_AUTH_LEN)
}

#[cfg(test)]
mod tests {
    use super::{derive_seal_auth, TPM_AUTH_LEN};

    #[test]
    fn value_is_always_the_auth_length() {
        assert_eq!(derive_seal_auth("123456").unwrap().len(), TPM_AUTH_LEN);
        assert_eq!(
            derive_seal_auth(&"x".repeat(200)).unwrap().len(),
            TPM_AUTH_LEN
        );
    }

    #[test]
    fn same_pin_gives_same_value() {
        assert_eq!(
            derive_seal_auth("123456").unwrap().as_ref(),
            derive_seal_auth("123456").unwrap().as_ref()
        );
    }

    #[test]
    fn different_pins_give_different_values() {
        assert_ne!(
            derive_seal_auth("123456").unwrap().as_ref(),
            derive_seal_auth("123457").unwrap().as_ref()
        );
    }

    #[test]
    fn rejects_empty_pin() {
        assert!(derive_seal_auth("").is_err());
    }
}
