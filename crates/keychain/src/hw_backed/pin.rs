//! The one rule a TPM wallet PIN has to satisfy, shared by both TPM backends.

/// Fewest characters a PIN may have. Six is enough because the TPM throttles
/// guesses in hardware; the floor exists so that throttling has something to
/// protect. See https://github.com/quantumpurse/quantum-purse-v2/issues/19#issuecomment-5324052809
pub(crate) const MIN_PIN_CHARS: usize = 6;

/// Checks a newly chosen PIN against the rule the creation dialog states.
/// Counts characters rather than bytes so a multibyte PIN is measured the way
/// the user sees it. Any character is allowed; letters only make a PIN stronger.
pub(crate) fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.chars().count() < MIN_PIN_CHARS {
        return Err(format!(
            "PIN must be at least {} characters.",
            MIN_PIN_CHARS
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_pin;

    #[test]
    fn rejects_five_characters() {
        assert!(validate_pin("12345").is_err());
    }

    #[test]
    fn accepts_six_characters() {
        assert!(validate_pin("123456").is_ok());
    }

    #[test]
    fn counts_characters_not_bytes() {
        // Six two-byte characters: twelve bytes, but six characters.
        assert!(validate_pin("ααββγγ").is_ok());
        assert!(validate_pin("ααββγ").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_pin("").is_err());
    }

    #[test]
    fn allows_letters_and_symbols() {
        assert!(validate_pin("a1!b2@").is_ok());
    }
}
