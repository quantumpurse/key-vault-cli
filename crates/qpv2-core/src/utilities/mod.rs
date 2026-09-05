use super::constants::{ENC_SCRYPT, IV_LENGTH, SALT_LENGTH, VAULT_ENC_KEY_HKDF_INFO};
use super::types::{AuthKey, CipherPayload, ScryptParam, SpxVariant};
use crate::containers::{SecureString, SecureVec};
use aes_gcm::{
    aead::{Aead, KeyInit},
    AeadInPlace, Aes256Gcm, Key, Nonce,
};
use bip39::{Language, Mnemonic};
use ckb_fips205_utils::{
    ckb_tx_message_all_from_mock_tx::{generate_ckb_tx_message_all_from_mock_tx, ScriptOrIndex},
    Hasher,
};
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction};
use hex::{decode, encode};
use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use sha2::Sha256;
#[cfg(test)]
mod tests;

/// Parses a QPV2 seed phrase into master-seed entropy.
///
/// The phrase is the concatenation of `required_bip39_size_in_word_total / 18`
/// standard BIP39 mnemonics, one per seed component. Each 18-word chunk
/// carries its own checksum, so a phrase cut at a chunk boundary still
/// parses chunk by chunk — the total word count is the only check that
/// catches it, which is why it runs first.
pub(crate) fn seed_phrase_to_entropy(
    variant: SpxVariant,
    seed_phrase: &str,
) -> Result<SecureVec, String> {
    let words: Vec<&str> = seed_phrase.split_whitespace().collect();
    let word_count = words.len();

    if word_count != variant.required_bip39_size_in_word_total() {
        let msg = format!(
            "Mismatch: The chosen SPHINCS+ parameter set {} requires {} words whereas the input mnemonic has {} words.",
            variant,
            variant.required_bip39_size_in_word_total(),
            word_count
        );
        tracing::error!("{}", msg);
        return Err(msg);
    }

    let mut combined_entropy = SecureVec::new_with_length(0);
    let size = variant.required_bip39_size_in_word_component();
    for (index, chunk) in (0_u8..).zip(words.chunks(size)) {
        let chunk_str = SecureString::from_string(chunk.join(" "));
        let mnemonic = Mnemonic::parse_in(Language::English, &*chunk_str).map_err(|e| {
            let msg = format!("Invalid mnemonic: Chunk{} index {}: {}", size, index, e);
            tracing::error!("{}", msg);
            msg
        })?;
        combined_entropy.extend(SecureVec::from_vec(mnemonic.to_entropy()));
    }
    Ok(combined_entropy)
}

/// Inverse of [`seed_phrase_to_entropy`]: renders master-seed entropy as
/// the space-joined words of its per-component BIP39 mnemonics.
pub(crate) fn entropy_to_seed_phrase(
    variant: SpxVariant,
    entropy: &[u8],
) -> Result<SecureString, String> {
    let size = variant.required_entropy_size_component();
    let mut combined_mnemonic = SecureString::new();
    for chunk in entropy.chunks(size) {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, chunk).map_err(|e| {
            let msg = format!("Export seed error: {}", e);
            tracing::error!("{}", msg);
            msg
        })?;
        for word in mnemonic.words() {
            combined_mnemonic.extend(word); //TODO: Pre-allocate SecureString capacity to prevent push_str reallocation from leaking unzeroized copies of the mnemonic in freed heap memory.
        }
    }
    Ok(combined_mnemonic)
}

/// Generates random bytes for cryptographic use.
///
/// **Parameters**:
/// - `length: usize` - The number of random bytes to generate.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - A Secure vector of random bytes on success, or an error message on failure.
pub fn get_random_bytes(length: usize) -> Result<SecureVec, getrandom::Error> {
    let mut buffer = SecureVec::new_with_length(length);
    getrandom::fill(&mut buffer)?;
    Ok(buffer)
}

/// This function is used for password hashing.
///
/// **Parameters**:
/// - `input: &[u8]` - The input from which the scrypt key is derived.
/// - `salt: &Vec<u8>` - Salt.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - Scrypt key on success, or an error message on failure.
///
/// Warning: Proper zeroization of the input is the responsibility of the caller.
pub fn derive_scrypt_key(
    input: &[u8],
    salt: &[u8],
    param: &ScryptParam,
) -> Result<SecureVec, String> {
    let mut scrypt_key = SecureVec::new_with_length(param.len);
    let scrypt_param = Params::new(param.log_n, param.r, param.p, param.len)
        .map_err(|e| format!("Scrypt params error: {:?}", e))?;
    scrypt(input, salt, &scrypt_param, &mut scrypt_key)
        .map_err(|e| format!("Scrypt error: {:?}", e))?;
    Ok(scrypt_key)
}

/// Derives a key using HKDF-SHA256.
///
/// **Parameters**:
/// - `ikm: &[u8]` - Input key material.
/// - `info: &[u8]` - Optional context and application specific information.
/// - `output_len: usize` - Desired output length in bytes.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - Derived key on success, or an error message on failure.
pub fn derive_hkdf_key(ikm: &[u8], info: &[u8], output_len: usize) -> Result<SecureVec, String> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = SecureVec::new_with_length(output_len);
    hkdf.expand(info, &mut okm)
        .map_err(|e| format!("HKDF expansion error: {:?}", e))?;
    Ok(okm)
}

/// Encrypts data using AES-256-GCM with a pre-derived key.
///
/// **Parameters**:
/// - `key: &[u8]` - The 32-byte AES-256 encryption crypto key.
/// - `input: &[u8]` - The plaintext data to encrypt.
///
/// **Returns**:
/// - `Result<CipherPayload, String>` - A `CipherPayload` containing the encrypted data, salt (empty), and IV on success, or an error message on failure.
///
/// Warning: Proper zeroization of the key and input is the responsibility of the caller.
pub fn encrypt_with_key(key: &[u8], input: &[u8]) -> Result<CipherPayload, String> {
    let iv_bytes = get_random_bytes(IV_LENGTH).map_err(|e| e.to_string())?;

    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv_bytes);
    let cipher_text = cipher
        .encrypt(nonce, input)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    Ok(CipherPayload {
        salt: String::new(),
        iv: encode(&*iv_bytes),
        cipher_text: encode(cipher_text),
    })
}

/// Decrypts data using AES-256-GCM with a pre-derived key.
///
/// **Parameters**:
/// - `key: &[u8]` - The 32-byte AES-256 decryption key.
/// - `payload: CipherPayload` - The encrypted data payload containing IV and ciphertext.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - The decrypted plaintext on success, or an error message on failure.
///
/// Warning: Proper zeroization of the key is the responsibility of the caller.
pub fn decrypt_with_key(key: &[u8], payload: CipherPayload) -> Result<SecureVec, String> {
    let iv = decode(payload.iv).map_err(|e| format!("IV decode error: {:?}", e))?;
    let cipher_text =
        decode(payload.cipher_text).map_err(|e| format!("Ciphertext decode error: {:?}", e))?;

    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);

    let mut secure_decipher = SecureVec::from_vec(cipher_text);
    cipher
        .decrypt_in_place(nonce, b"", &mut secure_decipher)
        .map_err(|_| "Incorrect key or corrupted data".to_string())?;
    Ok(secure_decipher)
}

/// Encrypts data using AES-GCM with a password-derived key (scrypt).
///
/// **Parameters**:
/// - `password: &[u8]` - The password used to derive the encryption key.
/// - `input: &[u8]` - The plaintext data to encrypt.
///
/// **Returns**:
/// - `Result<CipherPayload, String>` - A `CipherPayload` containing the encrypted data, salt, and IV on success, or an error message on failure.
///
/// Warning: Proper zeroization of the password and input is the responsibility of the caller.
pub fn encrypt_with_password(password: &[u8], input: &[u8]) -> Result<CipherPayload, String> {
    let mut salt = vec![0u8; SALT_LENGTH];
    let mut iv = vec![0u8; IV_LENGTH];
    let random_bytes = get_random_bytes(SALT_LENGTH + IV_LENGTH).map_err(|e| e.to_string())?;
    salt.copy_from_slice(&random_bytes[0..SALT_LENGTH]);
    iv.copy_from_slice(&random_bytes[SALT_LENGTH..]);

    let hashed_password = derive_scrypt_key(password, &salt, &ENC_SCRYPT)?;
    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&hashed_password);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);
    let cipher_text = cipher
        .encrypt(nonce, input)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    Ok(CipherPayload {
        salt: encode(salt),
        iv: encode(iv),
        cipher_text: encode(cipher_text),
    })
}

/// Decrypts data using AES-GCM with a password-derived key (scrypt).
///
/// **Parameters**:
/// - `password: &[u8]` - The password used to derive the decryption key.
/// - `payload: CipherPayload` - The encrypted data payload containing salt, IV, and ciphertext.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - The decrypted plaintext on success, or an error message on failure.
///
/// Warning: Proper zeroization of the password and input is the responsibility of the caller.
pub fn decrypt_with_password(password: &[u8], payload: CipherPayload) -> Result<SecureVec, String> {
    let salt = decode(payload.salt).map_err(|e| format!("Salt decode error: {:?}", e))?;
    let iv = decode(payload.iv).map_err(|e| format!("IV decode error: {:?}", e))?;
    let cipher_text =
        decode(payload.cipher_text).map_err(|e| format!("Ciphertext decode error: {:?}", e))?;

    let hashed_password = derive_scrypt_key(password, &salt, &ENC_SCRYPT)?;
    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&hashed_password);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);

    let mut secure_decipher = SecureVec::from_vec(cipher_text);
    cipher
        .decrypt_in_place(nonce, b"", &mut secure_decipher)
        .map_err(|_| "Incorrect password or corrupted data".to_string())?;
    Ok(secure_decipher)
}

/// Derives an AES-256 key from PRF output using HKDF-SHA256.
///
/// **Parameters**:
/// - `prf_output: &[u8]` - The 32-byte PRF output from passkey assertion.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - The derived 32-byte AES key on success, or an error on failure.
pub fn derive_vault_enc_key(prf_output: &[u8]) -> Result<SecureVec, String> {
    derive_hkdf_key(prf_output, VAULT_ENC_KEY_HKDF_INFO, 32)
}

/// Encrypts data using the appropriate method based on the authentication key.
///
/// **Parameters**:
/// - `auth: &AuthKey` - The authentication key (password or pre-derived key).
/// - `input: &[u8]` - The plaintext data to encrypt.
///
/// **Returns**:
/// - `Result<CipherPayload, String>` - The encrypted payload on success, or an error on failure.
pub fn encrypt(auth: &AuthKey, input: &[u8]) -> Result<CipherPayload, String> {
    match auth {
        AuthKey::Password(password) => encrypt_with_password(password.as_ref(), input),
        AuthKey::CryptoKey(key) => encrypt_with_key(key.as_ref(), input),
    }
}

/// Decrypts data using the appropriate method based on the authentication key.
///
/// **Parameters**:
/// - `auth: &AuthKey` - The authentication key (password or pre-derived key).
/// - `payload: CipherPayload` - The encrypted data payload.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - The decrypted plaintext on success, or an error on failure.
pub fn decrypt(auth: &AuthKey, payload: CipherPayload) -> Result<SecureVec, String> {
    match auth {
        AuthKey::Password(password) => decrypt_with_password(password.as_ref(), payload),
        AuthKey::CryptoKey(key) => decrypt_with_key(key.as_ref(), payload),
    }
}

/// Generates CKB transaction message all hash.
/// https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md.
///
/// **Parameters**:
/// - `serialized_mock_tx: Vec<u8>` - serialized CKB mock transaction.
///
/// **Returns**:
/// - `Result<Vec<u8>, String>` - The CKB transaction message all hash digest on success, or an error on failure.
pub fn get_ckb_tx_message_all(serialized_mock_tx: Vec<u8>) -> Result<Vec<u8>, String> {
    let repr_mock_tx: ReprMockTransaction = serde_json::from_slice(&serialized_mock_tx)
        .map_err(|e| format!("Deserialization error: {}", e))?;
    let mock_tx: MockTransaction = repr_mock_tx.into();
    let mut message_hasher = Hasher::message_hasher();
    generate_ckb_tx_message_all_from_mock_tx(
        &mock_tx,
        ScriptOrIndex::Index(0),
        &mut message_hasher,
    )
    .map_err(|e| format!("CKB_TX_MESSAGE_ALL error: {:?}", e))?;
    let message = message_hasher.hash();
    Ok(message.to_vec())
}

/// Check strength of a password.
/// There is no official weighting system to calculate the strength of a password.
/// This is just a simple implementation for ASCII passwords. Feel free to use your own password checker.
/// By default will require at least 20 characters.
///
/// **Parameters**:
/// - `password: SecureString` - the password.
///
/// **Returns**:
/// - `Result<u32, String>` - The strength of the password measured in bit on success, or an error on failure.
pub fn password_checker(password: &SecureString) -> Result<u32, String> {
    if password.is_empty() || password.is_uninitialized() {
        return Err("Password cannot be empty or uninitialized".to_string());
    }

    let mut has_space = false;
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digit = false;
    let mut has_punctuation = false;
    let mut has_other = false;

    for c in password.chars() {
        if c == ' ' {
            has_space = true;
        } else if c.is_ascii_lowercase() {
            has_lowercase = true;
        } else if c.is_ascii_uppercase() {
            has_uppercase = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii_punctuation() {
            has_punctuation = true;
        } else {
            has_other = true;
        }
    }

    if !has_uppercase {
        return Err("Password must contain at least one uppercase letter!".to_string());
    }
    if !has_lowercase {
        return Err("Password must contain at least one lowercase letter!".to_string());
    }
    if !has_digit {
        return Err("Password must contain at least one digit!".to_string());
    }
    if !has_punctuation {
        return Err("Password must contain at least one symbol!".to_string());
    }
    if password.len() < 20 {
        return Err("Password must contain at least 20 characters!".to_string());
    }

    let character_set_size = if has_other {
        256 // Entire characters space in ASCII
    } else {
        let mut size = 0;
        if has_space {
            size += 1;
        } // Space character
        if has_lowercase {
            size += 26;
        } // a-z
        if has_uppercase {
            size += 26;
        } // A-Z
        if has_digit {
            size += 10;
        } // 0-9
        if has_punctuation {
            size += 32;
        } // ASCII punctuation
        size
    };

    let entropy = (password.len() as f64) * (character_set_size as f64).log2();
    let rounded_entropy = entropy.round() as u32;
    Ok(rounded_entropy)
}

/// Parses a decimal CKB amount string into shannons (1 CKB = 10^8
/// shannons) using pure integer arithmetic.
///
/// f64 must never touch money: binary floats mis-convert a large share
/// of valid 8-decimal amounts by one shannon in either direction (e.g.
/// `"0.00000003" as f64 * 1e8` truncates to 2). A CKB amount IS an
/// integer of shannons — the decimal string denotes it exactly, so the
/// translation can and must be exact.
///
/// Accepts forms like `"12"`, `"12."`, `".5"`, `"0.00000003"`
/// (surrounding whitespace ignored). Rejects signs, exponents, more
/// than 8 fraction digits, and amounts overflowing u64.
pub fn parse_ckb_to_shannons(input: &str) -> Result<u64, String> {
    const SHANNONS_PER_CKB: u64 = 100_000_000;

    let s = input.trim();
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };

    if int_part.is_empty() && frac_part.is_empty() {
        return Err("Amount is empty.".to_string());
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("Amount must be a plain decimal number.".to_string());
    }
    if frac_part.len() > 8 {
        return Err("CKB supports at most 8 decimal places.".to_string());
    }

    let int_shannons = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(SHANNONS_PER_CKB))
            .ok_or_else(|| "Amount too large.".to_string())?
    };

    // Pad the fraction to exactly 8 digits: "5" means 0.5 CKB, i.e.
    // 50_000_000 shannons. An 8-digit number always fits u64.
    let frac_shannons = if frac_part.is_empty() {
        0
    } else {
        frac_part.parse::<u64>().expect("all-digit, <=8 chars")
            * 10u64.pow(8 - frac_part.len() as u32)
    };

    int_shannons
        .checked_add(frac_shannons)
        .ok_or_else(|| "Amount too large.".to_string())
}

/// Fewest characters a hardware-backed PIN may have. Six is enough because
/// the TPM throttles guesses in hardware; the floor exists so that throttling
/// has something to protect. Compare `password_checker`, which guards a file
/// an attacker can brute-force offline and therefore demands far more.
pub const MIN_PIN_CHARS: usize = 6;

/// Checks a newly chosen PIN against the rule the creation dialog states.
/// Counts characters rather than bytes so a multibyte PIN is measured the way
/// the user sees it. Any character is allowed; letters only make a PIN stronger.
/// Reads the secret in place and never copies it.
pub fn validate_pin(pin: &SecureString) -> Result<(), String> {
    if pin.chars().count() < MIN_PIN_CHARS {
        return Err(format!(
            "PIN must be at least {} characters.",
            MIN_PIN_CHARS
        ));
    }
    Ok(())
}
