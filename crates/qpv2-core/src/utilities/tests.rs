use super::*;
use std::sync::atomic::Ordering;

#[test]
fn test_pass_encrypt_decrypt() {
    let password = vec![1, 2, 3];
    let data = b"test";
    let payload = encrypt_with_password(&password, data).unwrap();
    let decrypted = decrypt_with_password(&password, payload).unwrap();
    assert_eq!(decrypted.as_ref(), data);
}

#[test]
fn test_fail_encrypt_decrypt() {
    let password = vec![1, 2, 3];
    let data = b"test";
    let payload = encrypt_with_password(&password, data).unwrap();
    let password1 = vec![2, 2, 3];
    let result = decrypt_with_password(&password1, payload);
    assert!(result.is_err());
}

#[test]
fn test_zeroize_on_drop_decrypt_output() {
    use crate::containers::ZEROIZED;
    ZEROIZED.store(false, Ordering::SeqCst);
    let password = vec![1, 2, 3];
    let data = b"test";
    let payload = encrypt_with_password(&password, data).unwrap();
    {
        let _decrypted = decrypt_with_password(&password, payload).unwrap();
    } // decrypted is dropped here
    assert!(ZEROIZED.load(Ordering::SeqCst));
}

#[test]
fn test_encrypt_decrypt_with_key() {
    let prf_output = vec![0x42u8; 32]; // Simulated 32-byte PRF output
    let key = derive_vault_enc_key(&prf_output).unwrap();
    let data = b"test key-based encryption";
    let payload = encrypt_with_key(&key, data).unwrap();
    assert!(
        payload.salt.is_empty(),
        "Salt should be empty for key-based encryption"
    );
    let decrypted = decrypt_with_key(&key, payload).unwrap();
    assert_eq!(decrypted.as_ref(), data);
}

#[test]
fn test_fail_decrypt_with_wrong_key() {
    let prf_output_1 = vec![0x42u8; 32];
    let prf_output_2 = vec![0x43u8; 32];
    let key_1 = derive_vault_enc_key(&prf_output_1).unwrap();
    let key_2 = derive_vault_enc_key(&prf_output_2).unwrap();
    let data = b"test";
    let payload = encrypt_with_key(&key_1, data).unwrap();
    let result = decrypt_with_key(&key_2, payload);
    assert!(result.is_err());
}

#[test]
fn test_derive_key_from_prf_deterministic() {
    let prf_output = vec![0xABu8; 32];
    let key_1 = derive_vault_enc_key(&prf_output).unwrap();
    let key_2 = derive_vault_enc_key(&prf_output).unwrap();
    assert_eq!(
        key_1.as_ref(),
        key_2.as_ref(),
        "Same PRF output should derive same key"
    );
}

#[test]
fn test_parse_ckb_to_shannons_exact() {
    // The f64 path turned "0.00000003" into 2 shannons; integer parsing
    // must be exact for every representable amount.
    assert_eq!(parse_ckb_to_shannons("0.00000003"), Ok(3));
    assert_eq!(parse_ckb_to_shannons("0"), Ok(0));
    assert_eq!(parse_ckb_to_shannons("1"), Ok(100_000_000));
    assert_eq!(parse_ckb_to_shannons("0.1"), Ok(10_000_000));
    assert_eq!(parse_ckb_to_shannons("12.5"), Ok(1_250_000_000));
    assert_eq!(
        parse_ckb_to_shannons("37774.55673077"),
        Ok(3_777_455_673_077)
    );
    // f64 rounded this one UP by a shannon; must be exact.
    assert_eq!(
        parse_ckb_to_shannons("90216076.29597175"),
        Ok(9_021_607_629_597_175)
    );
}

#[test]
fn test_parse_ckb_to_shannons_forms() {
    assert_eq!(parse_ckb_to_shannons(" 2.5 "), Ok(250_000_000));
    assert_eq!(parse_ckb_to_shannons("12."), Ok(1_200_000_000));
    assert_eq!(parse_ckb_to_shannons(".5"), Ok(50_000_000));
    // Full u64 range survives.
    assert_eq!(parse_ckb_to_shannons("184467440737.09551615"), Ok(u64::MAX));
}

#[test]
fn test_parse_ckb_to_shannons_rejects() {
    assert!(parse_ckb_to_shannons("").is_err());
    assert!(parse_ckb_to_shannons(".").is_err());
    assert!(parse_ckb_to_shannons("abc").is_err());
    assert!(parse_ckb_to_shannons("-1").is_err());
    assert!(parse_ckb_to_shannons("+1").is_err());
    assert!(parse_ckb_to_shannons("1.2.3").is_err());
    assert!(parse_ckb_to_shannons("1e8").is_err());
    // More than 8 fraction digits must be rejected, not truncated.
    assert!(parse_ckb_to_shannons("0.123456789").is_err());
    // Overflow past u64::MAX shannons.
    assert!(parse_ckb_to_shannons("184467440737.09551616").is_err());
    assert!(parse_ckb_to_shannons("99999999999999999999").is_err());
}

// ── Seed phrase codec ──

// 36 words — the 128-bit parameter sets.
const SHAKE128F_PHRASE: &str =
    "scene frog possible vapor cliff accident short effort rookie way harbor absorb \
    simple this over fancy party stone enjoy dignity long blast soda crash member truly mosquito \
    sister swarm evolve toast pupil buyer clock quote uncover";

// 54 words — the 192-bit parameter sets.
const SHAKE192F_PHRASE: &str =
    "grid walk tube belt clever spread melt nose move mango banner biology mansion \
    diagram glad exile guess canoe lesson river night copper admit danger limit suit april shadow \
    modify cup glass urban rubber picture toddler guess angry cube sword minor spirit indoor chair \
    empower together secret gauge grape raven cereal issue note recycle crop";

// 72 words — the 256-bit parameter sets.
const SHA2256S_PHRASE: &str = "famous knife noble voice auto blouse occur knee cat convince cabin where sea make \
    hockey oak reduce doctor fabric reduce large bomb plastic faculty pretty sadness latin fade helmet \
    suffer east hub laundry sphere kiwi chief enter damage amused cute breeze post order orchard \
    amount suffer stuff shadow select rate egg lunar logic tank apology spice matrix federal report \
    pig table slim observe shoulder tonight inmate arrow surge hungry plunge coconut region";

fn words(phrase: &str) -> Vec<&str> {
    phrase.split_whitespace().collect()
}

/// phrase → entropy → phrase must reproduce the exact word sequence, and
/// the entropy must be the full master-seed size for the variant.
fn assert_seed_phrase_roundtrip(variant: crate::types::SpxVariant, phrase: &str) {
    let entropy = seed_phrase_to_entropy(variant, phrase).expect("phrase parses");
    assert_eq!(entropy.len(), variant.required_entropy_size_total());
    let back = entropy_to_seed_phrase(variant, &entropy).expect("entropy renders");
    assert_eq!(words(&back), words(phrase));
}

#[test]
fn test_seed_phrase_roundtrip_36_words() {
    assert_seed_phrase_roundtrip(crate::types::SpxVariant::Shake128F, SHAKE128F_PHRASE);
}

#[test]
fn test_seed_phrase_roundtrip_54_words() {
    assert_seed_phrase_roundtrip(crate::types::SpxVariant::Shake192F, SHAKE192F_PHRASE);
}

#[test]
fn test_seed_phrase_roundtrip_72_words() {
    assert_seed_phrase_roundtrip(crate::types::SpxVariant::Sha2256S, SHA2256S_PHRASE);
}

/// Random entropy must survive the reverse trip too, so the two
/// functions are inverses in both directions.
#[test]
fn test_entropy_roundtrip_random() {
    let variant = crate::types::SpxVariant::Sha2128S;
    let entropy = get_random_bytes(variant.required_entropy_size_total()).unwrap();
    let phrase = entropy_to_seed_phrase(variant, &entropy).expect("entropy renders");
    assert_eq!(
        words(&phrase).len(),
        variant.required_bip39_size_in_word_total()
    );
    let back = seed_phrase_to_entropy(variant, &phrase).expect("phrase parses");
    assert_eq!(back.as_ref(), entropy.as_ref());
}

/// A phrase cut at an 18-word chunk boundary still parses as valid BIP39
/// chunks, so only the total word-count check can reject it. Without
/// that check a 54-word import into a 72-word wallet would succeed with
/// a seed that matches no backup.
#[test]
fn test_seed_phrase_rejects_chunk_boundary_truncation() {
    let truncated = words(SHA2256S_PHRASE)[..54].join(" ");
    // `.err()` rather than `expect_err`: the Ok type is a SecureVec,
    // which deliberately has no Debug impl.
    let err = seed_phrase_to_entropy(crate::types::SpxVariant::Sha2256S, &truncated)
        .err()
        .expect("54 words must not parse for a 72-word variant");
    assert!(err.contains("requires 72 words"), "unexpected error: {err}");
}

/// Off-boundary truncation fails too, from the same check, with the
/// same message — never from a chunk parse.
#[test]
fn test_seed_phrase_rejects_missing_word() {
    let short = words(SHAKE128F_PHRASE)[..35].join(" ");
    let err = seed_phrase_to_entropy(crate::types::SpxVariant::Shake128F, &short)
        .err()
        .expect("35 words must not parse for a 36-word variant");
    assert!(err.contains("requires 36 words"), "unexpected error: {err}");
}

fn pin(s: &str) -> SecureString {
    SecureString::from_string(s.to_string())
}

#[test]
fn test_validate_pin_rejects_five_characters() {
    assert!(validate_pin(&pin("12345")).is_err());
}

#[test]
fn test_validate_pin_accepts_six_characters() {
    assert!(validate_pin(&pin("123456")).is_ok());
}

#[test]
fn test_validate_pin_counts_characters_not_bytes() {
    // Six two-byte characters: twelve bytes, but six characters.
    assert!(validate_pin(&pin("ααββγγ")).is_ok());
    assert!(validate_pin(&pin("ααββγ")).is_err());
}

#[test]
fn test_validate_pin_rejects_empty() {
    assert!(validate_pin(&pin("")).is_err());
}

#[test]
fn test_validate_pin_allows_letters_and_symbols() {
    assert!(validate_pin(&pin("a1!b2@")).is_ok());
}
