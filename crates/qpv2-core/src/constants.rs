use super::types::ScryptParam;
use ckb_types::core::ScriptHashType;

// Constants
pub const SALT_LENGTH: usize = 16; // 128-bit salt
pub const IV_LENGTH: usize = 12; // 96-bit IV for AES-GCM
pub const KDF_PATH_PREFIX: &str = "ckb/quantum-purse/sphincs-plus/";

/// Given NIST new security post-quantum standards categorized as:
/// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
/// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
/// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
///
/// First protection layer: For a symetrical encryption practice, the first protection effort SHOULD be the responsibitlity of
/// the higher layer impelementation (Quantum Purse Wallet or any other system using this library) to ensure that the encrypted data
/// is never exposed. It is also the responsibility of the end-users to always lock their device carefully.
///
/// Second protection layer: Should the first protection layer fall in any situation, the encryption itself stands as the last resistance
/// against quantum attacks. It should be strong enough, so that breaking it requires comparable resouce to break the NIST category level 1), 3) and 5).
///
/// This library is aiming for level 1) minimum and let users decide if they want to go beyond that with longer passwords because
/// longer passwords are hard to manage. Letting users choose a pass phrase (similar to bip39 but has clearer patterns) is a good practice
/// but then if the passphrase is too long, it is unclear if we shouldlet users authenticate with the mnemonic seed directly.
///
/// For a reference setup:
///  - Minimum required 20-character passwords alone put us at ~128-bit of security in theory (less in reality because of human factors).
///  - Scrypt with param {log_n = 17, r = 8, p = 1, len 32} make each effort to guess a password even harder for the attacker.
///
/// The theoretical security for this setup, thus starts at level 1) and is not upper limited.
///
pub const ENC_SCRYPT: ScryptParam = ScryptParam {
    log_n: 17,
    r: 8,
    p: 1,
    len: 32,
};

/// HKDF info string for deriving AES-256 key from passkey PRF output.
/// Domain separation ensures this key is distinct from any other HKDF derivation in the system.
pub const VAULT_ENC_KEY_HKDF_INFO: &[u8] = b"quantum-purse-v2/vault-encryption/aes-256-gcm-key/v1";

/// CKB quantum-resistant lock script deployment info per network.
/// Source: https://github.com/cryptape/quantum-resistant-lock-script
///
/// Code hash and hash type — used to construct CKB addresses from lock script arguments.
pub const CKB_MAINNET_CODE_HASH: &str =
    "0x302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf";
pub const CKB_MAINNET_HASH_TYPE: ScriptHashType = ScriptHashType::Type;

pub const CKB_TESTNET_CODE_HASH: &str =
    "0x147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf";
pub const CKB_TESTNET_HASH_TYPE: ScriptHashType = ScriptHashType::Data2;

/// Cell dep OutPoint — the on-chain cell that contains the lock script binary.
/// Used to construct the CellDep when building transactions.
pub const CKB_MAINNET_CELL_DEP_TX_HASH: &str =
    "0x4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a";
pub const CKB_MAINNET_CELL_DEP_INDEX: u32 = 0;

pub const CKB_TESTNET_CELL_DEP_TX_HASH: &str =
    "0x631d9a6049fb1fc3790e89d9daf35abe535b5e754cd8c3404319319710f0b106";
pub const CKB_TESTNET_CELL_DEP_INDEX: u32 = 0;

/// Reserved field value for the quantum-resistant lock script's all-in-one multisig header.
/// Always 0x80, chosen to differ from the secp256k1 multisig lock in CKB's genesis block.
pub const MULTISIG_RESERVED_FIELD_VALUE: u8 = 0x80;
