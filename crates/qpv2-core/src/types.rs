use crate::constants::MULTISIG_RESERVED_FIELD_VALUE;
use crate::containers::{SecureString, SecureVec};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Shl, Shr};

/// Scrypt param structure.
pub struct ScryptParam {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub len: usize,
}

/// Represents an encrypted payload containing salt, IV, and ciphertext, all hex-encoded.
///
/// **Fields**:
/// - `salt: String` - Hex-encoded salt used for key derivation with Scrypt.
/// - `iv: String` - Hex-encoded initialization vector (nonce) for AES-GCM encryption.
/// - `cipher_text: String` - Hex-encoded encrypted data produced by AES-GCM.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CipherPayload {
    pub salt: String,
    pub iv: String,
    pub cipher_text: String,
}

/// A signer in a multisig group: their SPHINCS+ variant and public key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signer {
    pub variant: SpxVariant,
    #[serde(with = "hex::serde")]
    pub pubkey: Vec<u8>,
}

/// Configuration for the CKB quantum-resistant lock script's all-in-one multisig header.
/// Every account uses this — a "single-sig" account is threshold=1 with one signer.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MultisigConfig {
    /// How many of the first N signers must always provide a signature.
    pub required_first_n: u8,
    /// Minimum number of valid signatures required to unlock (M in M-of-N).
    pub threshold: u8,
    /// All signers in deterministic order, each with their own SPHINCS+ variant.
    pub signers: Vec<Signer>,
}

impl MultisigConfig {
    /// Validate multisig parameters.
    fn pre_validate(signers: &[Signer], threshold: u8, required_first_n: u8) -> Result<(), String> {
        let total_signers = signers.len();
        if total_signers == 0 || total_signers > 255 {
            return Err(format!(
                "Signer count must be 1..=255, got {}.",
                total_signers
            ));
        }
        if threshold == 0 {
            return Err("Threshold must be at least 1.".to_string());
        }
        if threshold as usize > total_signers {
            return Err(format!(
                "Threshold ({}) exceeds total signers ({}: {} co-signer(s) + your wallet's key).",
                threshold,
                total_signers,
                total_signers - 1
            ));
        }
        if required_first_n > threshold {
            return Err(format!(
                "required_first_n ({}) must not exceed threshold ({}).",
                required_first_n, threshold
            ));
        }
        for (i, a) in signers.iter().enumerate() {
            for b in signers.iter().skip(i + 1) {
                if a.pubkey == b.pubkey {
                    return Err("Duplicate public key in signer list.".to_string());
                }
            }
        }
        Ok(())
    }

    /// Validated constructor. Returns an error if the config violates on-chain constraints.
    pub fn new(required_first_n: u8, threshold: u8, signers: Vec<Signer>) -> Result<Self, String> {
        Self::pre_validate(&signers, threshold, required_first_n)?;
        Ok(MultisigConfig {
            required_first_n,
            threshold,
            signers,
        })
    }

    /// Convenience constructor for single-signer accounts.
    ///
    /// The quantum-resistant lock script specifies the single-sig
    /// config as `<80 01 01 01 param_id>`: the sole signer is required
    /// (`required_first_n: 1`), with threshold 1 of 1 total. See
    /// <https://github.com/nervosnetwork/quantum-resistant-lock-script/blob/main/docs/simple.md>.
    pub fn single_sig(variant: SpxVariant, pubkey: Vec<u8>) -> Self {
        MultisigConfig {
            required_first_n: 1,
            threshold: 1,
            signers: vec![Signer { variant, pubkey }],
        }
    }

    /// The 4-byte config header: [S, R, M, N].
    pub fn header_bytes(&self) -> [u8; 4] {
        [
            MULTISIG_RESERVED_FIELD_VALUE,
            self.required_first_n,
            self.threshold,
            self.signers.len() as u8,
        ]
    }

    /// Whether this config represents a single-signer account (1-of-1).
    pub fn is_single_sig(&self) -> bool {
        self.signers.len() == 1 && self.threshold == 1
    }

    /// Maximum byte size of the WitnessArgs lock field for this config.
    ///
    /// Uses the M signers with the largest signatures to ensure the fee
    /// covers any valid M-of-N combination. CKB_TX_MESSAGE_ALL excludes
    /// the lock field entirely, so the signing message is the same
    /// regardless of which M signers participate.
    ///
    /// Single-sig is the 1-of-1 degenerate case of multisig and uses the
    /// same witness layout, so this function handles both uniformly.
    ///
    /// Layout: `[S R M N]` (4 bytes) + N PWOS entries, where each is:
    /// - With signature: 1 (flag) + pubkey_len + sig_len
    /// - Without:        1 (flag) + pubkey_len
    pub fn max_witness_lock_size(&self) -> usize {
        let mut size = 4;
        let mut sig_lens = Vec::with_capacity(self.signers.len());
        for signer in &self.signers {
            let param_id: ckb_fips205_utils::ParamId = (signer.variant as u8)
                .try_into()
                .expect("SpxVariant and ParamId share discriminants");
            let (pk_len, sig_len) = ckb_fips205_utils::verifying::lengths(param_id);
            size += 1 + pk_len;
            sig_lens.push(sig_len);
        }
        sig_lens.sort_unstable_by(|a, b| b.cmp(a));
        size + sig_lens.iter().take(self.threshold as usize).sum::<usize>()
    }

    /// Compute 32-byte lock script args.
    ///
    /// Hashes: `[S R M N] + [param_flag₁ pk₁] + [param_flag₂ pk₂] + ...`
    /// where each param_flag has its lowest bit cleared (no-signature variant).
    pub fn lock_script_args(&self) -> [u8; 32] {
        use ckb_fips205_utils::Hasher;
        let mut hasher = Hasher::script_args_hasher();
        hasher.update(&self.header_bytes());
        for signer in &self.signers {
            let param_flag: u8 = (signer.variant as u8) << 1;
            hasher.update(&[param_flag]);
            hasher.update(&signer.pubkey);
        }
        hasher.hash()
    }
}

/// Represents a SPHINCS+ account within the quantum-resistant lock script.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SphincsPlusAccount {
    /// Derivation index — used to derive this wallet's SPHINCS+ key pair from the master seed.
    pub index: u32,
    /// Hex-encoded lock script arguments (32-byte blake2b hash of multisig config).
    pub lock_args: String,
    /// Lock script multisig configuration.
    pub config: MultisigConfig,
    /// For multisig accounts: the singlesig lock_args of the local signer
    /// that was chosen when creating this account. Used by `sign_and_send`
    /// to pick the correct key. `None` for singlesig accounts.
    #[serde(default)]
    pub initiating_signer_lock_args: Option<String>,
}

/// Human-readable metadata so co-signers can verify what they're signing.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SigningMetadata {
    /// Sender address (bech32m).
    pub from_address: String,
    /// Recipient address, if applicable.
    pub to_address: Option<String>,
    /// Amount in CKB, if applicable.
    pub amount_ckb: Option<String>,
    /// Transaction type description (e.g. "Transfer", "DAO Deposit").
    pub tx_type: String,
}

/// A request sent to co-signers asking them to sign a transaction.
///
/// Contains the unsigned transaction, pre-computed signing message,
/// and enough context for the co-signer to independently verify and sign.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SigningRequest {
    pub version: u8,
    /// The unsigned CKB transaction (ckb_jsonrpc_types::Transaction as JSON).
    pub unsigned_tx: serde_json::Value,
    /// Previous output cells for CKB_TX_MESSAGE_ALL verification.
    /// Each entry: (CellOutput molecule hex, data hex).
    pub input_cells: Vec<(String, String)>,
    /// The 32-byte signing message (blake2b hash), hex-encoded.
    pub signing_message: String,
    /// Full multisig configuration for the sending account.
    pub multisig_config: MultisigConfig,
    /// Witness index in the transaction where the lock field goes.
    pub script_group_index: usize,
    /// Whether this targets mainnet or testnet.
    pub is_mainnet: bool,
    /// Human-readable summary for co-signer verification.
    pub metadata: SigningMetadata,
}

/// A co-signer's response containing their signature.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SigningResponse {
    pub version: u8,
    /// Index of this signer within the multisig config's signers array.
    pub signer_index: usize,
    /// Raw SPHINCS+ signature bytes, hex-encoded.
    pub signature: String,
    /// Echo of the signing message this was signed against, for cross-check.
    pub signing_message: String,
}

/// Authentication method used to protect the vault.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(tag = "type")]
pub enum AuthMethod {
    /// Password-based authentication using scrypt key derivation.
    #[default]
    Password,
    /// Platform credential store (macOS Keychain, Windows TPM, Linux TPM).
    Keychain,
    /// FIDO2 hardware key with hmac-secret extension.
    Fido2 { credential_id: String },
}

/// Authentication key used to encrypt/decrypt the vault.
/// Unifies password-based and crypto key paths so that all core functions
/// accept a single parameter regardless of how the key was obtained.
pub enum AuthKey {
    /// Password to be hashed with Scrypt before use as AES-256 key.
    Password(SecureString),
    /// Pre-derived 32-byte AES-256 key (e.g. from passkey PRF + HKDF).
    CryptoKey(SecureVec),
}

/// Lightweight wallet listing entry derived from scanning the filesystem.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletEntry {
    pub id: u32,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletInfo {
    #[serde(default)]
    pub name: String,
    pub spx_variant: SpxVariant,
    #[serde(default)]
    pub auth_method: AuthMethod,
}

/// ID of all 12 SPHINCS+ variants following https://github.com/cryptape/quantum-resistant-lock-script/pull/14
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpxVariant {
    Sha2128F = 48,
    Sha2128S,
    Sha2192F,
    Sha2192S,
    Sha2256F,
    Sha2256S,
    Shake128F,
    Shake128S,
    Shake192F,
    Shake192S,
    Shake256F,
    Shake256S,
}

impl SpxVariant {
    // Each seed in the SPHINCS+ input seed trio {sk_seed, sk_prf, pk_seed} needs this amount of entropy in byte
    pub fn required_entropy_size_component(&self) -> usize {
        match self {
            Self::Sha2128F | Self::Sha2128S | Self::Shake128F | Self::Shake128S => 16,
            Self::Sha2192F | Self::Sha2192S | Self::Shake192F | Self::Shake192S => 24,
            _ => 32,
        }
    }

    // The whole SPHINCS+ seed backup seed/ the trio {sk_seed, sk_prf, pk_seed} needs this much of entropy in byte
    pub fn required_entropy_size_total(&self) -> usize {
        self.required_entropy_size_component() * 3
    }

    // Mapping each SPHINCS+ variant to the corresponding bip39 type (differentiated by word count)
    // Each word count option below contain the corresponding entropy defined in `required_entropy_size_component`
    pub fn required_bip39_size_in_word_component(&self) -> usize {
        match self {
            Self::Sha2128F | Self::Sha2128S | Self::Shake128F | Self::Shake128S => 12,
            Self::Sha2192F | Self::Sha2192S | Self::Shake192F | Self::Shake192S => 18,
            _ => 24,
        }
    }

    // The whole SPHINCS+ seed backup seed/ the trio {sk_seed, sk_prf, pk_seed} will need this much of words in BIP39 standard
    pub fn required_bip39_size_in_word_total(&self) -> usize {
        self.required_bip39_size_in_word_component() * 3
    }
}

impl fmt::Display for SpxVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SpxVariant::Sha2128F => "Sha2128F",
            SpxVariant::Sha2128S => "Sha2128S",
            SpxVariant::Sha2192F => "Sha2192F",
            SpxVariant::Sha2192S => "Sha2192S",
            SpxVariant::Sha2256F => "Sha2256F",
            SpxVariant::Sha2256S => "Sha2256S",
            SpxVariant::Shake128F => "Shake128F",
            SpxVariant::Shake128S => "Shake128S",
            SpxVariant::Shake192F => "Shake192F",
            SpxVariant::Shake192S => "Shake192S",
            SpxVariant::Shake256F => "Shake256F",
            SpxVariant::Shake256S => "Shake256S",
        };
        write!(f, "{}", s)
    }
}

impl Shr<u8> for SpxVariant {
    type Output = u8;
    fn shr(self, rhs: u8) -> u8 {
        (self as u8) >> rhs
    }
}

impl Shl<u8> for SpxVariant {
    type Output = u8;
    fn shl(self, rhs: u8) -> u8 {
        (self as u8) << rhs
    }
}
