//! # QuantumPurse KeyVault
//!
//! This module provides a secure authentication interface for managing cryptographic keys in the
//! QuantumPurse project. It leverages AES-GCM for encryption, Scrypt for password hashing, HKDF for key derivation,
//! and the SPHINCS+ signature scheme for post-quantum transaction signing. The master seed is encrypted and stored
//! locally in files, with access authenticated via password (Scrypt) or pre-derived key (e.g. passkey PRF + HKDF).

use bip39::{Language, Mnemonic};
use fips205::{
    traits::{KeyGen, SerDes, Signer, Verifier},
    *,
};
use hex::encode;
use zeroize::Zeroize;

pub mod constants;
mod containers;
pub mod db;
mod macros;
pub mod pinentry;
pub mod types;
pub mod utilities;

use crate::constants::KDF_PATH_PREFIX;
pub use containers::{SecureString, SecureVec};
use types::*;

////////////////////////////////////////////////////////////////////////////////
///  Key-vault functions
////////////////////////////////////////////////////////////////////////////////
pub struct KeyVault {
    pub variant: SpxVariant,
    pub wallet_id: u32,
}

impl KeyVault {
    pub fn new(variant: SpxVariant, wallet_id: u32) -> Self {
        KeyVault { variant, wallet_id }
    }

    /// To derive SPHINCS+ key pair. One master seed can derive multiple child index-based SPHINCS+ key pairs on demand.
    ///
    /// **Parameters**:
    /// - `seed: &[u8]` - The master seed from which the child sphincs+ key is derived. MUST carry at least N*3 bytes of entropy or panics.
    /// - `index: u32` - The index of the child sphincs+ key to be derived.
    ///
    /// **Returns**:
    /// - `Result<(SecureVec, SecureVec), String>` - The SPHINCS+ key pair on success, or an error message on failure.
    ///
    /// Warning: Proper zeroization of the input seed is the responsibility of the caller.
    fn derive_spx_keys(&self, seed: &[u8], index: u32) -> Result<(SecureVec, SecureVec), String> {
        match self.variant {
            SpxVariant::Sha2128S => {
                spx_keygen!(slh_dsa_sha2_128s::KG, slh_dsa_sha2_128s::N, seed, index)
            }
            SpxVariant::Sha2128F => {
                spx_keygen!(slh_dsa_sha2_128f::KG, slh_dsa_sha2_128f::N, seed, index)
            }
            SpxVariant::Sha2192S => {
                spx_keygen!(slh_dsa_sha2_192s::KG, slh_dsa_sha2_192s::N, seed, index)
            }
            SpxVariant::Sha2192F => {
                spx_keygen!(slh_dsa_sha2_192f::KG, slh_dsa_sha2_192f::N, seed, index)
            }
            SpxVariant::Sha2256S => {
                spx_keygen!(slh_dsa_sha2_256s::KG, slh_dsa_sha2_256s::N, seed, index)
            }
            SpxVariant::Sha2256F => {
                spx_keygen!(slh_dsa_sha2_256f::KG, slh_dsa_sha2_256f::N, seed, index)
            }
            SpxVariant::Shake128S => {
                spx_keygen!(slh_dsa_shake_128s::KG, slh_dsa_shake_128s::N, seed, index)
            }
            SpxVariant::Shake128F => {
                spx_keygen!(slh_dsa_shake_128f::KG, slh_dsa_shake_128f::N, seed, index)
            }
            SpxVariant::Shake192S => {
                spx_keygen!(slh_dsa_shake_192s::KG, slh_dsa_shake_192s::N, seed, index)
            }
            SpxVariant::Shake192F => {
                spx_keygen!(slh_dsa_shake_192f::KG, slh_dsa_shake_192f::N, seed, index)
            }
            SpxVariant::Shake256S => {
                spx_keygen!(slh_dsa_shake_256s::KG, slh_dsa_shake_256s::N, seed, index)
            }
            SpxVariant::Shake256F => {
                spx_keygen!(slh_dsa_shake_256f::KG, slh_dsa_shake_256f::N, seed, index)
            }
        }
    }

    /// Validates an authentication key, returning an error if it is empty or uninitialized.
    fn validate_auth(auth: &AuthKey) -> Result<(), String> {
        match auth {
            AuthKey::Password(password) => {
                if password.is_empty() || password.is_uninitialized() {
                    tracing::error!("Password cannot be empty or uninitialized");
                    return Err("Password cannot be empty or uninitialized".to_string());
                }
            }
            AuthKey::CryptoKey(key) => {
                if key.is_empty() || key.is_uninitialized() {
                    tracing::error!("Derived key cannot be empty or uninitialized");
                    return Err("Derived key cannot be empty or uninitialized".to_string());
                }
            }
        }
        Ok(())
    }

    /// Clears all data in the vault.
    ///
    /// **Returns**:
    /// - `Result<(), String>` - Ok on success, or an error message on failure.
    pub fn clear_database(wallet_id: u32) -> Result<(), String> {
        tracing::info!("Clearing wallet database (wallet_id={})", wallet_id);
        db::clear_master_seed(wallet_id).map_err(|e| e.to_string())?;
        db::clear_singlesig_accounts(wallet_id).map_err(|e| e.to_string())?;
        db::clear_multisig_accounts(wallet_id).map_err(|e| e.to_string())?;
        db::clear_wallet_info(wallet_id).map_err(|e| e.to_string())?;
        db::clear_tx_history(wallet_id).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Retrieves the stored wallet variant.
    ///
    /// **Returns**:
    /// - `Result<SpxVariant, String>` - The stored variant on success, or an error if not found.
    pub fn get_spx_variant(wallet_id: u32) -> Result<SpxVariant, String> {
        let wallet_info = db::get_wallet_info(wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Wallet not initialized (wallet_id={})", wallet_id);
                "Wallet not initialized. Run 'init' or 'import-mnemonic' first.".to_string()
            })?;
        Ok(wallet_info.spx_variant)
    }

    /// Retrieves the wallet's single-sig single-sig convention.
    ///
    /// **Returns**:
    /// - `Result<SingleSigConvention, String>` - The single-sig convention recorded at wallet creation, or an error on failure.
    pub fn get_single_sig_convention(wallet_id: u32) -> Result<SingleSigConvention, String> {
        Ok(Self::read_wallet_info(wallet_id)?.single_sig_convention)
    }

    /// Retrieves all SPHINCS+ lock script arguments (processed public keys) from the database in the order they get inserted.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, String>` - An array of hex-encoded SPHINCS+ lock script arguments on success, or an error on failure.
    pub fn get_singlesig_lock_args(wallet_id: u32) -> Result<Vec<String>, String> {
        let accounts = db::get_singlesig_accounts(wallet_id).map_err(|e| e.to_string())?;
        let lock_args_array: Vec<String> = accounts
            .into_iter()
            .map(|account| account.lock_args)
            .collect();
        Ok(lock_args_array)
    }

    /// Retrieves all single-sig accounts, ordered by insertion index.
    pub fn get_singlesig_accounts(wallet_id: u32) -> Result<Vec<SphincsPlusAccount>, String> {
        db::get_singlesig_accounts(wallet_id).map_err(|e| e.to_string())
    }

    /// Retrieves all multisig accounts, ordered by insertion index.
    pub fn get_multisig_accounts(wallet_id: u32) -> Result<Vec<SphincsPlusAccount>, String> {
        db::get_multisig_accounts(wallet_id).map_err(|e| e.to_string())
    }

    /// Retrieves all accounts (single-sig + multisig) combined.
    pub fn get_all_accounts(wallet_id: u32) -> Result<Vec<SphincsPlusAccount>, String> {
        let mut all = db::get_singlesig_accounts(wallet_id).map_err(|e| e.to_string())?;
        all.extend(db::get_multisig_accounts(wallet_id).map_err(|e| e.to_string())?);
        Ok(all)
    }

    /// Retrieves all lock args (single-sig + multisig) combined.
    pub fn get_all_lock_args(wallet_id: u32) -> Result<Vec<String>, String> {
        Ok(Self::get_all_accounts(wallet_id)?
            .into_iter()
            .map(|a| a.lock_args)
            .collect())
    }

    /// Looks up an account by lock_args across both stores.
    pub fn get_account(
        wallet_id: u32,
        lock_args: &str,
    ) -> Result<Option<SphincsPlusAccount>, String> {
        if let Some(acct) =
            db::get_singlesig_account(wallet_id, lock_args).map_err(|e| e.to_string())?
        {
            return Ok(Some(acct));
        }
        db::get_multisig_account(wallet_id, lock_args).map_err(|e| e.to_string())
    }

    /// Check if there's a master seed stored.
    ///
    /// **Returns**:
    /// - `Result<bool, String>` - `true` if a master seed exists, or `false` if it doesn't.
    pub fn has_master_seed(wallet_id: u32) -> Result<bool, String> {
        let payload = db::get_encrypted_seed(wallet_id).map_err(|e| e.to_string())?;
        Ok(payload.is_some())
    }

    /// Generates master seed for your wallet, encrypts it, and stores it.
    /// Returns the BIP39 mnemonic seed phrase for backup.
    /// Errors if the master seed already exists.
    ///
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to encrypt the generated master seed.
    /// - `auth_method: AuthMethod` - The authentication method to record in wallet metadata.
    ///
    /// **Returns**:
    /// - `Result<(), String>` - Ok on success, or an error on failure.
    ///
    /// **Security Considerations**:
    ///
    /// Given NIST new security post-quantum standards categorized as:
    /// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
    /// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
    /// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
    ///
    /// First protection layer: For a symmetrical encryption practice, the first protection effort SHOULD be the responsibility of
    /// the higher layer implementation (Quantum Purse Wallet or any other system using this library) to ensure that the encrypted data
    /// is never exposed. It is also the responsibility of the end-users to always lock their device carefully.
    ///
    /// Second protection layer: Should the first protection layer fail in any situation, the encryption itself stands as the last
    /// resistance against quantum attacks. The passwords provided should be strong enough, so that breaking it requires comparable
    /// resource to break the NIST category level 1), 3) and 5).
    ///
    /// For a reference setup:
    ///  - Minimum required 20-character passwords. This puts us at ~128-bit of security in theory (less in reality because of human factors).
    ///  - Scrypt with param {log_n = 17, r = 8, p = 1, len 32} make each effort to guess a password even harder for the attacker.
    ///
    /// The theoretical security for this setup, thus starts at level 1) and is not upper limited following how long users passwords can be.
    pub fn generate_master_seed(
        &self,
        auth: AuthKey,
        auth_method: AuthMethod,
        name: &str,
    ) -> Result<(), String> {
        Self::validate_auth(&auth)?;
        db::wallets::validate_wallet_name(name, None).map_err(|e| e.to_string())?;

        if Self::has_master_seed(self.wallet_id)? {
            tracing::error!("Master seed already exists (wallet_id={})", self.wallet_id);
            return Err("Master seed already exists".to_string());
        }

        tracing::info!(
            "Generating master seed (wallet_id={}, variant={}, name={})",
            self.wallet_id,
            self.variant,
            name
        );

        let size = self.variant.required_entropy_size_total();
        let entropy = utilities::get_random_bytes(size).map_err(|e| {
            let msg = format!("Failed generating master seed: {}", e);
            tracing::error!("{}", msg);
            msg
        })?;
        let encrypted_seed = utilities::encrypt(&auth, entropy.as_ref()).map_err(|e| {
            let msg = format!("Encryption error: {}", e);
            tracing::error!("{}", msg);
            msg
        })?;

        db::create_wallet_dir(self.wallet_id).map_err(|e| e.to_string())?;
        db::set_encrypted_seed(self.wallet_id, encrypted_seed).map_err(|e| e.to_string())?;

        // All wallets are single-sig by default.
        // All single-sig wallets use the standard single-sig convention.
        let wallet_info = types::WalletInfo {
            name: name.to_string(),
            spx_variant: self.variant,
            auth_method,
            single_sig_convention: SingleSigConvention::Standard,
        };
        db::set_wallet_info(self.wallet_id, wallet_info).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Generates a new SPHINCS+ account - a SPHINCS+ child account derived from the master seed and stores it.
    ///
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to decrypt the master seed.
    ///
    /// **Returns**:
    /// - `Result<String, String>` - The hex-encoded SPHINCS+ lock argument (processed SPHINCS+ public key) of the account on success, or an error on failure.
    pub fn gen_singlesig_account(&self, auth: AuthKey) -> Result<SphincsPlusAccount, String> {
        Self::validate_auth(&auth)?;

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed(self.wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Master seed not found");
                "Master seed not found".to_string()
            })?;
        let seed = utilities::decrypt(&auth, payload)?;

        let index = Self::get_singlesig_lock_args(self.wallet_id)?.len() as u32;
        tracing::info!(
            "Deriving new account (wallet_id={}, index={})",
            self.wallet_id,
            index
        );
        let (pub_key, _) = self.derive_spx_keys(&seed, index).map_err(|e| {
            let msg = format!("Key derivation error: {}", e);
            tracing::error!("{}", msg);
            msg
        })?;

        let single_sig_convention = Self::get_single_sig_convention(self.wallet_id)?;
        let config = MultisigConfig::single_sig(
            self.variant,
            pub_key.as_ref().to_vec(),
            single_sig_convention,
        );
        let lock_script_args = config.lock_script_args();

        let account = SphincsPlusAccount {
            index: 0,
            lock_args: encode(lock_script_args),
            config,
            initiating_signer_lock_args: None,
        };

        db::add_singlesig_account(self.wallet_id, account.clone()).map_err(|e| e.to_string())?;

        Ok(account)
    }

    /// Creates a multisig account using an existing single-sig account as
    /// the local signer, combined with external co-signers. All signers
    /// are sorted by pubkey bytes to produce a deterministic address.
    ///
    /// **Parameters**:
    /// - `wallet_id` - The wallet containing the single-sig account.
    /// - `singlesig_lock_args` - Lock args of the single-sig account to use as local signer.
    /// - `co_signers` - External signers (variant + pubkey) to include.
    /// - `threshold` - Minimum signatures required to unlock (M).
    /// - `required_first_n` - How many of the first N sorted signers must always sign (R).
    ///
    /// **Returns**:
    /// - The new multisig account on success, or an error on failure.
    pub fn gen_multisig_account(
        wallet_id: u32,
        singlesig_lock_args: &str,
        co_signers: Vec<types::Signer>,
        threshold: u8,
        required_first_n: u8,
    ) -> Result<SphincsPlusAccount, String> {
        let singlesig = db::get_singlesig_account(wallet_id, singlesig_lock_args)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!(
                    "Single-sig account not found (lock_args={})",
                    singlesig_lock_args
                );
                "Single-sig account not found.".to_string()
            })?;

        let local_signer = singlesig.config.signers[0].clone();
        tracing::info!(
            "Creating multisig account (wallet_id={}, local_signer={}..., co_signers={})",
            wallet_id,
            &singlesig_lock_args[..8.min(singlesig_lock_args.len())],
            co_signers.len()
        );

        let mut signers = co_signers;
        signers.push(local_signer);
        signers.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));

        let config = MultisigConfig::new(required_first_n, threshold, signers)?;
        let lock_script_args = config.lock_script_args();

        let account = SphincsPlusAccount {
            index: 0,
            lock_args: encode(lock_script_args),
            config,
            initiating_signer_lock_args: Some(singlesig_lock_args.to_string()),
        };

        db::add_multisig_account(wallet_id, account.clone()).map_err(|e| e.to_string())?;

        Ok(account)
    }

    /// Imports master seed from a mnemonic phrase, encrypts it, and stores it.
    /// Overwrites the existing master seed.
    ///
    /// **Parameters**:
    /// - `seed_phrase: SecureString` - The mnemonic phrase to import.
    ///   There're only 3 options accepted: 36, 54 or 72 words.
    /// - `auth: AuthKey` - The authentication key used to encrypt the translated master seed.
    /// - `auth_method: AuthMethod` - The authentication method to record in wallet metadata.
    ///
    /// **Returns**:
    /// - `Result<(), String>` - Ok on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `auth` and `seed_phrase` buffers are cleared immediately after use.
    ///
    /// **Security Considerations**:
    ///
    /// Given NIST new security post-quantum standards categorized as:
    /// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
    /// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
    /// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
    ///
    /// First protection layer: For a symmetrical encryption practice, the first protection effort SHOULD be the responsibility of
    /// the higher layer implementation (Quantum Purse Wallet or any other system using this library) to ensure that the encrypted data
    /// is never exposed. It is also the responsibility of the end-users to always lock their device carefully.
    ///
    /// Second protection layer: Should the first protection layer fail in any situation, the encryption itself stands as the last
    /// resistance against quantum attacks. The passwords provided should be strong enough, so that breaking it requires comparable
    /// resource to break the NIST category level 1), 3) and 5).
    ///
    /// For a reference setup:
    ///  - Minimum required 20-character passwords. This puts us at ~128-bit of security in theory (less in reality because of human factors).
    ///  - Scrypt with param {log_n = 17, r = 8, p = 1, len 32} make each effort to guess a password even harder for the attacker.
    ///
    /// The theoretical security for this setup, thus starts at level 1) and is not upper limited following how long users passwords can be.
    pub fn import_seed_phrase(
        &self,
        seed_phrase: SecureString,
        auth: AuthKey,
        auth_method: AuthMethod,
        name: &str,
        single_sig_convention: SingleSigConvention,
    ) -> Result<(), String> {
        Self::validate_auth(&auth)?;
        db::wallets::validate_wallet_name(name, None).map_err(|e| e.to_string())?;

        if seed_phrase.is_empty() || seed_phrase.is_uninitialized() {
            tracing::error!("Seed phrase cannot be empty or uninitialized");
            return Err("Seed phrase cannot be empty or uninitialized".to_string());
        }

        let words: Vec<&str> = seed_phrase.split_whitespace().collect();
        let word_count = words.len();

        if word_count != self.variant.required_bip39_size_in_word_total() {
            let msg = format!(
                "Mismatch: The chosen SPHINCS+ parameter set {} requires {} words whereas the input mnemonic has {} words.",
                self.variant,
                self.variant.required_bip39_size_in_word_total(),
                word_count
            );
            tracing::error!("{}", msg);
            return Err(msg);
        }

        tracing::info!(
            "Importing seed phrase (wallet_id={}, variant={}, name={})",
            self.wallet_id,
            self.variant,
            name
        );

        let mut combined_entropy = SecureVec::new_with_length(0);
        let size = self.variant.required_bip39_size_in_word_component();
        for (index, chunk) in (0_u8..).zip(words.chunks(size)) {
            let chunk_str = SecureString::from_string(chunk.join(" "));
            let mnemonic = Mnemonic::parse_in(Language::English, &*chunk_str).map_err(|e| {
                let msg = format!("Invalid mnemonic: Chunk{} index {}: {}", size, index, e);
                tracing::error!("{}", msg);
                msg
            })?;
            combined_entropy.extend(SecureVec::from_vec(mnemonic.to_entropy()));
        }

        let payload = utilities::encrypt(&auth, &combined_entropy)?;
        db::create_wallet_dir(self.wallet_id).map_err(|e| e.to_string())?;
        db::set_encrypted_seed(self.wallet_id, payload).map_err(|e| e.to_string())?;

        let wallet_info = types::WalletInfo {
            name: name.to_string(),
            spx_variant: self.variant,
            auth_method,
            single_sig_convention,
        };
        db::set_wallet_info(self.wallet_id, wallet_info).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Exports the master seed in the form of a custom bip39 mnemonic phrase. There're only 3 options: 36, 54 or 72 words.
    ///
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to decrypt the master seed.
    ///
    /// **Returns**:
    /// - `Result<SecureString, String>` - The mnemonic phrase on success, or an error on failure.
    ///
    /// **Warning**: Exporting the mnemonic exposes it and may pose a security risk.
    pub fn export_seed_phrase(&self, auth: AuthKey) -> Result<SecureString, String> {
        Self::validate_auth(&auth)?;

        tracing::info!("Exporting seed phrase (wallet_id={})", self.wallet_id);

        let payload = db::get_encrypted_seed(self.wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Master seed not found");
                "Master seed not found".to_string()
            })?;

        let entropy = utilities::decrypt(&auth, payload)?;
        let size = self.variant.required_entropy_size_component();
        let chunks = entropy.chunks(size);

        let mut combined_mnemonic = SecureString::new();
        for chunk in chunks {
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

    /// Sign and produce a valid signature for the CKB Blockchain Quantum Resistant Lock Script.
    ///
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to decrypt the private key.
    /// - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
    /// - `message: Vec<u8>` - The CKB transaction message all. For details check https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md
    ///
    /// **Returns**:
    /// - `Result<Vec<u8>, String>` - The signature on success, or an error on failure.
    pub fn ckb_sign(
        &self,
        auth: AuthKey,
        lock_args: String,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        Self::validate_auth(&auth)?;

        tracing::info!(
            "CKB signing (wallet_id={}, lock_args={}..)",
            self.wallet_id,
            &lock_args[..8.min(lock_args.len())]
        );

        let account = Self::get_account(self.wallet_id, &lock_args)?.ok_or_else(|| {
            tracing::error!("Account not found");
            "Account not found".to_string()
        })?;

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed(self.wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Master seed not found");
                "Master seed not found".to_string()
            })?;
        let seed = utilities::decrypt(&auth, payload)?;

        let (_, pri_key) = self.derive_spx_keys(&seed, account.index)?;
        let config = &account.config;

        match self.variant {
            SpxVariant::Sha2128S => {
                ckb_spx_sign!(slh_dsa_sha2_128s, pri_key, &message, self.variant, config)
            }
            SpxVariant::Sha2128F => {
                ckb_spx_sign!(slh_dsa_sha2_128f, pri_key, &message, self.variant, config)
            }
            SpxVariant::Shake128S => {
                ckb_spx_sign!(slh_dsa_shake_128s, pri_key, &message, self.variant, config)
            }
            SpxVariant::Shake128F => {
                ckb_spx_sign!(slh_dsa_shake_128f, pri_key, &message, self.variant, config)
            }
            SpxVariant::Sha2192S => {
                ckb_spx_sign!(slh_dsa_sha2_192s, pri_key, &message, self.variant, config)
            }
            SpxVariant::Sha2192F => {
                ckb_spx_sign!(slh_dsa_sha2_192f, pri_key, &message, self.variant, config)
            }
            SpxVariant::Shake192S => {
                ckb_spx_sign!(slh_dsa_shake_192s, pri_key, &message, self.variant, config)
            }
            SpxVariant::Shake192F => {
                ckb_spx_sign!(slh_dsa_shake_192f, pri_key, &message, self.variant, config)
            }
            SpxVariant::Sha2256S => {
                ckb_spx_sign!(slh_dsa_sha2_256s, pri_key, &message, self.variant, config)
            }
            SpxVariant::Sha2256F => {
                ckb_spx_sign!(slh_dsa_sha2_256f, pri_key, &message, self.variant, config)
            }
            SpxVariant::Shake256S => {
                ckb_spx_sign!(slh_dsa_shake_256s, pri_key, &message, self.variant, config)
            }
            SpxVariant::Shake256F => {
                ckb_spx_sign!(slh_dsa_shake_256f, pri_key, &message, self.variant, config)
            }
        }
    }

    /// Raw SPHINCS+ sign
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to decrypt the private key.
    /// - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
    /// - `message: Vec<u8>` - The CKB transaction message all. For details check https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md
    ///
    /// **Returns**:
    /// - `Result<(Vec<u8>, Vec<u8>), String>` - A tuple of (signature, public_key) on success, or an error on failure.
    pub fn raw_sign(
        &self,
        auth: AuthKey,
        lock_args: String,
        message: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        Self::validate_auth(&auth)?;

        tracing::info!(
            "Raw signing (wallet_id={}, lock_args={}..)",
            self.wallet_id,
            &lock_args[..8.min(lock_args.len())]
        );

        let account = Self::get_account(self.wallet_id, &lock_args)?.ok_or_else(|| {
            tracing::error!("Account not found");
            "Account not found".to_string()
        })?;

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed(self.wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Master seed not found");
                "Master seed not found".to_string()
            })?;
        let seed = utilities::decrypt(&auth, payload)?;

        let (_, pri_key) = self.derive_spx_keys(&seed, account.index)?;

        match self.variant {
            SpxVariant::Sha2128S => {
                raw_spx_sign!(slh_dsa_sha2_128s, pri_key, &message, self.variant)
            }
            SpxVariant::Sha2128F => {
                raw_spx_sign!(slh_dsa_sha2_128f, pri_key, &message, self.variant)
            }
            SpxVariant::Shake128S => {
                raw_spx_sign!(slh_dsa_shake_128s, pri_key, &message, self.variant)
            }
            SpxVariant::Shake128F => {
                raw_spx_sign!(slh_dsa_shake_128f, pri_key, &message, self.variant)
            }
            SpxVariant::Sha2192S => {
                raw_spx_sign!(slh_dsa_sha2_192s, pri_key, &message, self.variant)
            }
            SpxVariant::Sha2192F => {
                raw_spx_sign!(slh_dsa_sha2_192f, pri_key, &message, self.variant)
            }
            SpxVariant::Shake192S => {
                raw_spx_sign!(slh_dsa_shake_192s, pri_key, &message, self.variant)
            }
            SpxVariant::Shake192F => {
                raw_spx_sign!(slh_dsa_shake_192f, pri_key, &message, self.variant)
            }
            SpxVariant::Sha2256S => {
                raw_spx_sign!(slh_dsa_sha2_256s, pri_key, &message, self.variant)
            }
            SpxVariant::Sha2256F => {
                raw_spx_sign!(slh_dsa_sha2_256f, pri_key, &message, self.variant)
            }
            SpxVariant::Shake256S => {
                raw_spx_sign!(slh_dsa_shake_256s, pri_key, &message, self.variant)
            }
            SpxVariant::Shake256F => {
                raw_spx_sign!(slh_dsa_shake_256f, pri_key, &message, self.variant)
            }
        }
    }

    /// Raw SPHINCS+ verify
    /// **Parameters**:
    /// - `public_key: &[u8]` - SPHINCS+ public key associated with the signature.
    /// - `message: &[u8]` - The message from which the signature was created.
    /// - `signature: &[u8]` - The SPHINCS+ signature to verify.
    ///
    /// **Returns**:
    /// - `Result<bool, String>` - A tuple of (signature, public_key) on success, or an error on failure.
    pub fn raw_verify(
        variant: SpxVariant,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        match variant {
            SpxVariant::Sha2128S => {
                raw_spx_verify!(slh_dsa_sha2_128s, public_key, message, signature)
            }
            SpxVariant::Sha2128F => {
                raw_spx_verify!(slh_dsa_sha2_128f, public_key, message, signature)
            }
            SpxVariant::Shake128S => {
                raw_spx_verify!(slh_dsa_shake_128s, public_key, message, signature)
            }
            SpxVariant::Shake128F => {
                raw_spx_verify!(slh_dsa_shake_128f, public_key, message, signature)
            }
            SpxVariant::Sha2192S => {
                raw_spx_verify!(slh_dsa_sha2_192s, public_key, message, signature)
            }
            SpxVariant::Sha2192F => {
                raw_spx_verify!(slh_dsa_sha2_192f, public_key, message, signature)
            }
            SpxVariant::Shake192S => {
                raw_spx_verify!(slh_dsa_shake_192s, public_key, message, signature)
            }
            SpxVariant::Shake192F => {
                raw_spx_verify!(slh_dsa_shake_192f, public_key, message, signature)
            }
            SpxVariant::Sha2256S => {
                raw_spx_verify!(slh_dsa_sha2_256s, public_key, message, signature)
            }
            SpxVariant::Sha2256F => {
                raw_spx_verify!(slh_dsa_sha2_256f, public_key, message, signature)
            }
            SpxVariant::Shake256S => {
                raw_spx_verify!(slh_dsa_shake_256s, public_key, message, signature)
            }
            SpxVariant::Shake256F => {
                raw_spx_verify!(slh_dsa_shake_256f, public_key, message, signature)
            }
        }
    }

    /// Supporting wallet recovery - quickly derives a list of lock script arguments (processed public keys).
    ///
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to decrypt the master seed.
    /// - `start_index: u32` - The starting index for derivation.
    /// - `count: u32` - The number of sequential lock scripts arguments to derive.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, String>` - A list of lock script arguments on success, or an error on failure.
    pub fn try_gen_account_batch(
        &self,
        auth: AuthKey,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<String>, String> {
        Self::validate_auth(&auth)?;

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed(self.wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Master seed not found");
                "Master seed not found".to_string()
            })?;
        let seed = utilities::decrypt(&auth, payload)?;
        let single_sig_convention = Self::get_single_sig_convention(self.wallet_id)?;
        let mut lock_args_array: Vec<String> = Vec::new();
        for index in start_index..(start_index + count) {
            let (pub_key, _) = self.derive_spx_keys(&seed, index).map_err(|e| {
                let msg = format!("Key derivation error: {}", e);
                tracing::error!("{}", msg);
                msg
            })?;

            let config = MultisigConfig::single_sig(
                self.variant,
                pub_key.as_ref().to_vec(),
                single_sig_convention,
            );
            let lock_script_args = config.lock_script_args();
            lock_args_array.push(encode(lock_script_args));
        }
        Ok(lock_args_array)
    }

    /// Supporting wallet recovery - Recovers the wallet by deriving and storing private keys for the first N accounts.
    ///
    /// **Parameters**:
    /// - `auth: AuthKey` - The authentication key used to decrypt the master seed.
    /// - `count: u32` - The number of accounts to recover (from index 0 to count-1).
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, String>` - A list of newly generated sphincs+ lock script arguments (processed public keys) on success, or an error on failure.
    pub fn recover_accounts(&self, auth: AuthKey, count: u32) -> Result<Vec<String>, String> {
        Self::validate_auth(&auth)?;
        tracing::info!(
            "Recovering accounts (wallet_id={}, count={})",
            self.wallet_id,
            count
        );

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed(self.wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Master seed not found");
                "Master seed not found".to_string()
            })?;
        let mut lock_args_array: Vec<String> = Vec::new();
        let seed = utilities::decrypt(&auth, payload)?;
        let single_sig_convention = Self::get_single_sig_convention(self.wallet_id)?;
        for index in 0..count {
            let (pub_key, _) = self.derive_spx_keys(&seed, index).map_err(|e| {
                let msg = format!("Key derivation error: {}", e);
                tracing::error!("{}", msg);
                msg
            })?;

            let config = MultisigConfig::single_sig(
                self.variant,
                pub_key.as_ref().to_vec(),
                single_sig_convention,
            );
            let lock_script_args = config.lock_script_args();

            let account = SphincsPlusAccount {
                index: 0,
                lock_args: encode(lock_script_args),
                config,
                initiating_signer_lock_args: None,
            };
            lock_args_array.push(encode(lock_script_args));

            db::add_singlesig_account(self.wallet_id, account).map_err(|e| e.to_string())?;
        }
        Ok(lock_args_array)
    }

    /// Checks whether a wallet exists (i.e. a master seed is stored).
    ///
    /// **Returns**:
    /// - `bool` - `true` if a wallet exists.
    pub fn wallet_exists(wallet_id: u32) -> bool {
        Self::has_master_seed(wallet_id).unwrap_or(false)
    }

    pub fn read_wallet_info(wallet_id: u32) -> Result<WalletInfo, String> {
        db::get_wallet_info(wallet_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                tracing::error!("Wallet not initialized (wallet_id={})", wallet_id);
                "Wallet not initialized. Run 'init' or 'import-mnemonic' first.".to_string()
            })
    }

    pub fn check_auth_compatibility(wallet_id: u32, expected: &AuthMethod) -> Result<(), String> {
        let wallet_info = Self::read_wallet_info(wallet_id)?;

        match (&wallet_info.auth_method, expected) {
            (AuthMethod::Password, AuthMethod::Password) => Ok(()),
            (AuthMethod::Keychain, AuthMethod::Keychain) => Ok(()),
            (AuthMethod::Fido2 { .. }, AuthMethod::Fido2 { .. }) => Ok(()),
            (actual, attempted) => {
                let label = |m: &AuthMethod| match m {
                    AuthMethod::Password => "Password",
                    AuthMethod::Keychain => "Keychain",
                    AuthMethod::Fido2 { .. } => "Fido2",
                    AuthMethod::Trezor { .. } => "Trezor",
                };
                let msg = format!(
                    "Authentication method mismatch: wallet uses {}, attempted {}.",
                    label(actual),
                    label(attempted)
                );
                tracing::error!("{}", msg);
                Err(msg)
            }
        }
    }

    /// Whether a wallet is backed by a hardware device (Trezor). Such wallets
    /// hold no seed; signing is delegated to the device.
    pub fn is_hardware_wallet(wallet_id: u32) -> bool {
        matches!(
            Self::read_wallet_info(wallet_id).map(|w| w.auth_method),
            Ok(AuthMethod::Trezor { .. })
        )
    }

    /// Creates a watch-only, device-backed wallet. Unlike [`Self::generate_master_seed`]
    /// this writes no `seed.json`: the private key lives on the hardware device.
    /// The imported `accounts` (public key + lock args exported from the device)
    /// must be ordered by device account index starting at 0, so each stored
    /// account's position equals its derivation index. Device accounts use the
    /// V1 single-sig convention, matching the firmware's lock script.
    pub fn create_device_wallet(
        wallet_id: u32,
        name: &str,
        variant: SpxVariant,
        model: &str,
        accounts: Vec<SphincsPlusAccount>,
    ) -> Result<(), String> {
        db::wallets::validate_wallet_name(name, None).map_err(|e| e.to_string())?;

        if Self::has_master_seed(wallet_id)? {
            return Err("A seed-backed wallet already exists at this id.".to_string());
        }

        db::create_wallet_dir(wallet_id).map_err(|e| e.to_string())?;

        let wallet_info = types::WalletInfo {
            name: name.to_string(),
            spx_variant: variant,
            auth_method: AuthMethod::Trezor {
                model: model.to_string(),
            },
            single_sig_convention: SingleSigConvention::V1,
        };
        db::set_wallet_info(wallet_id, wallet_info).map_err(|e| e.to_string())?;

        for account in accounts {
            db::add_singlesig_account(wallet_id, account).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub fn list_wallets() -> Result<Vec<types::WalletEntry>, String> {
        db::wallets::list_wallets().map_err(|e| e.to_string())
    }

    pub fn any_wallet_exists() -> Result<bool, String> {
        let entries = Self::list_wallets()?;
        Ok(!entries.is_empty())
    }

    pub fn remove_wallet(wallet_id: u32) -> Result<(), String> {
        tracing::info!("Removing wallet (wallet_id={})", wallet_id);
        let dir = db::get_wallet_dir(wallet_id).map_err(|e| e.to_string())?;
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| {
                let msg = format!("Failed to remove wallet directory: {}.", e);
                tracing::error!("{}", msg);
                msg
            })?;
        }
        Ok(())
    }
}
