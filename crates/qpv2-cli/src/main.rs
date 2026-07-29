use clap::{Parser, Subcommand};
use qpv2_core::types::{AuthKey, AuthMethod, SingleSigConvention, SpxVariant};
use qpv2_core::KeyVault;
use qpv2_core::SecureString;
use rpassword::read_password;
use std::fs;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "qpv2")]
#[command(about = "A SPHINCS+-based key management CLI with integrated CKB blockchain address resolution.", long_about = None)]
struct Cli {
    /// Wallet name (optional for init and import — auto-generated if omitted; auto-selects if only one wallet exists)
    #[arg(long, global = true)]
    wallet: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new wallet by generating a seed
    Init {
        /// SPHINCS+ variant (Sha2128F, Sha2128S, Sha2192F, Sha2192S, Sha2256F, Sha2256S, Shake128F, Shake128S, Shake192F, Shake192S, Shake256F, Shake256S)
        #[arg(short, long)]
        variant: String,
        /// Use platform credential store (Touch ID on macOS, Windows Hello + TPM on Windows, TPM on Linux)
        #[arg(long)]
        keychain: bool,
        /// Use a FIDO2 security key with hmac-secret extension
        #[arg(long)]
        fido2: bool,
    },
    /// Mnemonic operations (import/export)
    Mnemonic {
        #[command(subcommand)]
        command: MnemonicCommands,
    },
    /// Account operations (new/list/recover/try-gen-batch)
    Account {
        #[command(subcommand)]
        command: AccountCommands,
    },
    /// Generate raw SPHINCS+ signature for any message (returns signature and public key)
    Sign {
        /// Account identifier (CKB quantum lock args). Run `qpv2-cli account list` to see all accounts
        #[arg(short, long)]
        identifier: String,
        /// Message to sign (hex-encoded)
        #[arg(short, long)]
        message: String,
    },
    /// Verify raw SPHINCS+ signature
    Verify {
        /// SPHINCS+ variant (Sha2128F, Sha2128S, Sha2192F, Sha2192S, Sha2256F, Sha2256S, Shake128F, Shake128S, Shake192F, Shake192S, Shake256F, Shake256S)
        #[arg(short, long)]
        variant: String,
        /// Public key (hex-encoded)
        #[arg(short, long)]
        public_key: String,
        /// Message to verify (hex-encoded)
        #[arg(short, long)]
        message: String,
        /// Signature to verify (hex-encoded)
        #[arg(short, long)]
        signature: String,
    },
    /// CKB blockchain operations (sign/get-tx-message)
    Ckb {
        #[command(subcommand)]
        command: CkbCommands,
    },
    /// Send CKB from an account (single-sig or 1-of-1 multisig)
    Transfer {
        /// Account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Recipient CKB address (bech32m)
        #[arg(short, long)]
        to: String,
        /// Amount in CKB (decimal, e.g. 100.5)
        #[arg(short, long)]
        amount: String,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
        /// Network: mainnet or testnet
        #[arg(long, default_value = "testnet")]
        network: String,
        /// CKB RPC URL (overrides the default for the chosen network)
        #[arg(long)]
        rpc_url: Option<String>,
    },
    /// NervosDAO operations (single-sig)
    Dao {
        /// Network: mainnet or testnet
        #[arg(long, default_value = "testnet")]
        network: String,
        /// CKB RPC URL (overrides the default for the chosen network)
        #[arg(long)]
        rpc_url: Option<String>,
        #[command(subcommand)]
        command: DaoCommands,
    },
    /// Multisig transaction operations (build, sign, submit)
    Msig {
        /// Network: mainnet or testnet
        #[arg(long, default_value = "testnet")]
        network: String,
        /// CKB RPC URL (overrides the default for the chosen network)
        #[arg(long)]
        rpc_url: Option<String>,
        #[command(subcommand)]
        command: MsigCommands,
    },
    /// Delete the selected wallet and all its data
    Delete,
    /// Wallet management operations
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
}

#[derive(Subcommand)]
enum MnemonicCommands {
    Import {
        /// SPHINCS+ variant
        #[arg(short, long)]
        variant: String,

        #[arg(short, long)]
        seed_file: Option<String>,

        /// Use platform credential store (Touch ID on macOS, Windows Hello + TPM on Windows, TPM on Linux)
        #[arg(long)]
        keychain: bool,

        /// Use a FIDO2 security key with hmac-secret extension
        #[arg(long)]
        fido2: bool,

        /// Import from the Quantum Purse v1 wallet (uses its legacy address format)
        #[arg(long)]
        v1: bool,
    },
    Export {
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Generate a new SPHINCS+ account
    New,
    /// Create a multisig account with co-signers
    NewMultisig {
        /// Lock args of the single-sig account to use as local signer (from `account list`)
        #[arg(short = 'a', long)]
        singlesig_lock_args: String,
        /// Threshold: minimum signatures required (M in M-of-N)
        #[arg(short = 'm', long)]
        threshold: u8,
        /// Required first N signers that must always sign (0 = no mandatory signers)
        #[arg(short = 'r', long, default_value = "0")]
        required_first_n: u8,
        /// Co-signer entries as "variant:hex_pubkey" (e.g. "Sha2256S:abcd..."). Repeat for each co-signer
        #[arg(short, long, num_args = 1..)]
        signer: Vec<String>,
    },
    /// List all SPHINCS+ accounts
    List,
    /// Recover accounts
    Recover {
        /// Number of accounts to recover
        #[arg(short, long)]
        count: u32,
    },
    /// Generate account batch (for discovery)
    TryGenBatch {
        /// Start index
        #[arg(short, long)]
        start: u32,
        /// Count
        #[arg(short, long)]
        count: u32,
    },
}

#[derive(Subcommand)]
enum CkbCommands {
    /// Sign a CKB message
    Sign {
        /// CKB quantum lock script args (Account identifier)
        #[arg(short, long)]
        lock_args: String,
        /// Message to sign (hex-encoded)
        #[arg(short, long)]
        message: String,
    },
    /// Get CKB transaction message hash from mock transaction
    GetTxMessage {
        /// Path to serialized mock transaction file
        #[arg(short, long)]
        tx_file: String,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// List all wallets
    List,
    /// Rename the selected wallet
    Rename {
        /// New display name for the wallet
        #[arg(long)]
        to: String,
    },
}

#[derive(Subcommand)]
enum DaoCommands {
    /// List deposited and prepared DAO cells
    List {
        /// Account lock args (from `account list`). If omitted, lists for all accounts
        #[arg(short, long)]
        lock_args: Option<String>,
    },
    /// Deposit CKB into NervosDAO
    Deposit {
        /// Account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Amount in CKB (decimal, e.g. 100.5)
        #[arg(short, long)]
        amount: String,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
    },
    /// Prepare a DAO withdrawal (phase 1)
    Prepare {
        /// Account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Deposit cell tx hash
        #[arg(long)]
        tx_hash: String,
        /// Deposit cell output index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
    },
    /// Complete a DAO withdrawal (phase 2)
    Withdraw {
        /// Account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Prepared cell tx hash
        #[arg(long)]
        tx_hash: String,
        /// Prepared cell output index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
    },
}

#[derive(Subcommand)]
enum MsigCommands {
    /// Build an unsigned transfer and output a signing request
    BuildTransfer {
        /// Multisig account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Recipient CKB address (bech32m)
        #[arg(short, long)]
        to: String,
        /// Amount in CKB (decimal, e.g. 100.5)
        #[arg(short, long)]
        amount: String,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
        /// Output file for the signing request JSON
        #[arg(short, long, default_value = "signing_request.json")]
        output: String,
    },
    /// Build an unsigned DAO deposit and output a signing request
    BuildDeposit {
        /// Multisig account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Amount in CKB (decimal, e.g. 100.5)
        #[arg(short, long)]
        amount: String,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
        /// Output file for the signing request JSON
        #[arg(short, long, default_value = "signing_request.json")]
        output: String,
    },
    /// Build an unsigned DAO prepare (phase 1) and output a signing request
    BuildPrepare {
        /// Multisig account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Deposit cell tx hash
        #[arg(long)]
        tx_hash: String,
        /// Deposit cell output index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
        /// Output file for the signing request JSON
        #[arg(short, long, default_value = "signing_request.json")]
        output: String,
    },
    /// Build an unsigned DAO withdraw (phase 2) and output a signing request
    BuildWithdraw {
        /// Multisig account lock args (from `account list`)
        #[arg(short, long)]
        lock_args: String,
        /// Prepared cell tx hash
        #[arg(long)]
        tx_hash: String,
        /// Prepared cell output index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Fee rate (shannons per 1000 bytes)
        #[arg(short, long, default_value = "1000")]
        fee_rate: u64,
        /// Output file for the signing request JSON
        #[arg(short, long, default_value = "signing_request.json")]
        output: String,
    },
    /// Sign a signing request with a local key
    Sign {
        /// Path to the signing request JSON file
        #[arg(short, long)]
        request: String,
        /// Output file for the signing response JSON
        #[arg(short, long, default_value = "signing_response.json")]
        output: String,
    },
    /// Assemble co-signer responses and submit the signed transaction
    Submit {
        /// Path to the signing request JSON file
        #[arg(short = 'q', long)]
        request: String,
        /// Paths to signing response JSON files (repeat for each response)
        #[arg(short, long, num_args = 1..)]
        response: Vec<String>,
    },
}

fn parse_variant(variant_str: &str) -> Result<SpxVariant, String> {
    match variant_str.to_lowercase().as_str() {
        "sha2128f" => Ok(SpxVariant::Sha2128F),
        "sha2128s" => Ok(SpxVariant::Sha2128S),
        "sha2192f" => Ok(SpxVariant::Sha2192F),
        "sha2192s" => Ok(SpxVariant::Sha2192S),
        "sha2256f" => Ok(SpxVariant::Sha2256F),
        "sha2256s" => Ok(SpxVariant::Sha2256S),
        "shake128f" => Ok(SpxVariant::Shake128F),
        "shake128s" => Ok(SpxVariant::Shake128S),
        "shake192f" => Ok(SpxVariant::Shake192F),
        "shake192s" => Ok(SpxVariant::Shake192S),
        "shake256f" => Ok(SpxVariant::Shake256F),
        "shake256s" => Ok(SpxVariant::Shake256S),
        _ => Err(format!("Invalid variant: {}", variant_str)),
    }
}

fn prompt_for_input(prompt: &str) -> Result<SecureString, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let input = read_password().map_err(|e| e.to_string())?;
    let result = SecureString::from_utf8(input.into_bytes())?;
    Ok(result)
}

fn get_auth_key(wallet_id: u32) -> Result<AuthKey, String> {
    let wallet_info = KeyVault::read_wallet_info(wallet_id)?;
    match wallet_info.auth_method {
        AuthMethod::Password => {
            let password = prompt_for_input("Enter password: ")?;
            Ok(AuthKey::Password(password))
        }
        AuthMethod::Keychain => {
            println!("Authenticate with {}...", keychain::short_name());
            let key = keychain::retrieve_key(wallet_id)?;
            Ok(AuthKey::CryptoKey(key))
        }
        AuthMethod::Fido2 { ref credential_id } => {
            let cred_bytes =
                hex::decode(credential_id).map_err(|e| format!("Invalid credential ID: {}", e))?;
            let pin = prompt_for_input("Enter security key PIN: ")?;
            let hmac_output = keychain::fido2::authenticate(&cred_bytes, &pin)?;
            let key = qpv2_core::utilities::derive_vault_enc_key(&hmac_output)?;
            Ok(AuthKey::CryptoKey(key))
        }
        AuthMethod::Trezor { .. } => Err(
            "This is a Trezor (hardware) wallet; signing happens on the device, so there is no vault key."
                .to_string(),
        ),
    }
}

fn init_with_keychain(vault: &KeyVault, name: &str) -> Result<(), String> {
    let key = qpv2_core::utilities::get_random_bytes(32)
        .map_err(|e| format!("Failed to generate key: {}", e))?;
    keychain::store_key(vault.wallet_id, &key)?;
    if let Err(e) = vault.generate_master_seed(AuthKey::CryptoKey(key), AuthMethod::Keychain, name)
    {
        let _ = keychain::delete_key(vault.wallet_id);
        return Err(e);
    }
    Ok(())
}

// All wallets are imported as single-sig wallet by default.
fn import_with_keychain(
    vault: &KeyVault,
    seed_phrase: SecureString,
    name: &str,
    single_sig_convention: SingleSigConvention,
) -> Result<(), String> {
    let key = qpv2_core::utilities::get_random_bytes(32)
        .map_err(|e| format!("Failed to generate key: {}", e))?;
    keychain::store_key(vault.wallet_id, &key)?;
    if let Err(e) = vault.import_seed_phrase(
        seed_phrase,
        AuthKey::CryptoKey(key),
        AuthMethod::Keychain,
        name,
        single_sig_convention,
    ) {
        let _ = keychain::delete_key(vault.wallet_id);
        return Err(e);
    }
    Ok(())
}

fn init_with_fido2(vault: &KeyVault, name: &str) -> Result<(), String> {
    let pin = prompt_for_input("Enter security key PIN: ")?;
    println!("Registering credential...");
    let credential = keychain::fido2::register(&pin)?;
    let credential_id = hex::encode(&credential.credential_id);

    println!("Deriving encryption key...");
    let hmac_output = keychain::fido2::authenticate(&credential.credential_id, &pin)?;
    let key = qpv2_core::utilities::derive_vault_enc_key(&hmac_output)?;

    let auth_method = AuthMethod::Fido2 { credential_id };
    vault.generate_master_seed(AuthKey::CryptoKey(key), auth_method, name)?;
    Ok(())
}

// All wallets are imported as single-sig wallet by default.
fn import_with_fido2(
    vault: &KeyVault,
    seed_phrase: SecureString,
    name: &str,
    single_sig_convention: SingleSigConvention,
) -> Result<(), String> {
    let pin = prompt_for_input("Enter security key PIN: ")?;
    println!("Registering credential...");
    let credential = keychain::fido2::register(&pin)?;
    let credential_id = hex::encode(&credential.credential_id);

    println!("Deriving encryption key...");
    let hmac_output = keychain::fido2::authenticate(&credential.credential_id, &pin)?;
    let key = qpv2_core::utilities::derive_vault_enc_key(&hmac_output)?;

    let auth_method = AuthMethod::Fido2 { credential_id };
    vault.import_seed_phrase(
        seed_phrase,
        AuthKey::CryptoKey(key),
        auth_method,
        name,
        single_sig_convention,
    )?;
    Ok(())
}

/// Finds an existing wallet by name. Auto-selects if only one wallet exists.
fn find_wallet(wallet_name: &Option<String>) -> Result<(u32, String), String> {
    let wallets = KeyVault::list_wallets()?;
    if let Some(name) = wallet_name {
        let entry = wallets
            .into_iter()
            .find(|w| w.name == *name)
            .ok_or_else(|| format!("Wallet '{}' not found.", name))?;
        Ok((entry.id, entry.name))
    } else if wallets.len() == 1 {
        let entry = wallets.into_iter().next().unwrap();
        Ok((entry.id, entry.name))
    } else if wallets.is_empty() {
        Err("No wallet found. Run 'init' first.".to_string())
    } else {
        Err("Multiple wallets exist. Specify --wallet <name>. Run 'wallet list' to see all wallets.".to_string())
    }
}

/// Validates a wallet name for creation and returns the next available ID.
fn prepare_new_wallet(wallet_name: &Option<String>) -> Result<(u32, String), String> {
    let name = match wallet_name {
        Some(n) => n.clone(),
        None => names::Generator::default()
            .next()
            .unwrap_or_else(|| "wallet".to_string()),
    };
    let wallets = KeyVault::list_wallets()?;
    if wallets.iter().any(|w| w.name == name) {
        return Err(format!("Wallet '{}' already exists.", name));
    }
    let id = qpv2_core::db::wallets::next_wallet_id().map_err(|e| e.to_string())?;
    Ok((id, name))
}

fn lock_args_to_address(lock_args: &str, is_mainnet: bool) -> Result<ckb_sdk::Address, String> {
    use ckb_sdk::{Address, AddressPayload, NetworkType};
    use ckb_types::{bytes::Bytes, core::ScriptHashType};
    use qpv2_core::constants::{
        CKB_MAINNET_CODE_HASH, CKB_MAINNET_HASH_TYPE, CKB_TESTNET_CODE_HASH, CKB_TESTNET_HASH_TYPE,
    };

    let (code_hash_hex, hash_type_str, network) = if is_mainnet {
        (
            CKB_MAINNET_CODE_HASH,
            CKB_MAINNET_HASH_TYPE,
            NetworkType::Mainnet,
        )
    } else {
        (
            CKB_TESTNET_CODE_HASH,
            CKB_TESTNET_HASH_TYPE,
            NetworkType::Testnet,
        )
    };

    let code_hash_bytes = hex::decode(code_hash_hex.trim_start_matches("0x"))
        .map_err(|e| format!("Failed to decode code_hash: {:?}", e))?;
    let mut code_hash_array = [0u8; 32];
    code_hash_array.copy_from_slice(&code_hash_bytes);

    let script_hash_type = match hash_type_str {
        "type" => ScriptHashType::Type,
        "data1" => ScriptHashType::Data1,
        _ => return Err(format!("Unsupported hash_type: {}", hash_type_str)),
    };

    let args_bytes =
        hex::decode(lock_args).map_err(|e| format!("Failed to decode lock_args: {:?}", e))?;
    let payload = AddressPayload::new_full(
        script_hash_type,
        code_hash_array.into(),
        Bytes::from(args_bytes),
    );
    Ok(Address::new(network, payload, true))
}

fn make_qp_client(
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(ckb_node::QpClient, bool), String> {
    let (net, is_mainnet) = match network {
        "mainnet" => (ckb_node::NetworkType::Mainnet, true),
        "testnet" => (ckb_node::NetworkType::Testnet, false),
        _ => {
            return Err(format!(
                "Invalid network '{}'. Use 'mainnet' or 'testnet'.",
                network
            ))
        }
    };

    let url = match rpc_url {
        Some(u) => u.clone(),
        None => ckb_node::NodeConfig::default_rpc_url_for(ckb_node::NodeType::PublicRpc, net)
            .to_string(),
    };

    let config = ckb_node::NodeConfig {
        node_type: ckb_node::NodeType::PublicRpc,
        network: net,
        binary_path: None,
        rpc_url: url,
        data_dir: qpv2_core::db::get_data_dir()
            .map_err(|e| e.to_string())?
            .join("node"),
    };

    Ok((ckb_node::QpClient::new(config), is_mainnet))
}

fn parse_out_point(tx_hash: &str, index: u32) -> Result<ckb_types::packed::OutPoint, String> {
    use std::str::FromStr;
    let hash = ckb_types::H256::from_str(tx_hash.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid tx hash: {}", e))?;
    let json_out_point = ckb_jsonrpc_types::OutPoint {
        tx_hash: hash,
        index: ckb_jsonrpc_types::Uint32::from(index),
    };
    Ok(json_out_point.into())
}

fn handle_dao_list(
    wallet_id: u32,
    lock_args: &Option<String>,
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(), String> {
    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;

    let accounts: Vec<qpv2_core::types::SphincsPlusAccount> = if let Some(la) = lock_args {
        let acct = KeyVault::get_account(wallet_id, la)?
            .ok_or_else(|| format!("Account with lock_args '{}' not found.", la))?;
        vec![acct]
    } else {
        KeyVault::get_all_accounts(wallet_id)?
    };

    let mut found_any = false;
    for account in &accounts {
        let address = lock_args_to_address(&account.lock_args, is_mainnet)?;
        let (deposited, prepared) =
            ckb_node::wallet_helpers::queries::categorize_dao_cells(&qp_client, &address)
                .map_err(|e| format!("Failed to query DAO cells: {}", e))?;

        if deposited.is_empty() && prepared.is_empty() {
            continue;
        }
        found_any = true;

        println!("Account: {}", account.lock_args);
        if !deposited.is_empty() {
            println!("  Deposited:");
            for cell in &deposited {
                use ckb_types::prelude::*;
                let tx_hash: ckb_types::H256 = cell.out_point.tx_hash().unpack();
                let idx: u32 = cell.out_point.index().unpack();
                println!(
                    "    {:#x}:{} — {} CKB (block #{})",
                    tx_hash,
                    idx,
                    cell.capacity as f64 / 1e8,
                    cell.block_number
                );
            }
        }
        if !prepared.is_empty() {
            println!("  Prepared (ready to withdraw):");
            for cell in &prepared {
                use ckb_types::prelude::*;
                let tx_hash: ckb_types::H256 = cell.out_point.tx_hash().unpack();
                let idx: u32 = cell.out_point.index().unpack();
                println!(
                    "    {:#x}:{} — {} CKB (max withdraw: {} CKB)",
                    tx_hash,
                    idx,
                    cell.capacity as f64 / 1e8,
                    cell.maximum_withdraw as f64 / 1e8
                );
            }
        }
    }

    if !found_any {
        println!("No DAO cells found.");
    }

    Ok(())
}

fn handle_dao_deposit(
    wallet_id: u32,
    lock_args: &str,
    amount: &str,
    fee_rate: u64,
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(), String> {
    let account = KeyVault::get_account(wallet_id, lock_args)?
        .ok_or_else(|| format!("Account with lock_args '{}' not found.", lock_args))?;
    if !account.config.is_single_sig() {
        return Err(
            "This account requires multiple signatures. Use `msig build-deposit` instead."
                .to_string(),
        );
    }
    // Integer parsing — f64 mis-converts amounts by a shannon
    // (see BACKLOG.md).
    let capacity_sh = qpv2_core::utilities::parse_ckb_to_shannons(amount)?;
    if capacity_sh == 0 {
        return Err("Amount must be greater than zero.".to_string());
    }

    let max_witness_lock_size = account.config.max_witness_lock_size();
    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;
    let from_address = lock_args_to_address(lock_args, is_mainnet)?;

    println!("Building DAO deposit...");
    let unsigned_tx = ckb_node::QpDaoDepositBuilder::new(&qp_client, is_mainnet)
        .with_placeholder_lock_size(max_witness_lock_size)
        .build_unsigned_deposit(&from_address, capacity_sh, fee_rate)
        .map_err(|e| format!("Failed to build DAO deposit: {}", e))?;

    let input_cells =
        ckb_node::wallet_helpers::tx_builder::fetch_input_cells(&qp_client, &unsigned_tx)
            .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

    let message = ckb_node::compute_signing_message(&unsigned_tx, &input_cells, 0)
        .map_err(|e| format!("Failed to compute tx message: {}", e))?;

    let auth = get_auth_key(wallet_id)?;
    let variant = KeyVault::get_spx_variant(wallet_id)?;
    let vault = KeyVault::new(variant, wallet_id);
    let signature_bytes = vault.ckb_sign(auth, lock_args.to_string(), message.to_vec())?;

    let signed_tx = ckb_node::fill_witness(unsigned_tx, 0, signature_bytes)
        .map_err(|e| format!("Failed to fill witness: {}", e))?;

    println!("Submitting transaction...");
    let tx_hash = ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
        .map_err(|e| format!("Failed to send transaction: {}", e))?;
    println!("DAO deposit submitted: {:#x}", tx_hash);
    Ok(())
}

fn handle_dao_prepare(
    wallet_id: u32,
    lock_args: &str,
    tx_hash: &str,
    index: u32,
    fee_rate: u64,
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(), String> {
    let account = KeyVault::get_account(wallet_id, lock_args)?
        .ok_or_else(|| format!("Account with lock_args '{}' not found.", lock_args))?;
    if !account.config.is_single_sig() {
        return Err(
            "This account requires multiple signatures. Use `msig build-prepare` instead."
                .to_string(),
        );
    }

    let max_witness_lock_size = account.config.max_witness_lock_size();
    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;
    let from_address = lock_args_to_address(lock_args, is_mainnet)?;
    let out_point = parse_out_point(tx_hash, index)?;

    println!("Building DAO prepare...");
    let unsigned_tx = ckb_node::QpDaoPrepareBuilder::new(&qp_client, is_mainnet)
        .with_placeholder_lock_size(max_witness_lock_size)
        .build_unsigned_dao_request_withdraw(&from_address, vec![out_point], fee_rate)
        .map_err(|e| format!("Failed to build DAO prepare: {}", e))?;

    let input_cells =
        ckb_node::wallet_helpers::tx_builder::fetch_input_cells(&qp_client, &unsigned_tx)
            .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

    let message = ckb_node::compute_signing_message(&unsigned_tx, &input_cells, 0)
        .map_err(|e| format!("Failed to compute tx message: {}", e))?;

    let auth = get_auth_key(wallet_id)?;
    let variant = KeyVault::get_spx_variant(wallet_id)?;
    let vault = KeyVault::new(variant, wallet_id);
    let signature_bytes = vault.ckb_sign(auth, lock_args.to_string(), message.to_vec())?;

    let signed_tx = ckb_node::fill_witness(unsigned_tx, 0, signature_bytes)
        .map_err(|e| format!("Failed to fill witness: {}", e))?;

    println!("Submitting transaction...");
    let tx_hash = ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
        .map_err(|e| format!("Failed to send transaction: {}", e))?;
    println!("DAO prepare submitted: {:#x}", tx_hash);
    Ok(())
}

fn handle_dao_withdraw(
    wallet_id: u32,
    lock_args: &str,
    tx_hash: &str,
    index: u32,
    fee_rate: u64,
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(), String> {
    let account = KeyVault::get_account(wallet_id, lock_args)?
        .ok_or_else(|| format!("Account with lock_args '{}' not found.", lock_args))?;
    if !account.config.is_single_sig() {
        return Err(
            "This account requires multiple signatures. Use `msig build-withdraw` instead."
                .to_string(),
        );
    }

    let max_witness_lock_size = account.config.max_witness_lock_size();
    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;
    let from_address = lock_args_to_address(lock_args, is_mainnet)?;
    let out_point = parse_out_point(tx_hash, index)?;

    println!("Building DAO withdraw...");
    let unsigned_tx = ckb_node::QpDaoWithdrawBuilder::new(&qp_client, is_mainnet)
        .with_placeholder_lock_size(max_witness_lock_size)
        .build_unsigned_dao_withdraw(&from_address, vec![out_point], fee_rate)
        .map_err(|e| format!("Failed to build DAO withdraw: {}", e))?;

    let input_cells =
        ckb_node::wallet_helpers::tx_builder::fetch_input_cells(&qp_client, &unsigned_tx)
            .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

    let message = ckb_node::compute_signing_message(&unsigned_tx, &input_cells, 0)
        .map_err(|e| format!("Failed to compute tx message: {}", e))?;

    let auth = get_auth_key(wallet_id)?;
    let variant = KeyVault::get_spx_variant(wallet_id)?;
    let vault = KeyVault::new(variant, wallet_id);
    let signature_bytes = vault.ckb_sign(auth, lock_args.to_string(), message.to_vec())?;

    let signed_tx = ckb_node::fill_witness(unsigned_tx, 0, signature_bytes)
        .map_err(|e| format!("Failed to fill witness: {}", e))?;

    println!("Submitting transaction...");
    let tx_hash = ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
        .map_err(|e| format!("Failed to send transaction: {}", e))?;
    println!("DAO withdraw submitted: {:#x}", tx_hash);
    Ok(())
}

fn handle_transfer(
    wallet_id: u32,
    lock_args: &str,
    to: &str,
    amount: &str,
    fee_rate: u64,
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(), String> {
    let account = KeyVault::get_account(wallet_id, lock_args)?
        .ok_or_else(|| format!("Account with lock_args '{}' not found.", lock_args))?;

    if !account.config.is_single_sig() {
        return Err(
            "This account requires multiple signatures. Use `msig build-transfer` instead."
                .to_string(),
        );
    }

    // Integer parsing — f64 mis-converts amounts by a shannon
    // (see BACKLOG.md).
    let capacity_sh = qpv2_core::utilities::parse_ckb_to_shannons(amount)?;
    if capacity_sh == 0 {
        return Err("Amount must be greater than zero.".to_string());
    }

    let max_witness_lock_size = account.config.max_witness_lock_size();
    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;

    let from_address = lock_args_to_address(lock_args, is_mainnet)?;
    let to_address: ckb_sdk::Address = to
        .parse()
        .map_err(|e| format!("Invalid recipient address: {}", e))?;
    let expected_net = if is_mainnet {
        ckb_sdk::NetworkType::Mainnet
    } else {
        ckb_sdk::NetworkType::Testnet
    };
    if to_address.network() != expected_net {
        return Err("Recipient address is for the wrong network.".to_string());
    }

    println!("Building transaction...");
    let builder = ckb_node::QpTransferBuilder::new(&qp_client, is_mainnet)
        .with_placeholder_lock_size(max_witness_lock_size);
    let unsigned_tx = builder
        .build_unsigned_transfer(&from_address, &to_address, capacity_sh, fee_rate, None)
        .map_err(|e| format!("Failed to build transaction: {}", e))?;

    println!("Fetching input cells...");
    let input_cells =
        ckb_node::wallet_helpers::tx_builder::fetch_input_cells(&qp_client, &unsigned_tx)
            .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

    println!("Computing signing message...");
    let message = ckb_node::compute_signing_message(&unsigned_tx, &input_cells, 0)
        .map_err(|e| format!("Failed to compute tx message: {}", e))?;

    let signed_tx = if KeyVault::is_hardware_wallet(wallet_id) {
        sign_transfer_with_trezor(&account, &qp_client, is_mainnet, unsigned_tx)?
    } else {
        let auth = get_auth_key(wallet_id)?;
        let variant = KeyVault::get_spx_variant(wallet_id)?;
        let vault = KeyVault::new(variant, wallet_id);
        let signature_bytes = vault.ckb_sign(auth, lock_args.to_string(), message.to_vec())?;
        ckb_node::fill_witness(unsigned_tx, 0, signature_bytes)
            .map_err(|e| format!("Failed to fill witness: {}", e))?
    };

    println!("Submitting transaction...");
    let tx_hash = ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
        .map_err(|e| format!("Failed to send transaction: {}", e))?;

    println!("Transaction submitted: {:#x}", tx_hash);
    Ok(())
}

/// Sign a single-sig transfer with a Trezor device: stream the transaction (and
/// its previous transactions) to the device and fill the returned witness lock.
fn sign_transfer_with_trezor(
    account: &qpv2_core::types::SphincsPlusAccount,
    qp_client: &ckb_node::QpClient,
    is_mainnet: bool,
    unsigned_tx: ckb_types::core::TransactionView,
) -> Result<ckb_types::core::TransactionView, String> {
    println!("Fetching previous transactions for the device...");
    let prev_txs = ckb_node::wallet_helpers::tx_builder::fetch_prev_txs(qp_client, &unsigned_tx)
        .map_err(|e| format!("Failed to fetch previous transactions: {}", e))?;

    let variant = account.config.signers[0].variant;
    let sign_group: Vec<u32> = (0..unsigned_tx.inputs().len() as u32).collect();

    println!("Confirm the transaction on your Trezor...");
    let mut device = trezor_connect::open(&mut trezor_connect::StdinPairing)
        .map_err(|e| format!("Could not connect to Trezor: {}", e))?;
    let signed = device
        .sign_tx(
            account.index,
            variant,
            is_mainnet,
            &unsigned_tx,
            account.config.max_witness_lock_size(),
            &prev_txs,
            &sign_group,
        )
        .map_err(|e| format!("Trezor signing failed: {}", e))?;

    ckb_node::fill_witness(unsigned_tx, 0, signed.witness_lock)
        .map_err(|e| format!("Failed to fill witness: {}", e))
}

/// Shared context for the multisig `build-*` CLI handlers: the wallet,
/// account selector, fee, output path, and network that every variant
/// needs. Grouping them keeps each handler's own parameter list short.
struct MsigBuildCtx<'a> {
    wallet_id: u32,
    lock_args: &'a str,
    fee_rate: u64,
    output: &'a str,
    network: &'a str,
    rpc_url: &'a Option<String>,
}

fn handle_msig_build_dao(
    ctx: &MsigBuildCtx,
    op: &str,
    amount: &str,
    tx_hash: Option<&str>,
    index: u32,
) -> Result<(), String> {
    let &MsigBuildCtx {
        wallet_id,
        lock_args,
        fee_rate,
        output,
        network,
        rpc_url,
    } = ctx;
    let account = KeyVault::get_account(wallet_id, lock_args)?
        .ok_or_else(|| format!("Account with lock_args '{}' not found.", lock_args))?;

    if account.config.is_single_sig() {
        return Err(format!(
            "This is a single-sig account. Use `dao {}` instead.",
            op
        ));
    }

    let max_witness_lock_size = account.config.max_witness_lock_size();
    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;
    let from_address = lock_args_to_address(lock_args, is_mainnet)?;

    println!("Building unsigned DAO {} transaction...", op);
    let unsigned_tx = match op {
        "deposit" => {
            // Integer parsing — f64 mis-converts amounts by a
            // shannon (see BACKLOG.md).
            let capacity_sh = qpv2_core::utilities::parse_ckb_to_shannons(amount)?;
            if capacity_sh == 0 {
                return Err("Amount must be greater than zero.".to_string());
            }
            ckb_node::QpDaoDepositBuilder::new(&qp_client, is_mainnet)
                .with_placeholder_lock_size(max_witness_lock_size)
                .build_unsigned_deposit(&from_address, capacity_sh, fee_rate)
                .map_err(|e| format!("Failed to build DAO deposit: {}", e))?
        }
        "prepare" => {
            let out_point = parse_out_point(tx_hash.ok_or("tx_hash required for prepare")?, index)?;
            ckb_node::QpDaoPrepareBuilder::new(&qp_client, is_mainnet)
                .with_placeholder_lock_size(max_witness_lock_size)
                .build_unsigned_dao_request_withdraw(&from_address, vec![out_point], fee_rate)
                .map_err(|e| format!("Failed to build DAO prepare: {}", e))?
        }
        "withdraw" => {
            let out_point =
                parse_out_point(tx_hash.ok_or("tx_hash required for withdraw")?, index)?;
            ckb_node::QpDaoWithdrawBuilder::new(&qp_client, is_mainnet)
                .with_placeholder_lock_size(max_witness_lock_size)
                .build_unsigned_dao_withdraw(&from_address, vec![out_point], fee_rate)
                .map_err(|e| format!("Failed to build DAO withdraw: {}", e))?
        }
        _ => return Err(format!("Unknown DAO operation: {}", op)),
    };

    println!("Fetching input cells...");
    let input_cells =
        ckb_node::wallet_helpers::tx_builder::fetch_input_cells(&qp_client, &unsigned_tx)
            .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

    let metadata = qpv2_core::types::SigningMetadata {
        from_address: from_address.to_string(),
        to_address: None,
        amount_ckb: if op == "deposit" {
            Some(amount.to_string())
        } else {
            None
        },
        tx_type: format!("DAO {}", op),
    };

    println!("Computing signing message...");
    let request = ckb_node::build_signing_request(
        &unsigned_tx,
        &input_cells,
        &account.config,
        0,
        is_mainnet,
        metadata,
    )
    .map_err(|e| format!("Failed to build signing request: {}", e))?;

    let json = serde_json::to_string_pretty(&request)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    fs::write(output, &json).map_err(|e| format!("Failed to write file: {}", e))?;

    println!("Signing request written to: {}", output);
    println!("Message: {}", request.signing_message);
    println!(
        "Requires {} of {} signatures.",
        account.config.threshold,
        account.config.signers.len()
    );
    Ok(())
}

fn handle_msig_build_transfer(ctx: &MsigBuildCtx, to: &str, amount: &str) -> Result<(), String> {
    let &MsigBuildCtx {
        wallet_id,
        lock_args,
        fee_rate,
        output,
        network,
        rpc_url,
    } = ctx;
    let account = KeyVault::get_account(wallet_id, lock_args)?
        .ok_or_else(|| format!("Account with lock_args '{}' not found.", lock_args))?;

    if account.config.is_single_sig() {
        return Err("This is a single-sig account. Use `transfer` instead.".to_string());
    }

    let max_witness_lock_size = account.config.max_witness_lock_size();

    let (qp_client, is_mainnet) = make_qp_client(network, rpc_url)?;

    let from_address = lock_args_to_address(lock_args, is_mainnet)?;
    let to_address: ckb_sdk::Address = to
        .parse()
        .map_err(|e| format!("Invalid recipient address: {}", e))?;
    let expected_net = if is_mainnet {
        ckb_sdk::NetworkType::Mainnet
    } else {
        ckb_sdk::NetworkType::Testnet
    };
    if to_address.network() != expected_net {
        return Err("Recipient address is for the wrong network.".to_string());
    }

    // Integer parsing — f64 mis-converts amounts by a shannon
    // (see BACKLOG.md).
    let capacity_sh = qpv2_core::utilities::parse_ckb_to_shannons(amount)?;
    if capacity_sh == 0 {
        return Err("Amount must be greater than zero.".to_string());
    }

    let builder = ckb_node::QpTransferBuilder::new(&qp_client, is_mainnet)
        .with_placeholder_lock_size(max_witness_lock_size);

    println!("Building unsigned transaction...");
    let unsigned_tx = builder
        .build_unsigned_transfer(&from_address, &to_address, capacity_sh, fee_rate, None)
        .map_err(|e| format!("Failed to build transaction: {}", e))?;

    println!("Fetching input cells...");
    let input_cells =
        ckb_node::wallet_helpers::tx_builder::fetch_input_cells(&qp_client, &unsigned_tx)
            .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

    let metadata = qpv2_core::types::SigningMetadata {
        from_address: from_address.to_string(),
        to_address: Some(to.to_string()),
        amount_ckb: Some(amount.to_string()),
        tx_type: "Transfer".to_string(),
    };

    println!("Computing signing message...");
    let request = ckb_node::build_signing_request(
        &unsigned_tx,
        &input_cells,
        &account.config,
        0,
        is_mainnet,
        metadata,
    )
    .map_err(|e| format!("Failed to build signing request: {}", e))?;

    let json = serde_json::to_string_pretty(&request)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    fs::write(output, &json).map_err(|e| format!("Failed to write file: {}", e))?;

    println!("Signing request written to: {}", output);
    println!("Message: {}", request.signing_message);
    println!(
        "Requires {} of {} signatures.",
        account.config.threshold,
        account.config.signers.len()
    );
    Ok(())
}

fn handle_msig_sign(wallet_id: u32, request_path: &str, output: &str) -> Result<(), String> {
    let json = fs::read_to_string(request_path)
        .map_err(|e| format!("Failed to read request file: {}", e))?;
    let request: qpv2_core::types::SigningRequest =
        serde_json::from_str(&json).map_err(|e| format!("Invalid signing request JSON: {}", e))?;

    println!("Transaction type: {}", request.metadata.tx_type);
    println!("From: {}", request.metadata.from_address);
    if let Some(ref to) = request.metadata.to_address {
        println!("To: {}", to);
    }
    if let Some(ref amount) = request.metadata.amount_ckb {
        println!("Amount: {} CKB", amount);
    }
    println!(
        "Threshold: {}-of-{}",
        request.multisig_config.threshold,
        request.multisig_config.signers.len()
    );

    let singlesig_accounts = KeyVault::get_singlesig_accounts(wallet_id)?;
    let variant = KeyVault::get_spx_variant(wallet_id)?;

    let mut matched_signer_index = None;
    let mut matched_lock_args = None;

    for account in &singlesig_accounts {
        let account_pubkey = &account.config.signers[0].pubkey;
        for (i, signer) in request.multisig_config.signers.iter().enumerate() {
            if signer.pubkey == *account_pubkey && signer.variant == variant {
                matched_signer_index = Some(i);
                matched_lock_args = Some(account.lock_args.clone());
                break;
            }
        }
        if matched_signer_index.is_some() {
            break;
        }
    }

    let signer_index = matched_signer_index.ok_or_else(|| {
        "No local singlesig account matches any signer in this multisig config.".to_string()
    })?;
    let singlesig_lock_args = matched_lock_args.unwrap();

    println!("Matched local account as signer index {}.", signer_index);

    let message_bytes = hex::decode(&request.signing_message)
        .map_err(|e| format!("Invalid signing message hex: {}", e))?;

    let auth = get_auth_key(wallet_id)?;
    let vault = KeyVault::new(variant, wallet_id);

    let (signature, _pubkey) = vault.raw_sign(auth, singlesig_lock_args, message_bytes)?;

    let response = qpv2_core::types::SigningResponse {
        version: request.version,
        signer_index,
        signature: hex::encode(&signature),
        signing_message: request.signing_message.clone(),
    };

    let response_json = serde_json::to_string_pretty(&response)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    fs::write(output, &response_json).map_err(|e| format!("Failed to write file: {}", e))?;

    println!("Signing response written to: {}", output);
    Ok(())
}

fn handle_msig_submit(
    request_path: &str,
    response_paths: &[String],
    network: &str,
    rpc_url: &Option<String>,
) -> Result<(), String> {
    let req_json = fs::read_to_string(request_path)
        .map_err(|e| format!("Failed to read request file: {}", e))?;
    let request: qpv2_core::types::SigningRequest = serde_json::from_str(&req_json)
        .map_err(|e| format!("Invalid signing request JSON: {}", e))?;

    if (network == "mainnet") != request.is_mainnet {
        return Err("Network mismatch: request was built for a different network.".to_string());
    }

    let mut signatures: Vec<(usize, Vec<u8>)> = Vec::new();

    for path in response_paths {
        let resp_json = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read response file '{}': {}", path, e))?;
        let response: qpv2_core::types::SigningResponse = serde_json::from_str(&resp_json)
            .map_err(|e| format!("Invalid signing response JSON in '{}': {}", path, e))?;

        if response.signing_message != request.signing_message {
            return Err(format!(
                "Response from '{}' has mismatched signing message.",
                path
            ));
        }

        let sig_bytes = hex::decode(&response.signature)
            .map_err(|e| format!("Invalid signature hex in '{}': {}", path, e))?;
        signatures.push((response.signer_index, sig_bytes));
    }

    let threshold = request.multisig_config.threshold as usize;
    if signatures.len() != threshold {
        return Err(format!(
            "Expected {} response file(s) (threshold), got {}.",
            threshold,
            signatures.len()
        ));
    }

    println!("Assembling witness with {} signatures...", signatures.len());
    let witness_lock = ckb_node::assemble_multisig_witness(&request.multisig_config, &signatures)
        .map_err(|e| format!("Failed to assemble witness: {}", e))?;

    let json_tx: ckb_jsonrpc_types::Transaction = serde_json::from_value(request.unsigned_tx)
        .map_err(|e| format!("Failed to parse unsigned tx: {}", e))?;
    let packed_tx: ckb_types::packed::Transaction = json_tx.into();
    use ckb_types::prelude::IntoTransactionView;
    let unsigned_tx = packed_tx.into_view();

    let signed_tx = ckb_node::fill_witness(unsigned_tx, request.script_group_index, witness_lock)
        .map_err(|e| format!("Failed to fill witness: {}", e))?;

    let (qp_client, _) = make_qp_client(network, rpc_url)?;

    println!("Submitting transaction...");
    let tx_hash = ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
        .map_err(|e| format!("Failed to send transaction: {}", e))?;

    println!("Transaction submitted: {:#x}", tx_hash);
    Ok(())
}

fn main() -> Result<(), String> {
    if let Ok(data_dir) = qpv2_core::db::get_data_dir() {
        let log_path = data_dir.join("qpv2.log");
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(file)
                .with_ansi(false)
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_max_level(tracing::Level::INFO)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            variant,
            keychain,
            fido2,
        } => {
            let variant = parse_variant(&variant)?;
            let (wallet_id, name) = prepare_new_wallet(&cli.wallet)?;
            let vault = KeyVault::new(variant, wallet_id);

            println!("Initializing wallet '{}' with variant: {}", name, variant);
            println!(
                "Required mnemonic words: {}",
                variant.required_bip39_size_in_word_total()
            );

            if keychain && fido2 {
                return Err("Cannot use both --keychain and --fido2.".to_string());
            } else if fido2 {
                init_with_fido2(&vault, &name)?;
            } else if keychain {
                init_with_keychain(&vault, &name)?;
            } else {
                let password = prompt_for_input("Enter password: ")?;
                let confirm = prompt_for_input("Confirm password: ")?;
                if password != confirm {
                    return Err("Passwords do not match".to_string());
                }

                match qpv2_core::utilities::password_checker(&password) {
                    Ok(strength) => println!("Password strength: {} bits", strength),
                    Err(e) => {
                        return Err(format!("Password validation failed: {}", e));
                    }
                }

                vault.generate_master_seed(
                    AuthKey::Password(password),
                    AuthMethod::Password,
                    &name,
                )?;
            }
            println!("✓ Master seed generated successfully");
            println!(
                "⚠️  Make sure to backup your seed phrase using the 'mnemonic export' command"
            );
        }

        Commands::Mnemonic { command } => match command {
            MnemonicCommands::Import {
                variant,
                seed_file,
                keychain,
                fido2,
                v1,
            } => {
                let variant = parse_variant(&variant)?;
                let (wallet_id, name) = prepare_new_wallet(&cli.wallet)?;
                let vault = KeyVault::new(variant, wallet_id);
                let single_sig_convention = SingleSigConvention::new(v1);

                let seed_phrase = if let Some(file_path) = seed_file {
                    SecureString::from_string(
                        fs::read_to_string(file_path).map_err(|e| e.to_string())?,
                    )
                } else {
                    prompt_for_input("Enter seed phrase: ")?
                };

                if keychain && fido2 {
                    return Err("Cannot use both --keychain and --fido2.".to_string());
                } else if fido2 {
                    import_with_fido2(&vault, seed_phrase, &name, single_sig_convention)?;
                } else if keychain {
                    import_with_keychain(&vault, seed_phrase, &name, single_sig_convention)?;
                } else {
                    let password = prompt_for_input("Enter password: ")?;
                    let confirm = prompt_for_input("Confirm password: ")?;
                    if password != confirm {
                        return Err("Passwords do not match".to_string());
                    }

                    match qpv2_core::utilities::password_checker(&password) {
                        Ok(strength) => println!("Password strength: {} bits", strength),
                        Err(e) => {
                            return Err(format!("Password validation failed: {}", e));
                        }
                    }

                    vault.import_seed_phrase(
                        seed_phrase,
                        AuthKey::Password(password),
                        AuthMethod::Password,
                        &name,
                        single_sig_convention,
                    )?;
                }
                println!("✓ Seed phrase imported successfully");
            }

            MnemonicCommands::Export { output } => {
                let (wallet_id, _) = find_wallet(&cli.wallet)?;
                let variant = KeyVault::get_spx_variant(wallet_id)?;
                let vault = KeyVault::new(variant, wallet_id);

                let auth = get_auth_key(wallet_id)?;
                let seed_phrase = vault.export_seed_phrase(auth)?;

                if let Some(output_path) = output {
                    fs::write(&output_path, &*seed_phrase).map_err(|e| e.to_string())?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))
                            .map_err(|e| e.to_string())?;
                    }
                    println!("✓ Seed phrase exported to file");
                } else {
                    println!("Seed phrase:");
                    println!("{}", &*seed_phrase);
                }
            }
        },

        Commands::Account { command } => {
            let (wallet_id, _) = find_wallet(&cli.wallet)?;

            match command {
                AccountCommands::New => {
                    let variant = KeyVault::get_spx_variant(wallet_id)?;
                    let vault = KeyVault::new(variant, wallet_id);

                    let auth = get_auth_key(wallet_id)?;
                    let account = vault.gen_singlesig_account(auth)?;
                    println!("✓ New account created");
                    println!(
                        "Identifier(CKB quantum lock script args): {}",
                        account.lock_args
                    );
                }

                AccountCommands::NewMultisig {
                    singlesig_lock_args,
                    threshold,
                    required_first_n,
                    signer,
                } => {
                    let co_signers: Vec<qpv2_core::types::Signer> = signer
                        .iter()
                        .map(|s| {
                            let (var_str, hex) = s.split_once(':').ok_or_else(|| {
                                format!(
                                    "Invalid signer format '{}'. Expected 'Variant:hex_pubkey'.",
                                    s
                                )
                            })?;
                            let v = parse_variant(var_str)?;
                            let pubkey = hex::decode(hex)
                                .map_err(|e| format!("Invalid pubkey hex '{}': {}", hex, e))?;
                            Ok(qpv2_core::types::Signer { variant: v, pubkey })
                        })
                        .collect::<Result<Vec<_>, String>>()?;

                    let account = KeyVault::gen_multisig_account(
                        wallet_id,
                        &singlesig_lock_args,
                        co_signers,
                        threshold,
                        required_first_n,
                    )?;
                    println!(
                        "✓ Multisig account created ({}-of-{})",
                        account.config.threshold,
                        account.config.signers.len()
                    );
                    println!(
                        "Identifier(CKB quantum lock script args): {}",
                        account.lock_args
                    );
                }

                AccountCommands::List => {
                    let single = KeyVault::get_singlesig_accounts(wallet_id)?;
                    let multisig = KeyVault::get_multisig_accounts(wallet_id)?;

                    if single.is_empty() && multisig.is_empty() {
                        println!("No accounts found. Run `qpv2-cli account new` to generate a new SPHINCS+ account");
                    } else {
                        if !single.is_empty() {
                            println!("Single-sig ({}):", single.len());
                            println!("  Index  Account Identifier (CKB Quantum Lock Args)");
                            println!("  ─────────────────────────────────────────────────────────────────────");
                            for (idx, account) in single.iter().enumerate() {
                                let signer = &account.config.signers[0];
                                println!("  [{}]    {}", idx, account.lock_args);
                                println!(
                                    "         Pubkey:  {}:{}",
                                    signer.variant,
                                    hex::encode(&signer.pubkey)
                                );
                            }
                        }

                        if !multisig.is_empty() {
                            println!();
                            println!("Multisig ({}):", multisig.len());
                            println!(
                                "  Index  Type       Account Identifier (CKB Quantum Lock Args)"
                            );
                            println!("  ─────────────────────────────────────────────────────────────────────");
                            for (idx, account) in multisig.iter().enumerate() {
                                let n = account.config.signers.len();
                                println!(
                                    "  [{}]    {}-of-{:<4}  {}",
                                    idx, account.config.threshold, n, account.lock_args
                                );
                            }
                        }
                    }
                }

                AccountCommands::Recover { count } => {
                    let variant = KeyVault::get_spx_variant(wallet_id)?;
                    let vault = KeyVault::new(variant, wallet_id);

                    let auth = get_auth_key(wallet_id)?;
                    let accounts = vault.recover_accounts(auth, count)?;

                    println!("✓ Recovered {} accounts:", accounts.len());
                    for (idx, lock_args) in accounts.iter().enumerate() {
                        println!("  [{}] {}", idx, lock_args);
                    }
                }

                AccountCommands::TryGenBatch { start, count } => {
                    let variant = KeyVault::get_spx_variant(wallet_id)?;
                    let vault = KeyVault::new(variant, wallet_id);

                    let auth = get_auth_key(wallet_id)?;
                    let accounts = vault.try_gen_account_batch(auth, start, count)?;

                    println!("Generated {} accounts:", accounts.len());
                    for (idx, lock_args) in accounts.iter().enumerate() {
                        println!("  [{}] {}", start + idx as u32, lock_args);
                    }
                }
            }
        }

        Commands::Sign {
            identifier,
            message,
        } => {
            let (wallet_id, _) = find_wallet(&cli.wallet)?;
            let variant = KeyVault::get_spx_variant(wallet_id)?;
            let vault = KeyVault::new(variant, wallet_id);

            let message_bytes = hex::decode(&message).map_err(|e| e.to_string())?;
            let auth = get_auth_key(wallet_id)?;

            let (signature, pub_key) = vault.raw_sign(auth, identifier, message_bytes)?;
            println!("Signature: {}", hex::encode(signature));
            println!("Public Key: {}", hex::encode(pub_key));
        }

        Commands::Verify {
            variant,
            public_key,
            message,
            signature,
        } => {
            let variant = parse_variant(&variant)?;
            let message_bytes = hex::decode(&message).map_err(|e| e.to_string())?;
            let public_key_bytes = hex::decode(&public_key).map_err(|e| e.to_string())?;
            let signature_bytes = hex::decode(&signature).map_err(|e| e.to_string())?;

            let is_valid =
                KeyVault::raw_verify(variant, &public_key_bytes, &message_bytes, &signature_bytes)?;
            if is_valid {
                println!("✓ Signature is valid");
            } else {
                println!("✗ Signature is invalid");
            }
        }

        Commands::Ckb { command } => match command {
            CkbCommands::Sign { lock_args, message } => {
                let (wallet_id, _) = find_wallet(&cli.wallet)?;
                let variant = KeyVault::get_spx_variant(wallet_id)?;
                let vault = KeyVault::new(variant, wallet_id);

                let message_bytes = hex::decode(&message).map_err(|e| e.to_string())?;
                let auth = get_auth_key(wallet_id)?;

                let signature = vault.ckb_sign(auth, lock_args, message_bytes)?;
                println!("Signature: {}", hex::encode(signature));
            }

            CkbCommands::GetTxMessage { tx_file } => {
                let tx_data = fs::read(tx_file).map_err(|e| e.to_string())?;
                let message = qpv2_core::utilities::get_ckb_tx_message_all(tx_data)?;
                println!("CKB Tx message hash: {}", hex::encode(message));
            }
        },

        Commands::Transfer {
            lock_args,
            to,
            amount,
            fee_rate,
            network,
            rpc_url,
        } => {
            let (wallet_id, _) = find_wallet(&cli.wallet)?;
            handle_transfer(
                wallet_id, &lock_args, &to, &amount, fee_rate, &network, &rpc_url,
            )?;
        }

        Commands::Dao {
            network,
            rpc_url,
            command,
        } => {
            let (wallet_id, _) = find_wallet(&cli.wallet)?;

            match command {
                DaoCommands::List { lock_args } => {
                    handle_dao_list(wallet_id, &lock_args, &network, &rpc_url)?;
                }
                DaoCommands::Deposit {
                    lock_args,
                    amount,
                    fee_rate,
                } => {
                    handle_dao_deposit(
                        wallet_id, &lock_args, &amount, fee_rate, &network, &rpc_url,
                    )?;
                }
                DaoCommands::Prepare {
                    lock_args,
                    tx_hash,
                    index,
                    fee_rate,
                } => {
                    handle_dao_prepare(
                        wallet_id, &lock_args, &tx_hash, index, fee_rate, &network, &rpc_url,
                    )?;
                }
                DaoCommands::Withdraw {
                    lock_args,
                    tx_hash,
                    index,
                    fee_rate,
                } => {
                    handle_dao_withdraw(
                        wallet_id, &lock_args, &tx_hash, index, fee_rate, &network, &rpc_url,
                    )?;
                }
            }
        }

        Commands::Msig {
            network,
            rpc_url,
            command,
        } => {
            let (wallet_id, _) = find_wallet(&cli.wallet)?;

            match command {
                MsigCommands::BuildTransfer {
                    lock_args,
                    to,
                    amount,
                    fee_rate,
                    output,
                } => {
                    handle_msig_build_transfer(
                        &MsigBuildCtx {
                            wallet_id,
                            lock_args: &lock_args,
                            fee_rate,
                            output: &output,
                            network: &network,
                            rpc_url: &rpc_url,
                        },
                        &to,
                        &amount,
                    )?;
                }
                MsigCommands::BuildDeposit {
                    lock_args,
                    amount,
                    fee_rate,
                    output,
                } => {
                    handle_msig_build_dao(
                        &MsigBuildCtx {
                            wallet_id,
                            lock_args: &lock_args,
                            fee_rate,
                            output: &output,
                            network: &network,
                            rpc_url: &rpc_url,
                        },
                        "deposit",
                        &amount,
                        None,
                        0,
                    )?;
                }
                MsigCommands::BuildPrepare {
                    lock_args,
                    tx_hash,
                    index,
                    fee_rate,
                    output,
                } => {
                    handle_msig_build_dao(
                        &MsigBuildCtx {
                            wallet_id,
                            lock_args: &lock_args,
                            fee_rate,
                            output: &output,
                            network: &network,
                            rpc_url: &rpc_url,
                        },
                        "prepare",
                        "0", // Unused: only the deposit op takes an amount.
                        Some(&tx_hash),
                        index,
                    )?;
                }
                MsigCommands::BuildWithdraw {
                    lock_args,
                    tx_hash,
                    index,
                    fee_rate,
                    output,
                } => {
                    handle_msig_build_dao(
                        &MsigBuildCtx {
                            wallet_id,
                            lock_args: &lock_args,
                            fee_rate,
                            output: &output,
                            network: &network,
                            rpc_url: &rpc_url,
                        },
                        "withdraw",
                        "0", // Unused: only the deposit op takes an amount.
                        Some(&tx_hash),
                        index,
                    )?;
                }
                MsigCommands::Sign { request, output } => {
                    handle_msig_sign(wallet_id, &request, &output)?;
                }
                MsigCommands::Submit { request, response } => {
                    handle_msig_submit(&request, &response, &network, &rpc_url)?;
                }
            }
        }

        Commands::Delete => {
            let (wallet_id, name) = find_wallet(&cli.wallet)?;
            print!(
                "Are you sure you want to remove wallet '{}' and all its data? (yes/no): ",
                name
            );
            io::stdout().flush().map_err(|e| e.to_string())?;

            let mut confirmation = String::new();
            io::stdin()
                .read_line(&mut confirmation)
                .map_err(|e| e.to_string())?;

            if confirmation.trim().to_lowercase() == "yes" {
                let _ = keychain::delete_key(wallet_id);
                KeyVault::remove_wallet(wallet_id)?;
                println!("✓ Wallet '{}' removed", name);
            } else {
                println!("Operation cancelled");
            }
        }

        Commands::Wallet { command } => match command {
            WalletCommands::List => {
                let wallets = KeyVault::list_wallets()?;
                if wallets.is_empty() {
                    println!("No wallets found. Run 'init' to create one.");
                } else {
                    println!("Wallets ({}):\n", wallets.len());
                    for entry in &wallets {
                        let wallet_info = KeyVault::read_wallet_info(entry.id)?;
                        let accounts = KeyVault::get_all_lock_args(entry.id)?;
                        let data_path =
                            qpv2_core::db::get_wallet_dir(entry.id).map_err(|e| e.to_string())?;

                        let auth_method_display = match wallet_info.auth_method {
                            AuthMethod::Password => "Password".to_string(),
                            AuthMethod::Keychain => keychain::display_name().to_string(),
                            AuthMethod::Fido2 { .. } => "FIDO2 Security Key".to_string(),
                            AuthMethod::Trezor { ref model } => format!("Trezor ({model})"),
                        };

                        println!("  [{}] {}", entry.id, entry.name);
                        println!("      Variant               : {}", wallet_info.spx_variant);
                        println!("      Authentication        : {}", auth_method_display);
                        println!(
                            "      Single-sig convention : {}",
                            wallet_info.single_sig_convention
                        );
                        println!("      Accounts              : {}", accounts.len());
                        println!("      Path                  : {}", data_path.display());
                        println!();
                    }
                }
            }
            WalletCommands::Rename { to } => {
                let (wallet_id, old_name) = find_wallet(&cli.wallet)?;
                qpv2_core::db::wallets::rename_wallet(wallet_id, &to).map_err(|e| e.to_string())?;
                println!("✓ Wallet renamed from '{}' to '{}'", old_name, to);
            }
        },
    }

    Ok(())
}
