//! Shared utilities for wallet-domain helpers.

use crate::config::NetworkType;
use crate::error::NodeManagerError;

/// Builds the Quantum Resistant lock script for `network` with the given
/// lock args (empty args + the indexer's default prefix mode match all
/// cells under the contract).
pub(crate) fn build_qr_lock_script(
    network: NetworkType,
    lock_args_hex: &str,
) -> Result<ckb_jsonrpc_types::Script, NodeManagerError> {
    let (code_hash_hex, hash_type_str) = match network {
        NetworkType::Mainnet => (
            qpv2_core::constants::CKB_MAINNET_CODE_HASH,
            qpv2_core::constants::CKB_MAINNET_HASH_TYPE,
        ),
        NetworkType::Testnet => (
            qpv2_core::constants::CKB_TESTNET_CODE_HASH,
            qpv2_core::constants::CKB_TESTNET_HASH_TYPE,
        ),
    };

    let hash_type = match hash_type_str {
        "type" => ckb_jsonrpc_types::ScriptHashType::Type,
        "data1" => ckb_jsonrpc_types::ScriptHashType::Data1,
        _ => ckb_jsonrpc_types::ScriptHashType::Data,
    };

    // H256: FromStr does the hex-decode and 32-byte length check in one
    // step (same idiom as tx_builder/utils.rs).
    let code_hash: ckb_types::H256 = code_hash_hex
        .trim_start_matches("0x")
        .parse()
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid QR lock code hash: {}", e)))?;

    let args_clean = lock_args_hex.strip_prefix("0x").unwrap_or(lock_args_hex);
    let args = hex::decode(args_clean)
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid lock args hex: {}", e)))?;

    Ok(ckb_jsonrpc_types::Script {
        code_hash,
        hash_type,
        args: ckb_jsonrpc_types::JsonBytes::from_bytes(args.into()),
    })
}
