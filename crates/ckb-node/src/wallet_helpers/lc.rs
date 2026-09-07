//! Light-client filter-script management for the wallet's accounts.
//!
//! The light client only indexes cells whose lock matches a script it's
//! been told to track via `set_scripts`. These free functions manage
//! that registration on behalf of the wallet — translating QPV2's
//! account `lock_args` and the active network into the right
//! `(code_hash, hash_type, args)` tuples and applying a sensible
//! start-block policy.
//!
//! All functions error with `UnsupportedOperation` when called against
//! a non-LightClient backend; full nodes / public RPC index every cell
//! and don't need (or expose) this surface. The downcast is enforced
//! here at the boundary so call sites don't repeat it.

use ckb_types::H256;

use crate::client::{LightClient, QpClient};
use crate::config::NetworkType;
use crate::error::NodeManagerError;

/// Asks the light client to pull the QR-lock-script deployment cell
/// into its local store. The LC otherwise wouldn't index it (its lock
/// isn't one of ours) and would reject any transfer that uses it as a
/// cell dep.
///
/// Returns `true` once the dep is in the LC's store; `false` while the
/// fetch is still pending. Idempotent.
pub fn fetch_qr_lock_dep(qp_client: &QpClient) -> Result<bool, NodeManagerError> {
    let Some(light) = qp_client.as_any().downcast_ref::<LightClient>() else {
        return Err(NodeManagerError::UnsupportedOperation {
            node_type: qp_client.config().node_type.to_string(),
            reason: "fetch_qr_lock_dep is light-client-only.".to_string(),
        });
    };
    let dep_tx_hash_hex = match qp_client.config().network {
        NetworkType::Mainnet => qpv2_core::constants::CKB_MAINNET_CELL_DEP_TX_HASH,
        NetworkType::Testnet => qpv2_core::constants::CKB_TESTNET_CELL_DEP_TX_HASH,
    };
    let tx_hash: H256 = dep_tx_hash_hex
        .trim_start_matches("0x")
        .parse()
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid QR lock dep tx hash: {}", e)))?;
    light.fetch_transaction(tx_hash)
}

/// Registers wallet lock scripts with the LC's indexer at the given
/// `start_block`. Empty input is a no-op.
///
/// The LC's `set_scripts(Partial)` skips already-tracked scripts so
/// existing sync cursors are preserved. For deliberate cursor reset
/// (manual rescan), call [`register_all_lock_scripts`] instead.
pub fn register_lock_scripts(
    qp_client: &QpClient,
    lock_args_list: &[String],
    start_block: u64,
) -> Result<(), NodeManagerError> {
    let Some(light) = qp_client.as_any().downcast_ref::<LightClient>() else {
        return Err(NodeManagerError::UnsupportedOperation {
            node_type: qp_client.config().node_type.to_string(),
            reason: "register_lock_scripts is light-client-only.".to_string(),
        });
    };
    if lock_args_list.is_empty() {
        return Ok(());
    }

    let scripts: Vec<(&str, u64)> = lock_args_list
        .iter()
        .map(|a| (a.as_str(), start_block))
        .collect();
    light.register_lock_scripts(&scripts, qp_client.config().network)
}

/// Removes only the given wallet's scripts from the light client,
/// preserving scripts from other wallets. Fetches the current script
/// list, filters out entries whose `args` match `lock_args_list`, and
/// replaces the full list with the remainder. No-op when the backend
/// isn't LightClient or `lock_args_list` is empty.
pub fn clear_wallet_scripts(
    qp_client: &QpClient,
    lock_args_list: &[String],
) -> Result<(), NodeManagerError> {
    let Some(light) = qp_client.as_any().downcast_ref::<LightClient>() else {
        return Ok(());
    };
    if lock_args_list.is_empty() {
        return Ok(());
    }

    let to_remove: std::collections::HashSet<Vec<u8>> = lock_args_list
        .iter()
        .filter_map(|hex| {
            let clean = hex.strip_prefix("0x").unwrap_or(hex);
            hex::decode(clean).ok()
        })
        .collect();

    let remaining: Vec<_> = light
        .get_scripts()?
        .into_iter()
        .filter(|ss| !to_remove.contains(ss.script.args.as_bytes()))
        .collect();

    light.replace_scripts(remaining)
}

/// Forces every given lock script to `start_block` on the LC,
/// **without** the cursor-preservation filter. Use only from a manual
/// "set scan from block" UI control where the user explicitly asked
/// for a rescan. Empty input is a no-op.
pub fn register_all_lock_scripts(
    qp_client: &QpClient,
    lock_args_list: &[String],
    start_block: u64,
) -> Result<(), NodeManagerError> {
    let Some(light) = qp_client.as_any().downcast_ref::<LightClient>() else {
        return Err(NodeManagerError::UnsupportedOperation {
            node_type: qp_client.config().node_type.to_string(),
            reason: "register_all_lock_scripts is light-client-only.".to_string(),
        });
    };
    if lock_args_list.is_empty() {
        return Ok(());
    }
    let scripts: Vec<(&str, u64)> = lock_args_list
        .iter()
        .map(|a| (a.as_str(), start_block))
        .collect();
    light.register_all_lock_scripts(&scripts, qp_client.config().network)
}
