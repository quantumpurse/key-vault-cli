//! Balance queries for QuantumPurse lock scripts.

use crate::client::QpClient;
use crate::error::NodeManagerError;
use crate::wallet_helpers::utils::build_qr_lock_script;
use ckb_sdk::rpc::ckb_indexer::{ScriptType, SearchKey, SearchKeyFilter};

/// Queries the total balance (in shannons) for a QuantumPurse lock
/// script. Selects the correct lock deployment for the active network
/// via the shared [`build_qr_lock_script`] builder, then asks the indexer for
/// the total capacity under it.
pub fn fetch_quantum_lock_balance(
    qp_client: &QpClient,
    lock_args_hex: &str,
) -> Result<u64, NodeManagerError> {
    let script = build_qr_lock_script(qp_client.config().network, lock_args_hex)?;

    let search_key = SearchKey {
        script,
        script_type: ScriptType::Lock,
        script_search_mode: None,
        filter: Some(SearchKeyFilter {
            script: None,
            script_len_range: None,
            output_data: None,
            output_data_filter_mode: None,
            output_data_len_range: None,
            output_capacity_range: None,
            block_range: None,
        }),
        with_data: None,
        group_by_transaction: None,
    };

    match qp_client.get_cells_capacity(search_key)? {
        Some(capacity) => Ok(capacity.capacity.value()),
        None => Ok(0),
    }
}
