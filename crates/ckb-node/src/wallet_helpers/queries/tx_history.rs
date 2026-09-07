//! Transaction history queries for QuantumPurse lock scripts.

use crate::client::QpClient;
use crate::error::NodeManagerError;
use crate::wallet_helpers::utils::build_qr_lock_script;
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchKeyFilter, Tx};

/// Queries all transactions for a Quantum Resistant lock script via the indexer.
///
/// Paginates through the full result set using `last_cursor`. Returns grouped
/// `Tx` entries in descending order (newest first), one per unique transaction.
pub fn fetch_recent_transactions(
    qp_client: &QpClient,
    lock_args_hex: &str,
    after_block: Option<u64>,
    limit: Option<usize>,
) -> Result<Vec<Tx>, NodeManagerError> {
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
            block_range: after_block.map(|b| {
                [
                    ckb_jsonrpc_types::Uint64::from(b + 1),
                    ckb_jsonrpc_types::Uint64::from(u64::MAX),
                ]
            }),
        }),
        with_data: None,
        group_by_transaction: Some(true),
    };

    // Paginate through results (newest first).
    let page_size = 100;
    let mut all_txs = Vec::new();
    let mut cursor: Option<JsonBytes> = None;

    loop {
        let page =
            qp_client.get_transactions(search_key.clone(), Order::Desc, page_size, cursor)?;
        let is_last = page.objects.len() < page_size as usize;
        all_txs.extend(page.objects);

        if let Some(max) = limit {
            if all_txs.len() >= max {
                all_txs.truncate(max);
                break;
            }
        }

        if is_last {
            break;
        }
        cursor = Some(page.last_cursor);
    }

    Ok(all_txs)
}
