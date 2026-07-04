//! Network-wide adoption series for the Quantum Resistant lock script.

use crate::config::{NetworkType, NodeConfig, NodeType};
use crate::error::NodeManagerError;
use crate::wallet_helpers::utils::build_qr_lock_script;
use ckb_sdk::rpc::ckb_indexer::{Order, ScriptType, SearchKey};

/// Builds the adoption series for the Quantum Resistant lock script:
/// cumulative capacity of currently-live cells bucketed by creation
/// week over the last `weeks` weeks, ending at the live total. Always
/// queries the network's public RPC full node — light clients only
/// index their registered scripts and cannot answer a network-wide
/// question.
///
/// A cell that is live now was live at every instant since its
/// creation, so bucketing live cells by creation block yields each
/// week's locked total exactly — except that cells spent since then
/// vanish from all buckets. The curve is therefore "surviving capacity
/// by age", a slight under-statement of true historical TVL.
///
/// Block-to-time mapping uses the average block interval measured over
/// a recent 100k-block window — accurate to well under a day at the
/// weekly granularity drawn from it.
///
/// Errors rather than under-reports when the live-cell scan would be
/// truncated by the page cap.
pub fn fetch_qr_adoption_series(
    network: NetworkType,
    weeks: u64,
) -> Result<Vec<(u64, u64)>, NodeManagerError> {
    const WEEK_MS: u64 = 7 * 24 * 3_600 * 1_000;
    const PAGE: u32 = 500;
    const MAX_PAGES: usize = 200;
    /// Lookback for measuring the average block interval.
    const INTERVAL_WINDOW: u64 = 100_000;

    let url = NodeConfig::default_rpc_url_for(NodeType::PublicRpc, network);
    let rpc = crate::client::timed_ckb_rpc_client(url);

    let tip = rpc
        .get_tip_header()
        .map_err(|e| NodeManagerError::RpcError(format!("tip: {}", e)))?;
    let tip_num = tip.inner.number.value();
    let tip_ts = tip.inner.timestamp.value();

    let span = INTERVAL_WINDOW.min(tip_num.saturating_sub(1));
    if span == 0 {
        return Err(NodeManagerError::RpcError("chain too short".to_string()));
    }
    let past = rpc
        .get_header_by_number((tip_num - span).into())
        .map_err(|e| NodeManagerError::RpcError(format!("ref header: {}", e)))?
        .ok_or_else(|| NodeManagerError::RpcError("reference header missing".to_string()))?;
    let avg_ms = (tip_ts.saturating_sub(past.inner.timestamp.value())) as f64 / span as f64;
    if avg_ms <= 0.0 {
        return Err(NodeManagerError::RpcError(
            "degenerate block interval".to_string(),
        ));
    }

    // Page every live cell under the QR lock, keeping (creation_block,
    // capacity).
    let script = build_qr_lock_script(network, "")?;
    let mut cells: Vec<(u64, u64)> = Vec::new();
    let mut cursor: Option<ckb_jsonrpc_types::JsonBytes> = None;
    let mut complete = false;
    for _ in 0..MAX_PAGES {
        let search_key = SearchKey {
            script: script.clone(),
            script_type: ScriptType::Lock,
            script_search_mode: None, // defaults to prefix
            filter: None,
            with_data: Some(false),
            group_by_transaction: None,
        };
        let result = rpc
            .get_cells(search_key, Order::Asc, PAGE.into(), cursor)
            .map_err(|e| NodeManagerError::RpcError(format!("get_cells: {}", e)))?;
        let n = result.objects.len();
        for cell in result.objects {
            cells.push((cell.block_number.value(), cell.output.capacity.value()));
        }
        cursor = Some(result.last_cursor);
        if n < PAGE as usize {
            complete = true;
            break;
        }
    }
    if !complete {
        // Refuse to present a truncated scan as the authoritative
        // total — an under-reported TVL displayed (and cached) as fact
        // is worse than no update.
        return Err(NodeManagerError::RpcError(format!(
            "live-cell scan truncated at {} cells; raise the page cap",
            cells.len()
        )));
    }
    cells.sort_unstable_by_key(|&(block, _)| block);

    // Cumulative capacity at each weekly boundary, oldest first; the
    // final boundary is the tip itself, i.e. the live total.
    let mut series = Vec::with_capacity(weeks as usize + 1);
    let mut idx = 0;
    let mut cum: u64 = 0;
    for k in (0..=weeks).rev() {
        let boundary_ms = tip_ts.saturating_sub(k * WEEK_MS);
        let boundary_block = tip_num.saturating_sub(((k * WEEK_MS) as f64 / avg_ms) as u64);
        while idx < cells.len() && cells[idx].0 <= boundary_block {
            cum = cum.saturating_add(cells[idx].1);
            idx += 1;
        }
        series.push((boundary_ms / 1000, cum));
    }
    Ok(series)
}
