//! Background data fetchers (balances, DAO cells, spendable capacity, tx history).

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::sync::mpsc;
use std::time::Duration;

use crate::types::{DaoQueryEvent, NodeStatus, NodeStatusUpdate, TxHistoryEvent, TxKind, TxRecord};
use crate::App;

/// Initial backoff between retry attempts on a transient RPC failure.
const RETRY_BASE_DELAY: Duration = Duration::from_millis(500);
/// Cap on the exponential backoff.
const RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Retries `f` forever with exponential backoff (capped at
/// `RETRY_MAX_DELAY`) until it returns `Ok(Some(v))`. Both `Err(_)` and
/// `Ok(None)` are treated as "try again" and logged distinctly.
///
/// Callers that can never produce a legitimate `None` (e.g. the indexer
/// returning `Vec<Tx>`) adapt with `.map(Some)`. Callers that do
/// (`get_transaction`, `get_header`) pass their `Result<Option<T>, _>`
/// through unchanged.
///
/// Used by the tx-history sync thread so a transient public-RPC failure
/// never drops a tx silently. See `BACKLOG.md` ("Reorg handling") for the
/// cancellation story once reorg-aware sync lands.
fn retry_until_ready<T, E: Display>(tag: &str, mut f: impl FnMut() -> Result<Option<T>, E>) -> T {
    let mut delay = RETRY_BASE_DELAY;
    loop {
        match f() {
            Ok(Some(v)) => return v,
            Ok(None) => {
                tracing::warn!("tx history: {} returned None, retrying in {:?}", tag, delay);
            }
            Err(e) => {
                tracing::warn!(
                    "tx history: {} failed ({}), retrying in {:?}",
                    tag,
                    e,
                    delay
                );
            }
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(RETRY_MAX_DELAY);
    }
}

/// Parses the port out of an RPC URL (`http://host:port` or
/// `https://host:port`). Returns `None` on malformed input or when
/// the URL has no explicit port (we deliberately don't fall back to
/// scheme defaults — those would be hardcoded protocol artifacts,
/// not data from the endpoint).
fn parse_rpc_port(url: &str) -> Option<u16> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    let (_, port) = host_port.rsplit_once(':')?;
    port.parse().ok()
}

impl App {
    /// Kick off background queries for deposited + prepared DAO cells across all accounts.
    pub(crate) fn fetch_dao_cells(&mut self) {
        if self.accounts.is_empty() || self.dao_cells_query_rx.is_some() {
            return;
        }

        self.dao_deposited_staging.clear();
        self.dao_prepared_staging.clear();

        let is_mainnet = self.qp_client.is_mainnet();
        let qp_client = self.qp_client.clone();
        let all_lock_args: Vec<String> =
            self.accounts.iter().map(|a| a.lock_args.clone()).collect();

        let (tx, rx) = mpsc::channel();
        self.dao_cells_query_rx = Some(rx);

        std::thread::spawn(move || {
            let mut all_ok = true;

            for lock_args in &all_lock_args {
                let address = match crate::utils::lock_args_to_address(lock_args, is_mainnet) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx.send(Err(format!("Invalid address: {}", e)));
                        all_ok = false;
                        continue;
                    }
                };

                let (deposited, prepared) =
                    match ckb_node::wallet_helpers::queries::categorize_dao_cells(
                        &qp_client, &address,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = format!("Failed to query DAO cells: {}", e);
                            if e.to_string().contains("http error") {
                                tracing::error!("{}", msg);
                            } else {
                                let _ = tx.send(Err(msg));
                            }
                            all_ok = false;
                            continue;
                        }
                    };

                for cell in deposited {
                    if tx
                        .send(Ok(DaoQueryEvent::Deposited(lock_args.clone(), cell)))
                        .is_err()
                    {
                        return;
                    }
                }

                for cell in prepared {
                    if tx
                        .send(Ok(DaoQueryEvent::Prepared(lock_args.clone(), cell)))
                        .is_err()
                    {
                        return;
                    }
                }
            }

            // Only commit the refresh when every account succeeded.
            // Any failure means the staging buffer is incomplete — keep
            // the previous display data instead of swapping in a partial set.
            if all_ok {
                let _ = tx.send(Ok(DaoQueryEvent::Done));
            }
        });
    }

    /// Fetch deposit block headers that aren't cached yet.
    /// Skips if a fetch is already in flight or all headers are cached.
    // TODO: we are using remote RPC for convenient because get_header_by_number
    // is not supported by light client - thus the surface IF of ckb-node doesn't work.
    pub(crate) fn fetch_deposit_headers(&mut self) {
        if self.deposit_headers_rx.is_some() {
            return;
        }

        let missing: Vec<u64> = self
            .dao_deposited_cells
            .iter()
            .map(|(_, c)| c.block_number)
            .filter(|bn| !self.deposit_headers.contains_key(bn))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if missing.is_empty() {
            return;
        }

        let network = self.qp_client.network();
        let (tx, rx) = std::sync::mpsc::channel();
        self.deposit_headers_rx = Some(rx);

        std::thread::spawn(move || {
            let public_rpc_url =
                ckb_node::NodeConfig::default_rpc_url_for(ckb_node::NodeType::PublicRpc, network);
            let rpc = ckb_sdk::CkbRpcClient::new(public_rpc_url);

            let mut result = HashMap::new();
            for block_number in missing {
                match rpc.get_header_by_number(block_number.into()) {
                    Ok(Some(h)) => {
                        let core_header: ckb_types::core::HeaderView = h.into();
                        result.insert(block_number, core_header);
                    }
                    Ok(None) => {
                        tracing::warn!("Deposit header not found (block #{})", block_number);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to fetch deposit header (block #{}): {}",
                            block_number,
                            e
                        );
                    }
                }
            }
            let _ = tx.send(result);
        });
    }

    /// Fetch recent transaction history for all accounts in a background thread.
    ///
    /// When `incremental` is false (cold start), clears existing records and fetches. When true,
    /// only fetches transactions newer than the highest confirmed block already in the list.
    pub(crate) fn fetch_tx_history(&mut self, incremental: bool) {
        if self.accounts.is_empty() || self.tx_history_rx.is_some() {
            return;
        }

        // Incremental mode uses the current watermark (derived from
        // `tx_history`). A cold fetch clears memory so everything is
        // re-materialized from block 0.
        let after_block = if incremental {
            Some(self.tx_history_watermark())
        } else {
            self.tx_history.clear();
            None
        };

        let qp_client = self.qp_client.clone();
        let all_lock_args: Vec<String> =
            self.accounts.iter().map(|a| a.lock_args.clone()).collect();

        let (sender, rx) = mpsc::channel();
        self.tx_history_rx = Some(rx);

        std::thread::spawn(move || {
            // DAO type script code hash for classification.
            let dao_type_hash = format!("{:#x}", ckb_sdk::constants::DAO_TYPE_HASH);

            // Wallet lock script code hash for filtering outputs that belong to us.
            let wallet_code_hash = match qp_client.network() {
                ckb_node::NetworkType::Mainnet => qpv2_core::constants::CKB_MAINNET_CODE_HASH,
                ckb_node::NetworkType::Testnet => qpv2_core::constants::CKB_TESTNET_CODE_HASH,
            };
            let all_lock_args_set: HashSet<&str> =
                all_lock_args.iter().map(|s| s.as_str()).collect();

            // Extract the lock_args hex from an output if it matches the
            // wallet's code hash. Returns None for external outputs.
            fn wallet_lock_args(
                out: &ckb_jsonrpc_types::CellOutput,
                code_hash: &str,
                args_set: &HashSet<&str>,
            ) -> Option<String> {
                let ch = format!("{:#x}", out.lock.code_hash);
                if ch != code_hash {
                    return None;
                }
                let args_hex = hex::encode(out.lock.args.as_bytes());
                if args_set.contains(args_hex.as_str()) {
                    Some(args_hex)
                } else {
                    None
                }
            }

            // Collect all tx entries across accounts, grouped by tx_hash.
            // Per-account IO tracking: which accounts have inputs/outputs in each tx.
            struct TxInfo {
                block_number: u64,
                input_accounts: HashSet<String>,
                output_accounts: HashSet<String>,
                /// First account to encounter this tx (used as primary owner).
                owner_lock_args: String,
            }
            let mut seen: HashMap<String, TxInfo> = HashMap::new();

            for lock_args in &all_lock_args {
                // With group_by_transaction=true, each result is one unique tx.
                // Paginates through all results; merged and deduped across accounts.
                // Retries transient indexer failures — we must never skip an
                // account silently because a dropped page becomes a permanently
                // missing tx once the watermark advances.
                let txs = retry_until_ready(
                    &format!(
                        "fetch_recent_transactions | lock_args=0x{} | after_block={}",
                        lock_args,
                        after_block.map_or("none".to_string(), |b| b.to_string())
                    ),
                    || {
                        ckb_node::wallet_helpers::queries::fetch_recent_transactions(
                            &qp_client,
                            lock_args,
                            after_block,
                            None,
                        )
                        .map(Some)
                    },
                );

                for tx_entry in txs {
                    let tx_hash = format!("{:#x}", tx_entry.tx_hash());
                    let info = seen.entry(tx_hash).or_insert_with(|| TxInfo {
                        block_number: 0,
                        input_accounts: HashSet::new(),
                        output_accounts: HashSet::new(),
                        owner_lock_args: lock_args.clone(),
                    });

                    let mut record_io = |cell_type: &ckb_node::CellType| match cell_type {
                        ckb_node::CellType::Input => {
                            info.input_accounts.insert(lock_args.clone());
                        }
                        ckb_node::CellType::Output => {
                            info.output_accounts.insert(lock_args.clone());
                        }
                    };

                    match tx_entry {
                        ckb_node::Tx::Grouped(ref grouped) => {
                            info.block_number = grouped.block_number.value();
                            for (cell_type, _idx) in &grouped.cells {
                                record_io(cell_type);
                            }
                        }
                        ckb_node::Tx::Ungrouped(ref cell) => {
                            info.block_number = cell.block_number.value();
                            record_io(&cell.io_type);
                        }
                    }
                }
            }

            // Cache block headers to avoid redundant RPC calls.
            let mut header_cache: HashMap<ckb_types::H256, u64> = HashMap::new();

            // Process each unique transaction, sorted newest first.
            let mut tx_list: Vec<(String, TxInfo)> = seen.into_iter().collect();
            tx_list.sort_by_key(|item| Reverse(item.1.block_number));

            for (tx_hash_str, tx_info) in tx_list {
                let block_number = tx_info.block_number;
                let owner_lock_args = tx_info.owner_lock_args;
                // Use the owner's specific IO role, not a global merge.
                let has_input = tx_info.input_accounts.contains(&owner_lock_args);
                let has_output = tx_info.output_accounts.contains(&owner_lock_args);

                // For incoming internal transfers: the sender is a different
                // wallet account found in the input side.
                let sender_account: Option<String> = tx_info
                    .input_accounts
                    .iter()
                    .find(|a| a.as_str() != owner_lock_args)
                    .cloned();
                let tx_hash_clean = tx_hash_str.strip_prefix("0x").unwrap_or(&tx_hash_str);
                let tx_hash_bytes = match hex::decode(tx_hash_clean) {
                    Ok(b) if b.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        ckb_types::H256(arr)
                    }
                    _ => continue,
                };

                // Retry until we get a concrete tx_status. The indexer
                // just handed us this hash; `Ok(None)` means the node hasn't
                // caught up to its own indexer or is briefly unhappy — retry.
                let tx_hash_key = tx_hash_bytes.clone();
                let tx_status = retry_until_ready(
                    &format!("get_transaction tx_hash={:#x}", tx_hash_key),
                    || qp_client.get_transaction(tx_hash_bytes.clone()),
                );

                let is_pending = tx_status.status != "Committed" && tx_status.status != "committed";

                // A committed tx must have a transaction view. If it's missing
                // we want to retry rather than drop — so re-poll until it lands.
                // (For pending txs this is valid too: they should at least be
                // returned by the node.)
                let tx_view = match tx_status.transaction {
                    Some(tv) => tv,
                    None => retry_until_ready(
                        &format!("get_transaction.tx_view tx_hash={:#x}", tx_hash_key),
                        || {
                            qp_client
                                .get_transaction(tx_hash_bytes.clone())
                                .map(|opt| opt.and_then(|s| s.transaction))
                        },
                    ),
                };

                // Determine timestamp from block header. Retry until the
                // header resolves — we need a stable timestamp to avoid
                // rewriting the stored record on the next tick.
                let timestamp = if let Some(ref bh) = tx_status.block_hash {
                    if let Some(&cached) = header_cache.get(bh) {
                        cached
                    } else {
                        let bh_clone = bh.clone();
                        let header = retry_until_ready(
                            &format!("get_header block_hash={:#x}", bh_clone),
                            || qp_client.get_header(bh_clone.clone()),
                        );
                        // CKB header timestamp is in milliseconds.
                        let ts = header.inner.timestamp.value() / 1000;
                        header_cache.insert(bh.clone(), ts);
                        ts
                    }
                } else {
                    0
                };

                // Check for DAO type script in outputs.
                let has_dao_output = tx_view.inner.outputs.iter().any(|out| {
                    out.type_
                        .as_ref()
                        .is_some_and(|t| format!("{:#x}", t.code_hash) == dao_type_hash)
                });

                // Check DAO data to distinguish deposit vs prepare.
                let dao_output_data_is_zero = tx_view
                    .inner
                    .outputs
                    .iter()
                    .zip(tx_view.inner.outputs_data.iter())
                    .any(|(out, data)| {
                        out.type_
                            .as_ref()
                            .is_some_and(|t| format!("{:#x}", t.code_hash) == dao_type_hash)
                            && data.len() == 8
                            && data.as_bytes().iter().all(|&b| b == 0)
                    });

                // Classify the transaction.
                // DAO withdraw: has a DAO cell dep but no DAO type script in outputs
                // (the DAO cell is consumed, capacity returned to regular lock).
                let has_dao_cell_dep = tx_view.inner.cell_deps.iter().any(|dep| {
                    // The DAO cell dep is always at genesis tx index 2.
                    dep.out_point.index.value() == 2
                });

                let tx_kind = if has_dao_output && dao_output_data_is_zero {
                    TxKind::DaoDeposit
                } else if has_dao_output {
                    TxKind::DaoPrepare
                } else if has_dao_cell_dep && has_input && !has_dao_output {
                    TxKind::DaoWithdraw
                } else if has_output && !has_input {
                    TxKind::Incoming
                } else {
                    TxKind::Outgoing
                };

                // Classify each output: owner's capacity (incl. change), other
                // wallet accounts' capacity, and external capacity.
                let mut owner_capacity: u64 = 0;
                let mut internal_counterparty: Option<String> = None;
                let mut internal_capacity: u64 = 0;
                let mut external_capacity: u64 = 0;
                let mut external_recipient: Option<String> = None;

                for out in &tx_view.inner.outputs {
                    let cap = out.capacity.value();
                    match wallet_lock_args(out, wallet_code_hash, &all_lock_args_set) {
                        Some(args) if args == owner_lock_args => {
                            owner_capacity += cap;
                        }
                        Some(args) => {
                            // Output goes to a different wallet account.
                            internal_counterparty = Some(args);
                            internal_capacity += cap;
                        }
                        None => {
                            external_capacity += cap;
                            // Skip DAO type outputs — those belong to DAO flow,
                            // not a user-facing recipient address.
                            let is_dao_output = out
                                .type_
                                .as_ref()
                                .is_some_and(|t| format!("{:#x}", t.code_hash) == dao_type_hash);
                            if external_recipient.is_none() && !is_dao_output {
                                let packed: ckb_types::packed::Script = out.lock.clone().into();
                                let is_mainnet =
                                    matches!(qp_client.network(), ckb_node::NetworkType::Mainnet);
                                external_recipient =
                                    Some(crate::utils::script_to_address(&packed, is_mainnet));
                            }
                        }
                    }
                }

                let amount = match tx_kind {
                    TxKind::Incoming => owner_capacity,
                    TxKind::Outgoing => {
                        // Prefer external send amount; for internal transfers
                        // use the amount sent to the other wallet account.
                        if external_capacity > 0 {
                            external_capacity
                        } else {
                            internal_capacity
                        }
                    }
                    TxKind::DaoDeposit | TxKind::DaoPrepare => {
                        // Use the DAO cell's capacity for deposit/prepare.
                        tx_view
                            .inner
                            .outputs
                            .iter()
                            .find(|out| {
                                out.type_
                                    .as_ref()
                                    .is_some_and(|t| format!("{:#x}", t.code_hash) == dao_type_hash)
                            })
                            .map(|out| out.capacity.value())
                            .unwrap_or(owner_capacity)
                    }
                    TxKind::DaoWithdraw => owner_capacity,
                };

                // For outgoing: counterparty is the recipient (from outputs).
                // For incoming: counterparty is the sender (from input accounts).
                let internal_counterparty_lock_args = match tx_kind {
                    TxKind::Incoming => sender_account,
                    _ => internal_counterparty,
                };

                let external_recipient_address = match tx_kind {
                    TxKind::Outgoing => external_recipient,
                    _ => None,
                };

                let record = TxRecord {
                    tx_hash: tx_hash_str,
                    tx_kind,
                    amount,
                    block_number,
                    timestamp,
                    is_pending,
                    owner_lock_args,
                    internal_counterparty_lock_args,
                    external_recipient_address,
                };

                if sender.send(Ok(TxHistoryEvent::Record(record))).is_err() {
                    return;
                }
            }

            let _ = sender.send(Ok(TxHistoryEvent::Done));
        });
    }

    /// Fetch balances for all accounts in a background thread.
    pub(crate) fn fetch_all_balances(&mut self) {
        if self.balance_receiver.is_some() {
            return;
        }

        let lock_args_list: Vec<String> =
            self.accounts.iter().map(|a| a.lock_args.clone()).collect();
        if lock_args_list.is_empty() {
            return;
        }

        for lock_args in &lock_args_list {
            self.balances.entry(lock_args.clone()).or_insert(None);
            self.spendable_balances
                .entry(lock_args.clone())
                .or_insert(None);
        }

        let qp_client = self.qp_client.clone();
        let is_mainnet = self.qp_client.is_mainnet();
        let (tx, rx) = mpsc::channel();
        self.balance_receiver = Some(rx);

        std::thread::spawn(move || {
            for lock_args in lock_args_list {
                let total = ckb_node::wallet_helpers::queries::fetch_quantum_lock_balance(
                    &qp_client, &lock_args,
                )
                .map_err(|e| e.to_string());

                // Independent RPC call: keep its error distinct from `total` so a
                // transient failure here doesn't get masked as a real zero balance.
                let spendable = (|| -> Result<u64, String> {
                    let address = crate::utils::lock_args_to_address(&lock_args, is_mainnet)?;
                    ckb_node::wallet_helpers::queries::spendable_capacity(&qp_client, &address)
                        .map_err(|e| e.to_string())
                })();

                // If the receiver is dropped (e.g. wallet locked), stop.
                if tx.send((lock_args, total, spendable)).is_err() {
                    break;
                }
            }
        });
    }

    /// Refresh the Node Manager card's cached status in a background
    /// thread. One in-flight poll at a time (`node_status_rx` guards).
    ///
    /// Each field falls back to the previous reading on RPC error so
    /// transient failures (RPC server warming up after a backend
    /// switch, brief network blip) don't wipe the displayed values to
    /// "—" only to repopulate on the next tick. The `Result<Option<T>, _>`
    /// returned by each `qp_client` method is matched here at the
    /// boundary, before `.ok().flatten()` would collapse "RPC errored"
    /// and "legitimately empty" into the same `None` — preserving that
    /// distinction is what lets the merge be honest:
    ///
    /// - `Ok(Some(v))` / `Ok(None)` → trust the RPC's answer.
    /// - `Err(_)` → keep the last-known value.
    ///
    /// `online` reflects *this poll's* reachability via `get_tip_header`,
    /// so the status pill flips correctly during a blip even though the
    /// metric tiles hold their values.
    pub(crate) fn fetch_node_status(&mut self) {
        if self.node_status_rx.is_some() {
            return;
        }

        let cfg = self.qp_client.config();
        let rpc_port = parse_rpc_port(&cfg.rpc_url);
        let qp_client = self.qp_client.clone();
        let cached = self.node_status.clone();
        let network = self.qp_client.network();

        let (tx, rx) = mpsc::channel();
        self.node_status_rx = Some(rx);

        std::thread::spawn(move || {
            // Tip header — drives the `online` flag. The flag tracks
            // *this poll's* reachability, but the displayed `tip_block`
            // falls back to cached so transient errors don't flicker.
            let tip_result = qp_client.get_tip_header();
            let online = tip_result.is_ok();
            let tip_header: Option<ckb_types::core::HeaderView> = match tip_result {
                Ok(h) => Some(h.into()),
                Err(_) => cached.tip_header.clone(),
            };

            let peers = match qp_client.get_peers() {
                Ok(p) => p,
                Err(_) => cached.peers,
            };

            // Synced block — `Ok(None)` when LC has no scripts
            // registered (legit) or on non-LC backends.
            let synced_block = match qp_client.synced_block() {
                Ok(v) => v,
                Err(_) => cached.synced_block,
            };

            let tracked_scripts = match qp_client.tracked_scripts() {
                Ok(v) => v,
                Err(_) => cached.tracked_scripts,
            };

            // Sync state — `Ok(None)` outside FullNode (legit).
            let sync_state = match qp_client.sync_state() {
                Ok(v) => v,
                Err(_) => cached.sync_state,
            };

            let blockchain_info = match qp_client.blockchain_info() {
                Ok(Some(v)) => Some(std::sync::Arc::new(v)),
                Ok(None) => None,
                Err(_) => cached.blockchain_info,
            };

            let tx_pool_info = match qp_client.tx_pool_info() {
                Ok(v) => v,
                Err(_) => cached.tx_pool_info,
            };

            let local_node_info = match qp_client.local_node_info() {
                Ok(v) => Some(v),
                Err(_) => cached.local_node_info,
            };

            // Fetch a header ~7 days ago for APC calculation (same window as NervDAO).
            // Uses the public RPC so this works regardless of the active backend.
            // TODO: we are using remote RPC for convenient because get_header_by_number
            // is not supported by light client - thus the surface IF of ckb-node doesn't work.
            const APC_BLOCK_WINDOW: u64 = 75_600;
            let apc_baseline_header = tip_header
                .as_ref()
                .and_then(|tip| {
                    let target = tip.number().saturating_sub(APC_BLOCK_WINDOW);
                    if target == 0 {
                        return None;
                    }
                    let public_rpc_url = ckb_node::NodeConfig::default_rpc_url_for(
                        ckb_node::NodeType::PublicRpc,
                        network,
                    );
                    let rpc = ckb_sdk::CkbRpcClient::new(public_rpc_url);
                    match rpc.get_header_by_number(target.into()) {
                        Ok(Some(h)) => Some(h.into()),
                        Ok(None) => {
                            tracing::warn!("APC baseline header not found (block #{})", target);
                            None
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to fetch APC baseline header (block #{}): {}",
                                target,
                                e
                            );
                            None
                        }
                    }
                })
                .or(cached.apc_baseline_header);

            let status = NodeStatus {
                apc_baseline_header,
                tip_header,
                peers,
                rpc_port,
                synced_block,
                tracked_scripts,
                sync_state,
                blockchain_info,
                tx_pool_info,
                local_node_info,
                online,
            };
            let _ = tx.send(Ok(status) as NodeStatusUpdate);
        });
    }

    /// Kick off a rebuild of the QR-lock adoption series in a
    /// background thread; the chain query lives in ckb-node. Schedules
    /// the next attempt up front — `poll_qr_adoption` shortens the
    /// schedule when this one fails.
    pub(crate) fn fetch_qr_adoption(&mut self) {
        if self.qr_adoption_rx.is_some() {
            return;
        }
        /// ~3 months of weekly points.
        const WEEKS: u64 = 13;
        self.qr_adoption_next_fetch = Some(std::time::Instant::now() + crate::QR_ADOPTION_INTERVAL);
        let network = self.qp_client.network();

        let (tx, rx) = mpsc::channel();
        self.qr_adoption_rx = Some(rx);
        std::thread::spawn(move || {
            let result =
                ckb_node::wallet_helpers::queries::fetch_qr_adoption_series(network, WEEKS)
                    .map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }
}
