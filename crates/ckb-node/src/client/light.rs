//! Light client — wraps `ckb_sdk::LightClientRpcClient`.
//!
//! Adds light-client-specific operations: `set_scripts` filter
//! registration, `fetch_transaction` (pull a tx + its committing block
//! header into the LC's local store), and the QPV2-specific
//! `register_lock_scripts` flows that wrap them.
//!
//! Several `Client` trait methods need bespoke logic here because the
//! upstream LC's response types have private fields that prevent
//! direct field access — those methods round-trip through serde_json
//! to reach the data.

use std::any::Any;

use ckb_jsonrpc_types::{JsonBytes, Uint64};
use ckb_sdk::rpc::ckb_indexer::{
    CellsCapacity, Order, Pagination, ScriptType, SearchKey, SearchKeyFilter, Tx,
};
use ckb_sdk::rpc::ckb_light_client::{
    FetchStatus, LightClientRpcClient, ScriptStatus, SetScriptsCommand,
};
use ckb_sdk::traits::{
    CellCollector, CellQueryOptions, HeaderDepResolver, LightClientCellCollector,
    LightClientHeaderDepResolver, LightClientTransactionDependencyProvider, LiveCell,
    PrimaryScriptType, TransactionDependencyProvider, ValueRangeOption,
};
use ckb_types::prelude::*;
use ckb_types::H256;

use crate::config::NetworkType;
use crate::error::NodeManagerError;

use super::{TransactionStatus, UnifiedClient};

pub(crate) struct LightClient {
    client: LightClientRpcClient,
    rpc_url: String,
}

impl LightClient {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: super::timed_light_rpc_client(rpc_url),
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Registers lock/type scripts with the light client so it indexes
    /// matching cells. Internal helper for the `register_*` methods —
    /// not part of the public LightClient surface.
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<(), NodeManagerError> {
        self.client
            .set_scripts(scripts, command)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    /// Returns the list of scripts currently being tracked by the light client.
    pub fn get_scripts(&self) -> Result<Vec<ScriptStatus>, NodeManagerError> {
        self.client
            .get_scripts()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    /// Asks the light client to pull `tx_hash` (and its committing block
    /// header) into its local store. Returns `true` only when the tx is
    /// already in the store (`FetchStatus::Fetched`); any other status
    /// (`Added`, `Fetching`, `NotFound`) returns `false` — the caller
    /// shouldn't proceed with operations that depend on the tx.
    ///
    /// Idempotent: cached lookups return immediately without a network
    /// hit (verified in `vendor/ckb-light-client/.../rpc.rs:868`).
    pub fn fetch_transaction(&self, tx_hash: H256) -> Result<bool, NodeManagerError> {
        match self.client.fetch_transaction(tx_hash) {
            Ok(FetchStatus::Fetched { .. }) => Ok(true),
            Ok(_) => Ok(false),
            Err(e) => Err(NodeManagerError::RpcError(e.to_string())),
        }
    }

    /// Registers one or more QuantumPurse lock scripts with the light
    /// client so it indexes matching cells. Each entry is a
    /// `(lock_args_hex, start_block)` pair. Submits all in one
    /// `set_scripts(Partial)` call.
    ///
    /// Filters against `get_scripts` first so already-tracked scripts
    /// are skipped — their existing sync cursors stay put. This is the
    /// safe path used by the auto-flow (account creation, network
    /// switch). For deliberate cursor reset (manual UI) use
    /// [`Self::register_all_lock_scripts`].
    ///
    /// Why filter
    /// ----------
    /// `set_scripts(Partial)` overwrites the stored block_number for
    /// any script that's already registered (upstream LC's
    /// `update_filter_scripts` always `put`s the new value, never
    /// merges). LC data dirs are per-network and persistent, so when
    /// the user switches mainnet ↔ testnet the target network's
    /// RocksDB may already contain our scripts with valid sync cursors
    /// from a prior session. Naively re-registering at `tip` would
    /// yank those cursors forward and silently skip any blocks indexed
    /// since the last visit.
    pub fn register_lock_scripts(
        &self,
        scripts: &[(&str, u64)],
        network: NetworkType,
    ) -> Result<(), NodeManagerError> {
        if scripts.is_empty() {
            return Ok(());
        }

        // Set of lock_args bytes the LC already tracks. Only this wallet
        // talks to this LC, so every entry came from us — comparing by
        // lock_args alone is enough. One RPC call (`get_scripts`); the
        // rest is local.
        let existing: std::collections::HashSet<Vec<u8>> = self
            .client
            .get_scripts()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?
            .into_iter()
            .map(|ss| ss.script.args.as_bytes().to_vec())
            .collect();

        // Drop already-tracked entries; only newly-seen scripts go through.
        let filtered: Vec<(&str, u64)> = scripts
            .iter()
            .copied()
            .filter(|(args_hex, _)| {
                let clean = args_hex.strip_prefix("0x").unwrap_or(args_hex);
                match hex::decode(clean) {
                    Ok(bytes) => !existing.contains(&bytes),
                    // Invalid hex: let the helper surface a precise error
                    // when it tries to decode the same value.
                    Err(_) => true,
                }
            })
            .collect();

        let statuses = build_lock_script_statuses(&filtered, network)?;
        if statuses.is_empty() {
            return Ok(());
        }
        self.set_scripts(statuses, Some(SetScriptsCommand::Partial))
    }

    /// Replaces the entire tracked script list with the given set.
    /// An empty list clears all scripts.
    pub fn replace_scripts(&self, scripts: Vec<ScriptStatus>) -> Result<(), NodeManagerError> {
        self.set_scripts(scripts, Some(SetScriptsCommand::All))
    }

    /// Force-applies a `set_scripts(Partial)` call for every entry,
    /// **without** filtering. The user's intent is to deliberately
    /// reset (rewind or advance) the LC's stored sync cursor for these
    /// scripts — typically wired to a manual "set scan from block N"
    /// UI control.
    ///
    /// Same construction logic as [`Self::register_lock_scripts`]; only
    /// the filter is skipped. Empty input is a no-op.
    pub fn register_all_lock_scripts(
        &self,
        scripts: &[(&str, u64)],
        network: NetworkType,
    ) -> Result<(), NodeManagerError> {
        if scripts.is_empty() {
            return Ok(());
        }
        let statuses = build_lock_script_statuses(scripts, network)?;
        self.set_scripts(statuses, Some(SetScriptsCommand::Partial))
    }
}

/// Builds `ScriptStatus`es for a list of `(lock_args_hex, start_block)`
/// pairs against the active network's code_hash/hash_type. Pure
/// construction — no RPC. Shared between `register_lock_scripts` (auto,
/// filtered) and `register_all_lock_scripts` (manual, force).
fn build_lock_script_statuses(
    scripts: &[(&str, u64)],
    network: NetworkType,
) -> Result<Vec<ScriptStatus>, NodeManagerError> {
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

    let script_hash_type = match hash_type_str {
        "type" => ckb_jsonrpc_types::ScriptHashType::Type,
        "data1" => ckb_jsonrpc_types::ScriptHashType::Data1,
        _ => ckb_jsonrpc_types::ScriptHashType::Data,
    };

    let code_hash_clean = code_hash_hex.strip_prefix("0x").unwrap_or(code_hash_hex);
    let mut code_hash_bytes = [0u8; 32];
    let decoded = hex::decode(code_hash_clean)
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid code hash hex: {}", e)))?;
    if decoded.len() != 32 {
        return Err(NodeManagerError::RpcError(format!(
            "Code hash must be 32 bytes, got {}.",
            decoded.len()
        )));
    }
    code_hash_bytes.copy_from_slice(&decoded);

    let mut statuses: Vec<ScriptStatus> = Vec::with_capacity(scripts.len());
    for (lock_args_hex, start_block) in scripts {
        let lock_args_clean = lock_args_hex.strip_prefix("0x").unwrap_or(lock_args_hex);
        let args_bytes = hex::decode(lock_args_clean)
            .map_err(|e| NodeManagerError::RpcError(format!("Invalid lock args hex: {}", e)))?;

        let script = ckb_jsonrpc_types::Script {
            code_hash: H256(code_hash_bytes),
            hash_type: script_hash_type,
            args: JsonBytes::from_bytes(args_bytes.into()),
        };

        statuses.push(ScriptStatus {
            script,
            script_type: ScriptType::Lock,
            block_number: (*start_block).into(),
        });
    }

    Ok(statuses)
}

impl UnifiedClient for LightClient {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_tip_header(&self) -> Result<ckb_jsonrpc_types::HeaderView, NodeManagerError> {
        self.client
            .get_tip_header()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn get_peers(&self) -> Result<Vec<ckb_jsonrpc_types::RemoteNode>, NodeManagerError> {
        let peers = self
            .client
            .get_peers()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;
        Ok(peers
            .into_iter()
            .map(|p| ckb_jsonrpc_types::RemoteNode {
                version: p.version,
                node_id: p.node_id,
                addresses: p
                    .addresses
                    .into_iter()
                    .map(|a| ckb_jsonrpc_types::NodeAddress {
                        address: a.address,
                        score: a.score,
                    })
                    .collect(),
                is_outbound: false,
                connected_duration: p.connected_duration,
                last_ping_duration: None,
                sync_state: None,
                protocols: p
                    .protocols
                    .into_iter()
                    .map(|pr| ckb_jsonrpc_types::RemoteNodeProtocol {
                        id: pr.id,
                        version: pr.version,
                    })
                    .collect(),
            })
            .collect())
    }

    fn get_genesis_block(&self) -> Result<ckb_jsonrpc_types::BlockView, NodeManagerError> {
        self.client.get_genesis_block().map_err(|e| {
            NodeManagerError::RpcError(format!("Failed to fetch genesis block: {}", e))
        })
    }

    fn get_cells_capacity(
        &self,
        search_key: SearchKey,
    ) -> Result<Option<CellsCapacity>, NodeManagerError> {
        // Light client returns CellsCapacity directly (not Option), wrap in Some.
        let capacity = self
            .client
            .get_cells_capacity(search_key)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;
        Ok(Some(capacity))
    }

    fn send_transaction(
        &self,
        tx: ckb_jsonrpc_types::Transaction,
    ) -> Result<H256, NodeManagerError> {
        self.client
            .send_transaction(tx)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn get_transaction(&self, hash: H256) -> Result<Option<TransactionStatus>, NodeManagerError> {
        let resp = self
            .client
            .get_transaction(hash)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;

        // The light client's TransactionWithStatus has private fields.
        // Round-trip through serde_json to extract the data.
        Ok(resp.map(|r| {
            let json_value = serde_json::to_value(&r).unwrap_or_default();
            let transaction = json_value.get("transaction").and_then(|t| {
                serde_json::from_value::<ckb_jsonrpc_types::TransactionView>(t.clone()).ok()
            });
            let status = json_value
                .get("tx_status")
                .and_then(|s| s.get("status"))
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let block_hash = json_value
                .get("tx_status")
                .and_then(|s| s.get("block_hash"))
                .and_then(|h| serde_json::from_value::<H256>(h.clone()).ok());
            TransactionStatus {
                transaction,
                status,
                block_hash,
            }
        }))
    }

    fn get_header(
        &self,
        hash: H256,
    ) -> Result<Option<ckb_jsonrpc_types::HeaderView>, NodeManagerError> {
        self.client
            .get_header(hash)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: u32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>, NodeManagerError> {
        let resp = self
            .client
            .get_transactions(search_key, order, limit.into(), after)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;

        // TODO: Create an issue on CKB SDK.
        // The light client's TxWithCell/TxWithCells have private fields (likely
        // an oversight in ckb-sdk — the indexer equivalents are pub). This forces a
        // JSON round-trip to extract data. Remove this if the SDK makes them public.
        // The light client uses `transaction` (full TransactionView) where the
        // indexer uses `tx_hash` (H256 only). Transform `transaction.hash` → `tx_hash`.
        let mut json_value =
            serde_json::to_value(&resp).map_err(|e| NodeManagerError::RpcError(e.to_string()))?;

        if let Some(objects) = json_value.get_mut("objects").and_then(|v| v.as_array_mut()) {
            for obj in objects.iter_mut() {
                if let Some(map) = obj.as_object_mut() {
                    if let Some(tx_hash) =
                        map.get("transaction").and_then(|t| t.get("hash")).cloned()
                    {
                        map.remove("transaction");
                        map.insert("tx_hash".to_string(), tx_hash);
                    }
                }
            }
        }

        serde_json::from_value(json_value).map_err(|e| {
            NodeManagerError::RpcError(format!(
                "Failed to normalize light client transactions: {}",
                e
            ))
        })
    }

    fn collect_cells(&self, query: &CellQueryOptions) -> Result<Vec<LiveCell>, NodeManagerError> {
        // Translate ckb-sdk's `CellQueryOptions` into a light-client indexer
        // `SearchKey`. Then page through `get_cells` until either the total
        // capacity reaches `query.min_total_capacity` or the indexer runs out.
        //
        // `CellQueryOptions::maturity` and `query.limit` are not honored —
        // neither current call site (spendable, dao_cells) sets them, and
        // light-client indexer responses don't carry the cellbase metadata
        // needed for proper maturity filtering.
        let primary_type = match query.primary_type {
            PrimaryScriptType::Lock => ScriptType::Lock,
            PrimaryScriptType::Type => ScriptType::Type,
        };

        let to_range = |opt: Option<ValueRangeOption>| -> Option<[Uint64; 2]> {
            opt.map(|r| [Uint64::from(r.start), Uint64::from(r.end)])
        };

        let filter = SearchKeyFilter {
            script: query.secondary_script.clone().map(|s| s.into()),
            script_len_range: to_range(query.secondary_script_len_range),
            output_data: None,
            output_data_filter_mode: None,
            output_data_len_range: to_range(query.data_len_range),
            output_capacity_range: to_range(query.capacity_range),
            block_range: to_range(query.block_range),
        };

        let search_key = SearchKey {
            script: query.primary_script.clone().into(),
            script_type: primary_type,
            script_search_mode: None,
            filter: Some(filter),
            with_data: Some(true),
            group_by_transaction: None,
        };

        let page_size: u32 = 100;
        let mut after: Option<JsonBytes> = None;
        let mut collected: Vec<LiveCell> = Vec::new();
        let mut total_capacity: u64 = 0;

        loop {
            let page = self
                .client
                .get_cells(
                    search_key.clone(),
                    Order::Asc,
                    page_size.into(),
                    after.clone(),
                )
                .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;

            if page.objects.is_empty() {
                break;
            }

            for cell in page.objects {
                let output: ckb_types::packed::CellOutput = cell.output.into();
                let output_data = cell.output_data.map(|b| b.into_bytes()).unwrap_or_default();
                let out_point: ckb_types::packed::OutPoint = cell.out_point.into();
                let block_number: u64 = cell.block_number.value();
                let tx_index: u32 = cell.tx_index.value();
                let capacity: u64 = output.capacity().unpack();

                collected.push(LiveCell {
                    output,
                    output_data,
                    out_point,
                    block_number,
                    tx_index,
                });
                total_capacity = total_capacity.saturating_add(capacity);

                if query.min_total_capacity > 0 && total_capacity >= query.min_total_capacity {
                    return Ok(collected);
                }
            }

            if page.last_cursor.is_empty() {
                break;
            }
            after = Some(page.last_cursor);
        }

        Ok(collected)
    }

    fn cell_collector(&self) -> Box<dyn CellCollector> {
        Box::new(LightClientCellCollector::new(&self.rpc_url))
    }

    fn header_dep_resolver(&self) -> Box<dyn HeaderDepResolver> {
        Box::new(LightClientHeaderDepResolver::new(&self.rpc_url))
    }

    fn tx_dep_provider(&self) -> Box<dyn TransactionDependencyProvider> {
        Box::new(LightClientTransactionDependencyProvider::new(&self.rpc_url))
    }

    fn local_node_info(&self) -> Result<ckb_jsonrpc_types::LocalNode, NodeManagerError> {
        // ckb_sdk's light client defines its own LocalNode struct (not
        // ckb_jsonrpc_types::LocalNode), so a serde round-trip is needed.
        let info = self
            .client
            .local_node_info()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;
        let json =
            serde_json::to_value(&info).map_err(|e| NodeManagerError::RpcError(e.to_string()))?;
        serde_json::from_value(json).map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }
}
