//! Full node / public RPC client — wraps `ckb_sdk::CkbRpcClient`.
//!
//! Used for two backends that speak the same wire protocol:
//! - `NodeType::FullNode` — a local `ckb` node we own.
//! - `NodeType::PublicRpc` — a remote endpoint provided by someone else.
//!
//! The wire-level distinction (peer count, etc.) is made by callers
//! that already know which backend they configured; the client itself
//! is identical.

use std::any::Any;

use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::rpc::ckb_indexer::{CellsCapacity, Order, Pagination, ScriptType, SearchKey, Tx};
use ckb_sdk::rpc::{CkbRpcClient, ResponseFormatGetter};
use ckb_sdk::traits::{
    CellCollector, CellQueryOptions, DefaultCellCollector, DefaultHeaderDepResolver,
    DefaultTransactionDependencyProvider, HeaderDepResolver, LiveCell,
    TransactionDependencyProvider,
};
use ckb_types::H256;

use crate::config::NetworkType;
use crate::error::NodeManagerError;

use super::{TransactionStatus, UnifiedClient};

pub struct FullNodeClient {
    client: CkbRpcClient,
    rpc_url: String,
}

impl FullNodeClient {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: super::timed_ckb_rpc_client(rpc_url),
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Builds ckb-sdk's cell collector with [`super::RPC_TIMEOUT`]
    /// applied. `DefaultCellCollector::new` would embed its own untimed
    /// clients — never use it directly.
    fn timed_cell_collector(&self) -> DefaultCellCollector {
        DefaultCellCollector::new_with_timeout(&self.rpc_url, super::RPC_TIMEOUT)
            .expect("ckb rpc url, e.g. \"http://127.0.0.1:8114\"")
    }

    /// Light-client utility: best-effort discovery of the earliest
    /// funding block across a set of QuantumPurse accounts.
    ///
    /// Although this method lives on `FullNodeClient`, its sole purpose is
    /// to support the **light-client backend's** manual "Auto-detect
    /// rescan block" flow. The light client only indexes scripts it has
    /// been told to track — it cannot itself answer "when was account X
    /// first funded?" The wallet therefore constructs an ad-hoc
    /// `FullNodeClient` against a richly-indexed public endpoint, calls
    /// this method, and uses the result to pre-fill the user's
    /// `set_scripts(start_block)` input on the LC.
    ///
    /// For each account, asks the indexer for the earliest tx
    /// (`Order::Asc`, limit 1) involving that lock script and returns
    /// the minimum block number across all accounts. `Ok(None)` when
    /// no account has any indexer history.
    ///
    /// Returns the **raw** earliest block as the indexer reports it.
    /// Callers wiring this into the LC's `set_scripts` MUST account
    /// for the upstream LC's "already-filtered up to and including N"
    /// semantics (subtract 1 — sync resumes at `block_number + 1`, so
    /// passing the raw earliest would skip the very tx we just
    /// discovered).
    pub fn find_earliest_funding_block(
        &self,
        lock_args_list: &[String],
        network: NetworkType,
    ) -> Result<Option<u64>, NodeManagerError> {
        if lock_args_list.is_empty() {
            return Ok(None);
        }

        let (code_hash_hex, hash_type) = match network {
            NetworkType::Mainnet => (
                qpv2_core::constants::CKB_MAINNET_CODE_HASH,
                qpv2_core::constants::CKB_MAINNET_HASH_TYPE,
            ),
            NetworkType::Testnet => (
                qpv2_core::constants::CKB_TESTNET_CODE_HASH,
                qpv2_core::constants::CKB_TESTNET_HASH_TYPE,
            ),
        };
        let script_hash_type: ckb_jsonrpc_types::ScriptHashType = hash_type.into();
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

        let mut earliest: Option<u64> = None;
        for lock_args_hex in lock_args_list {
            let lock_args_clean = lock_args_hex.strip_prefix("0x").unwrap_or(lock_args_hex);
            let args_bytes = hex::decode(lock_args_clean)
                .map_err(|e| NodeManagerError::RpcError(format!("Invalid lock args hex: {}", e)))?;

            let script = ckb_jsonrpc_types::Script {
                code_hash: H256(code_hash_bytes),
                hash_type: script_hash_type,
                args: JsonBytes::from_bytes(args_bytes.into()),
            };
            let search_key = SearchKey {
                script,
                script_type: ScriptType::Lock,
                script_search_mode: None,
                filter: None,
                with_data: None,
                group_by_transaction: None,
            };

            let page = self
                .client
                .get_transactions(search_key, Order::Asc, 1u32.into(), None)
                .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;

            if let Some(first) = page.objects.first() {
                let block_num = match first {
                    Tx::Ungrouped(t) => t.block_number.value(),
                    Tx::Grouped(t) => t.block_number.value(),
                };
                earliest = Some(earliest.map_or(block_num, |e| e.min(block_num)));
            }
        }
        Ok(earliest)
    }

    /// Full node `sync_state` RPC. Reports IBD progress (header sync,
    /// block download, assume-valid-target verification, synced) so the
    /// Node Manager UI can render the active phase. Light clients have
    /// no analogue — their sync is per-script via `get_scripts`.
    pub fn sync_state(&self) -> Result<ckb_jsonrpc_types::SyncState, NodeManagerError> {
        self.client
            .sync_state()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    pub fn get_blockchain_info(&self) -> Result<ckb_jsonrpc_types::ChainInfo, NodeManagerError> {
        self.client
            .get_blockchain_info()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    pub fn tx_pool_info(&self) -> Result<ckb_jsonrpc_types::TxPoolInfo, NodeManagerError> {
        self.client
            .tx_pool_info()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }
}

impl UnifiedClient for FullNodeClient {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_tip_header(&self) -> Result<ckb_jsonrpc_types::HeaderView, NodeManagerError> {
        self.client
            .get_tip_header()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn get_peers(&self) -> Result<Vec<ckb_jsonrpc_types::RemoteNode>, NodeManagerError> {
        self.client
            .get_peers()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn get_genesis_block(&self) -> Result<ckb_jsonrpc_types::BlockView, NodeManagerError> {
        self.client
            .get_block_by_number(0u64.into())
            .map_err(|e| {
                NodeManagerError::RpcError(format!("Failed to fetch genesis block: {}", e))
            })?
            .ok_or_else(|| NodeManagerError::RpcError("Genesis block not found.".to_string()))
    }

    fn get_genesis_hash(&self) -> Result<H256, NodeManagerError> {
        self.client
            .get_block_hash(0u64.into())
            .map_err(|e| {
                NodeManagerError::RpcError(format!("Failed to fetch genesis hash: {}", e))
            })?
            .ok_or_else(|| NodeManagerError::RpcError("Genesis block not found.".to_string()))
    }

    fn get_cells_capacity(
        &self,
        search_key: SearchKey,
    ) -> Result<Option<CellsCapacity>, NodeManagerError> {
        self.client
            .get_cells_capacity(search_key)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn send_transaction(
        &self,
        tx: ckb_jsonrpc_types::Transaction,
    ) -> Result<H256, NodeManagerError> {
        self.client
            .send_transaction(tx, None)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn get_transaction(&self, hash: H256) -> Result<Option<TransactionStatus>, NodeManagerError> {
        let resp = self
            .client
            .get_transaction(hash)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;

        Ok(resp.map(|r| TransactionStatus {
            transaction: r.transaction.and_then(|inner| inner.get_value().ok()),
            status: format!("{:?}", r.tx_status.status),
            block_hash: r.tx_status.block_hash,
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
        self.client
            .get_transactions(search_key, order, limit.into(), after)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }

    fn collect_cells(&self, query: &CellQueryOptions) -> Result<Vec<LiveCell>, NodeManagerError> {
        let mut collector = self.timed_cell_collector();
        let (cells, _) = collector
            .collect_live_cells(query, false)
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))?;
        Ok(cells)
    }

    fn cell_collector(&self) -> Box<dyn CellCollector> {
        Box::new(self.timed_cell_collector())
    }

    fn header_dep_resolver(&self) -> Box<dyn HeaderDepResolver> {
        // Upstream has no timeout constructor for this type; its only
        // field is public, so inject the timed client directly.
        Box::new(DefaultHeaderDepResolver {
            ckb_client: super::timed_ckb_async_rpc_client(&self.rpc_url),
        })
    }

    fn tx_dep_provider(&self) -> Box<dyn TransactionDependencyProvider> {
        // Upstream has no timeout constructor for this type and its
        // inner state is private, so swap the public `rpc_client` for a
        // timed one after construction. `blocking_lock` is safe here —
        // wallet code calls this from plain threads, never from inside
        // an async runtime.
        let provider = DefaultTransactionDependencyProvider::new(&self.rpc_url, 10);
        provider.inner.blocking_lock().rpc_client =
            super::timed_ckb_async_rpc_client(&self.rpc_url);
        Box::new(provider)
    }

    fn local_node_info(&self) -> Result<ckb_jsonrpc_types::LocalNode, NodeManagerError> {
        self.client
            .local_node_info()
            .map_err(|e| NodeManagerError::RpcError(e.to_string()))
    }
}
