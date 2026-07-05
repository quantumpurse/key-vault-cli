//! Everything the wallet uses to talk to a CKB node.
//!
//! Contents, bottom layer first:
//!
//! - [`RPC_TIMEOUT`] and the `*_rpc_client` constructors — the only
//!   approved way to build an HTTP client in this crate. They exist to
//!   guarantee every RPC call has a timeout; ckb-sdk's own `new`
//!   constructors have none, and an untimed call can block its thread
//!   for as long as a broken node stays silent.
//! - [`UnifiedClient`] — the internal trait listing the node
//!   operations wallet code needs. Each backend implements it in its
//!   own submodule.
//! - [`FullNodeClient`] / [`LightClient`] — the two backend
//!   implementations. They wrap ckb-sdk's RPC clients, normalize the
//!   backends' different return shapes, and add a few backend-specific
//!   methods reachable via `as_any().downcast_ref::<…>()`.
//! - [`QpClient`] — the handle application code actually holds and
//!   clones. See its doc for the cloning and backend-switch rules.
//! - Free helpers ([`synced_block`], etc.) that answer questions any
//!   backend can be asked.

use std::any::Any;
use std::sync::Arc;

use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::rpc::ckb_indexer::{CellsCapacity, Order, Pagination, SearchKey, Tx};
use ckb_sdk::traits::{
    CellCollector, CellQueryOptions, HeaderDepResolver, LiveCell, TransactionDependencyProvider,
};
use ckb_types::H256;

use crate::config::{NetworkType, NodeConfig, NodeType};
use crate::error::NodeManagerError;

mod full;
mod light;

pub use full::FullNodeClient;
pub(crate) use light::LightClient;

/// Total-request timeout for every JSON-RPC call.
///
/// ckb-sdk's default HTTP client has no timeout, so a node that accepts
/// a connection but never responds blocks the calling thread
/// indefinitely — wedging any single-flight poller waiting on it. Every
/// RPC client in this workspace must be built through the constructors
/// below (or, for ckb-sdk helper types that embed their own clients,
/// have this timeout injected at their construction site) so this bound
/// applies.
///
/// Known exception: the `LightClient*` tx-building helpers
/// (`light.rs`) expose no constructor or field through which a timeout
/// can be injected — see `BACKLOG.md` ("ckb-sdk RPC timeout").
pub const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Builds a full-node / indexer RPC client with [`RPC_TIMEOUT`] applied.
///
/// Panics on a malformed URL, matching `CkbRpcClient::new`'s behavior.
pub fn timed_ckb_rpc_client(url: &str) -> ckb_sdk::CkbRpcClient {
    ckb_sdk::CkbRpcClient::with_builder(url, |b| b.timeout(RPC_TIMEOUT))
        .expect("ckb rpc url, e.g. \"http://127.0.0.1:8114\"")
}

/// Builds a light-client RPC client with [`RPC_TIMEOUT`] applied.
///
/// Panics on a malformed URL, matching `LightClientRpcClient::new`'s
/// behavior.
pub(crate) fn timed_light_rpc_client(
    url: &str,
) -> ckb_sdk::rpc::ckb_light_client::LightClientRpcClient {
    ckb_sdk::rpc::ckb_light_client::LightClientRpcClient::with_builder(url, |b| {
        b.timeout(RPC_TIMEOUT)
    })
    .expect("light client rpc url, e.g. \"http://127.0.0.1:9000\"")
}

/// Builds an async full-node RPC client with [`RPC_TIMEOUT`] applied —
/// for injecting into ckb-sdk `Default*` helpers, whose plain
/// constructors embed their own untimed clients.
pub(crate) fn timed_ckb_async_rpc_client(url: &str) -> ckb_sdk::rpc::CkbRpcAsyncClient {
    ckb_sdk::rpc::CkbRpcAsyncClient::with_builder(url, |b| b.timeout(RPC_TIMEOUT))
        .expect("ckb rpc url, e.g. \"http://127.0.0.1:8114\"")
}

/// Unified RPC interface for wallet operations.
///
/// Abstracts over full node and light client so wallet code does not
/// need to know which backend is active.
///
/// The `Send + Sync` supertraits allow a single client instance to be
/// shared across background threads via `Arc<dyn UnifiedClient>` inside
/// `QpClient`.
///
/// `Any` enables downcasting from `Arc<dyn UnifiedClient>` back to the
/// concrete type when callers need backend-specific methods (e.g.
/// `LightClient::set_scripts`) — avoids constructing a second RPC
/// client when one already exists.
trait UnifiedClient: Send + Sync + Any {
    /// Concrete-type access for downcast. Each impl returns `self` so
    /// callers can do `client.as_any().downcast_ref::<LightClient>()`.
    fn as_any(&self) -> &dyn Any;

    /// Returns the tip (latest) block header.
    fn get_tip_header(&self) -> Result<ckb_jsonrpc_types::HeaderView, NodeManagerError>;

    fn get_peers(&self) -> Result<Vec<ckb_jsonrpc_types::RemoteNode>, NodeManagerError>;

    /// Returns the genesis block. Full nodes serve this via
    /// `get_block_by_number(0)`; the light client has a dedicated
    /// `get_genesis_block` RPC. Used to bootstrap the system-script
    /// `CellDepResolver` for transaction building.
    fn get_genesis_block(&self) -> Result<ckb_jsonrpc_types::BlockView, NodeManagerError>;

    /// Returns the total capacity of live cells matching the search key.
    fn get_cells_capacity(
        &self,
        search_key: SearchKey,
    ) -> Result<Option<CellsCapacity>, NodeManagerError>;

    /// Submits a transaction to the network.
    fn send_transaction(
        &self,
        tx: ckb_jsonrpc_types::Transaction,
    ) -> Result<H256, NodeManagerError>;

    /// Retrieves a transaction by hash, returning its status.
    fn get_transaction(&self, hash: H256) -> Result<Option<TransactionStatus>, NodeManagerError>;

    /// Gets a header by its hash.
    fn get_header(
        &self,
        hash: H256,
    ) -> Result<Option<ckb_jsonrpc_types::HeaderView>, NodeManagerError>;

    /// Queries transactions matching the given search key via the indexer.
    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: u32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>, NodeManagerError>;

    /// Collects live cells matching `query`. Each backend picks its best
    /// strategy: full node delegates to ckb-sdk's `DefaultCellCollector`;
    /// light client paginates its indexer (`get_cells`) directly.
    fn collect_cells(&self, query: &CellQueryOptions) -> Result<Vec<LiveCell>, NodeManagerError>;

    /// Returns a fresh ckb-sdk `CellCollector` bound to this backend.
    /// Used by tx builders that consume `&mut dyn CellCollector` (e.g.
    /// `build_balanced`). Full node returns `DefaultCellCollector`; light
    /// client returns `LightClientCellCollector`.
    fn cell_collector(&self) -> Box<dyn CellCollector>;

    /// Returns a fresh ckb-sdk `HeaderDepResolver` bound to this backend.
    /// Used by tx builders that consume `&dyn HeaderDepResolver`.
    fn header_dep_resolver(&self) -> Box<dyn HeaderDepResolver>;

    /// Returns a fresh ckb-sdk `TransactionDependencyProvider` bound to
    /// this backend. Used by tx builders that consume
    /// `&dyn TransactionDependencyProvider`.
    fn tx_dep_provider(&self) -> Box<dyn TransactionDependencyProvider>;

    fn local_node_info(&self) -> Result<ckb_jsonrpc_types::LocalNode, NodeManagerError>;
}

/// Simplified transaction status returned by `UnifiedClient::get_transaction`.
///
/// Normalizes the different response types from full node and light
/// client into a common representation.
#[derive(Debug, Clone)]
pub struct TransactionStatus {
    /// The transaction view, if available.
    pub transaction: Option<ckb_jsonrpc_types::TransactionView>,
    /// Transaction status string: "pending", "proposed", "committed", "rejected", or "unknown".
    pub status: String,
    /// Block hash of the block that committed this transaction, if committed.
    pub block_hash: Option<H256>,
}

/// The wallet's handle to the active CKB node. This is the type
/// application code holds and passes around to make RPC calls.
///
/// It pairs the connection (`Arc<dyn UnifiedClient>` — full node,
/// light client, or public RPC) with a copy of the `NodeConfig` it was
/// built from, so any holder can both query the chain and ask which
/// network and backend it is talking to (`network()`, `is_mainnet()`,
/// `config()`).
///
/// Cloning is cheap and every clone talks to the same backend, so
/// background threads take their own clone instead of sharing state
/// with the UI thread.
///
/// Switching backends never mutates an existing `QpClient`. The app
/// builds a new one from the new config and drops its old handle;
/// threads still holding old clones keep talking to the old backend
/// until they finish their current work, and the last drop closes the
/// connection. An in-flight HTTP request cannot be cancelled from the
/// outside, so letting it finish is the only clean way to retire a
/// client — and because every call is bounded by [`RPC_TIMEOUT`],
/// retirement takes at most one request's worth of time.
#[derive(Clone)]
pub struct QpClient {
    unified_client: Arc<dyn UnifiedClient>,
    config: NodeConfig,
}

impl QpClient {
    /// Builds a fresh handle bound to `config`. Constructs the
    /// concrete `UnifiedClient` impl appropriate for `config.node_type`.
    pub fn new(config: NodeConfig) -> Self {
        let unified_client: Arc<dyn UnifiedClient> = match config.node_type {
            NodeType::PublicRpc | NodeType::FullNode => {
                Arc::new(FullNodeClient::new(&config.rpc_url))
            }
            NodeType::LightClient => Arc::new(LightClient::new(&config.rpc_url)),
        };
        Self {
            unified_client,
            config,
        }
    }

    /// Returns a reference to the `NodeConfig` snapshot this handle was built from.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns the network (Mainnet/Testnet) the active backend is bound to.
    pub fn network(&self) -> NetworkType {
        self.config.network
    }

    /// Returns the backend kind (`PublicRpc`, `FullNode`, or `LightClient`).
    pub fn node_type(&self) -> NodeType {
        self.config.node_type
    }

    /// True if this handle is bound to the mainnet network.
    pub fn is_mainnet(&self) -> bool {
        self.config.network == NetworkType::Mainnet
    }

    /// Returns the JSON-RPC endpoint URL this handle is bound to.
    fn rpc_url(&self) -> &str {
        &self.config.rpc_url
    }

    /// Sends a batch of JSON-RPC calls in a single HTTP POST and returns
    /// the results in request order. Each element of `calls` is a
    /// `(method, params)` pair. Returns one `serde_json::Value` per call
    /// (the `"result"` field); callers deserialize themselves.
    pub fn batch_rpc(
        &self,
        calls: &[(&str, serde_json::Value)],
    ) -> Result<Vec<serde_json::Value>, NodeManagerError> {
        if calls.is_empty() {
            return Ok(vec![]);
        }

        let batch: Vec<serde_json::Value> = calls
            .iter()
            .enumerate()
            .map(|(id, (method, params))| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": method,
                    "params": params,
                })
            })
            .collect();

        let resp = reqwest::blocking::Client::new()
            .post(self.rpc_url())
            .json(&batch)
            .send()
            .map_err(|e| NodeManagerError::RpcError(format!("Batch RPC HTTP error: {}", e)))?
            .error_for_status()
            .map_err(|e| NodeManagerError::RpcError(format!("Batch RPC HTTP {}", e)))?;

        let mut results: Vec<serde_json::Value> = resp
            .json()
            .map_err(|e| NodeManagerError::RpcError(format!("Batch RPC parse error: {}", e)))?;

        if results.len() != calls.len() {
            return Err(NodeManagerError::RpcError(format!(
                "Batch RPC: expected {} results, got {}",
                calls.len(),
                results.len(),
            )));
        }

        results.sort_by_key(|r| r.get("id").and_then(|v| v.as_u64()).unwrap_or(0));

        results
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                if let Some(err) = r.get("error") {
                    let method = calls[i].0;
                    return Err(NodeManagerError::RpcError(format!(
                        "Batch RPC '{}': {}",
                        method, err
                    )));
                }
                Ok(r.get("result").cloned().unwrap_or(serde_json::Value::Null))
            })
            .collect()
    }

    /// Returns the tip (latest) block header from the active backend.
    pub fn get_tip_header(&self) -> Result<ckb_jsonrpc_types::HeaderView, NodeManagerError> {
        self.unified_client.get_tip_header()
    }

    /// Retrieves a transaction by hash, returning its normalized status.
    pub fn get_transaction(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionStatus>, NodeManagerError> {
        self.unified_client.get_transaction(hash)
    }

    /// Retrieves a transaction like [`Self::get_transaction`], and
    /// additionally pulls it from the P2P network when the light client
    /// doesn't hold it locally.
    ///
    /// The light client only stores transactions that matched a
    /// registered script or were explicitly fetched, so an arbitrary
    /// transaction (e.g. the previous output spent by an external
    /// input) needs a `fetch_transaction` round trip to peers first.
    /// That fetch is asynchronous: this returns `Ok(None)` whenever no
    /// transaction view is available yet — call again until it lands in
    /// the store. A full node holds every committed transaction locally,
    /// so there is never a fetch to kick off.
    pub fn get_or_fetch_transaction(
        &self,
        hash: H256,
    ) -> Result<Option<TransactionStatus>, NodeManagerError> {
        if let Some(status) = self.unified_client.get_transaction(hash.clone())? {
            if status.transaction.is_some() {
                return Ok(Some(status));
            }
        }

        // Not in the local store. The light client can pull it from
        // peers; once fetched it becomes visible to `get_transaction`
        // above. A full node either has a transaction or it doesn't —
        // there is nothing to kick off.
        if let Some(light) = self.unified_client.as_any().downcast_ref::<LightClient>() {
            light.fetch_transaction(hash)?;
        }
        Ok(None)
    }

    /// Collects live cells matching `options`, using whichever strategy the
    /// active backend prefers (see [`UnifiedClient::collect_cells`]).
    pub fn collect_cells(
        &self,
        options: &CellQueryOptions,
    ) -> Result<Vec<LiveCell>, NodeManagerError> {
        self.unified_client.collect_cells(options)
    }

    /// Returns the total capacity of live cells matching `search_key`.
    pub fn get_cells_capacity(
        &self,
        search_key: SearchKey,
    ) -> Result<Option<CellsCapacity>, NodeManagerError> {
        self.unified_client.get_cells_capacity(search_key)
    }

    /// Gets a header by its block hash.
    pub fn get_header(
        &self,
        hash: H256,
    ) -> Result<Option<ckb_jsonrpc_types::HeaderView>, NodeManagerError> {
        self.unified_client.get_header(hash)
    }

    /// Queries indexer-side transactions matching `search_key`, paginated.
    pub fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: u32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>, NodeManagerError> {
        self.unified_client
            .get_transactions(search_key, order, limit, after)
    }

    /// Returns a fresh ckb-sdk `CellCollector` bound to the active backend,
    /// for tx builders that consume `&mut dyn CellCollector`.
    pub fn cell_collector(&self) -> Box<dyn CellCollector> {
        self.unified_client.cell_collector()
    }

    /// Returns a fresh ckb-sdk `HeaderDepResolver` bound to the active backend,
    /// for tx builders that consume `&dyn HeaderDepResolver`.
    pub fn header_dep_resolver(&self) -> Box<dyn HeaderDepResolver> {
        self.unified_client.header_dep_resolver()
    }

    /// Returns a fresh ckb-sdk `TransactionDependencyProvider` bound to the
    /// active backend, for tx builders that consume
    /// `&dyn TransactionDependencyProvider`.
    pub fn tx_dep_provider(&self) -> Box<dyn TransactionDependencyProvider> {
        self.unified_client.tx_dep_provider()
    }

    /// Returns the genesis block. Used to bootstrap the system-script
    /// `CellDepResolver` for transaction building.
    pub fn get_genesis_block(&self) -> Result<ckb_jsonrpc_types::BlockView, NodeManagerError> {
        self.unified_client.get_genesis_block()
    }

    /// Submits a transaction to the network and returns its hash.
    pub fn send_transaction(
        &self,
        tx: ckb_jsonrpc_types::Transaction,
    ) -> Result<H256, NodeManagerError> {
        self.unified_client.send_transaction(tx)
    }

    /// Concrete-type access for downcast — e.g.
    /// `client.as_any().downcast_ref::<LightClient>()` to reach
    /// backend-specific methods like `LightClient::set_scripts`.
    pub fn as_any(&self) -> &dyn Any {
        self.unified_client.as_any()
    }

    pub fn get_peers(&self) -> Result<Vec<ckb_jsonrpc_types::RemoteNode>, NodeManagerError> {
        self.unified_client.get_peers()
    }

    /// Min synced block across all scripts the LC is tracking. `Ok(None)`
    /// outside `LightClient` and when no scripts are registered.
    pub fn synced_block(&self) -> Result<Option<u64>, NodeManagerError> {
        let Some(light) = self.unified_client.as_any().downcast_ref::<LightClient>() else {
            return Ok(None);
        };
        let scripts = light.get_scripts()?;
        Ok(scripts.iter().map(|s| s.block_number.value()).min())
    }

    /// Per-script sync status from the LC. Returns `(lock_args_hex, block_number)`
    /// for each tracked script. Empty for non-LC backends.
    pub fn tracked_scripts(&self) -> Result<Vec<(String, u64)>, NodeManagerError> {
        let Some(light) = self.unified_client.as_any().downcast_ref::<LightClient>() else {
            return Ok(Vec::new());
        };
        let scripts = light.get_scripts()?;
        Ok(scripts
            .into_iter()
            .map(|s| {
                let args_hex = hex::encode(s.script.args.as_bytes());
                let block = s.block_number.value();
                (args_hex, block)
            })
            .collect())
    }

    /// Full node IBD progress and phase (header sync / block download /
    /// verifying / synced). `Ok(None)` for `LightClient` (no analogue)
    /// and `PublicRpc` (remote endpoint's sync isn't *our* sync, same
    /// policy as `peer_count`). `Some(_)` only for `FullNode`.
    pub fn sync_state(&self) -> Result<Option<ckb_jsonrpc_types::SyncState>, NodeManagerError> {
        if self.config.node_type != NodeType::FullNode {
            return Ok(None);
        }
        let Some(full) = self
            .unified_client
            .as_any()
            .downcast_ref::<FullNodeClient>()
        else {
            return Ok(None);
        };
        full.sync_state().map(Some)
    }

    pub fn blockchain_info(
        &self,
    ) -> Result<Option<ckb_jsonrpc_types::ChainInfo>, NodeManagerError> {
        let Some(full) = self
            .unified_client
            .as_any()
            .downcast_ref::<FullNodeClient>()
        else {
            return Ok(None);
        };
        full.get_blockchain_info().map(Some)
    }

    pub fn tx_pool_info(&self) -> Result<Option<ckb_jsonrpc_types::TxPoolInfo>, NodeManagerError> {
        let Some(full) = self
            .unified_client
            .as_any()
            .downcast_ref::<FullNodeClient>()
        else {
            return Ok(None);
        };
        full.tx_pool_info().map(Some)
    }

    pub fn local_node_info(&self) -> Result<ckb_jsonrpc_types::LocalNode, NodeManagerError> {
        self.unified_client.local_node_info()
    }
}
