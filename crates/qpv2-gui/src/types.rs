//! Shared types, constants, and utility functions for the GUI.

use eframe::egui;
use serde::{Deserialize, Serialize};

/// Result of a single account balance fetch from a background thread.
/// Tuple fields: (lock_args, total_balance, spendable_capacity).
///
/// Total and spendable are independent RPC calls, so each carries its own
/// `Result`: a transient failure on one must not discard the other's value,
/// nor overwrite the last good cached value with a fake zero.
pub(crate) type BalanceResult = (String, Result<u64, String>, Result<u64, String>);

/// One point in a chart time series: `(unix_secs, value_shannons)`.
pub(crate) type SeriesPoint = (u64, u64);

/// A chart time series: chronological `(timestamp, value)` points, as
/// consumed by the dashboard balance chart and the QR-adoption (TVL) chart.
pub(crate) type Series = Vec<SeriesPoint>;

/// Result of the QR-adoption background fetch streamed back to the UI.
pub(crate) type QrAdoptionUpdate = Result<Series, String>;

/// Memoized dashboard balance chart: `((tx_count, live_total, 10s_bucket),
/// line_points)`. Rebuilding from the whole tape every frame is
/// wasted work, so the result is cached under the key tuple.
pub(crate) type BalanceChartCache = ((usize, u64, u64), Series);

/// Identifies which transaction flow owns a shared background operation,
/// down to the specific DAO operation so mid-flight UI (e.g. the
/// multisig co-signer panel) can say what is being signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactionKind {
    Transfer,
    DaoDeposit,
    DaoPrepare,
    DaoWithdraw,
}

impl TransactionKind {
    /// True for any Nervos DAO operation.
    pub(crate) fn is_dao(self) -> bool {
        !matches!(self, TransactionKind::Transfer)
    }

    /// Human-readable operation name for signing requests and logs.
    pub(crate) fn label(self) -> &'static str {
        match self {
            TransactionKind::Transfer => "TRANSFER",
            TransactionKind::DaoDeposit => "DAO DEPOSIT",
            TransactionKind::DaoPrepare => "DAO WITHDRAWAL REQUEST",
            TransactionKind::DaoWithdraw => "DAO WITHDRAW",
        }
    }
}

/// Result type for transaction building (unsigned tx, input cells, lock_args).
pub(crate) type TxBuildResult = Result<
    (
        TransactionKind,
        ckb_types::core::TransactionView,
        Vec<(ckb_types::packed::CellOutput, ckb_types::bytes::Bytes)>,
        String,
    ),
    String,
>;

/// Result type for sending a signed transaction.
pub(crate) type TransactionSendResult = (TransactionKind, Result<String, String>);

/// Result type for DAO cell queries across all accounts.
pub(crate) type DaoQueryResult = Result<DaoQueryEvent, String>;

/// Streaming DAO query event from background thread.
pub(crate) enum DaoQueryEvent {
    Deposited(String, ckb_node::DepositedCell),
    Prepared(String, ckb_node::PreparedCell),
    Done,
}

/// Classification of a transaction from the wallet's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub(crate) enum TxKind {
    Incoming,
    Outgoing,
    /// Capacity moved strictly between this wallet's accounts.
    SelfTransfer,
    DaoDeposit,
    DaoPrepare,
    DaoWithdraw,
}

/// Blocks that must bury a transaction before its record is final.
/// CKB reorgs deeper than this are considered impossible. Records at
/// or past this depth are persisted and never re-checked; younger
/// records live in memory only and are re-verified against the chain
/// on every history sync, so a reorg can still move or remove them.
pub(crate) const CONFIRMATION_DEPTH: u64 = 24;

/// A resolved transaction record for display on the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxRecord {
    pub tx_hash: String,
    pub tx_kind: TxKind,
    /// Net amount in shannons (always positive).
    pub amount: u64,
    pub block_number: u64,
    /// Unix timestamp in seconds, resolved from block header.
    pub timestamp: u64,
    pub is_pending: bool,
    /// Lock args of the wallet account that owns this transaction.
    pub owner_lock_args: String,
    /// The other wallet account involved, when there is one: the
    /// receiver of a `SelfTransfer`, the in-wallet leg of a mixed
    /// payment, or the sending sibling account of an `Incoming`.
    pub internal_counterparty_lock_args: Option<String>,
    /// For Outgoing to external addresses: the first external recipient's full
    /// bech32m address. Used to build the Address Book in the Transfer tab.
    pub external_recipient_address: Option<String>,
}

impl TxRecord {
    /// Blocks on top of and including this record's block at `tip`;
    /// 0 while pending or when the tip is unknown or behind.
    pub fn confirmations(&self, tip: u64) -> u64 {
        if self.is_pending || self.block_number == 0 || tip < self.block_number {
            return 0;
        }
        tip - self.block_number + 1
    }

    /// Buried at least [`CONFIRMATION_DEPTH`] blocks deep — no reorg
    /// can move it, so the record is final.
    pub fn is_confirmed(&self, tip: u64) -> bool {
        self.confirmations(tip) >= CONFIRMATION_DEPTH
    }
}

/// Streaming event from the transaction history background thread.
pub(crate) enum TxHistoryEvent {
    Record(TxRecord),
    /// Emitted when the sync thread has no more records to stream.
    Done,
    /// Emitted when the sync gives up because a lookup stayed
    /// unavailable past its retry budget. The records streamed so far
    /// must be discarded: the watermark derived from a partial batch
    /// would skip the transactions that were never emitted.
    Aborted,
}

/// Pre-fetched wallet metadata so rendering never hits the filesystem.
pub(crate) struct CurrentWallet {
    pub id: u32,
    pub name: String,
    pub spx_variant: qpv2_core::types::SpxVariant,
    pub auth_method: qpv2_core::types::AuthMethod,
    pub single_sig_convention: qpv2_core::types::SingleSigConvention,
    pub account_count: usize,
    pub path: String,
}

/// Navigation modules listed in the left rail. Order here is the rail
/// order and the 1–7 keyboard shortcut order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Tab {
    Dashboard,
    Transfer,
    DaoOperations,
    NodeManager,
    Accounts,
    Multisig,
    Wallets,
}

impl Tab {
    /// All modules in rail / shortcut order.
    pub(crate) const ALL: [Tab; 7] = [
        Tab::Dashboard,
        Tab::Transfer,
        Tab::DaoOperations,
        Tab::NodeManager,
        Tab::Accounts,
        Tab::Multisig,
        Tab::Wallets,
    ];

    /// Four-letter module code shown in the rail.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Tab::Dashboard => "DASH",
            Tab::Transfer => "XFER",
            Tab::DaoOperations => "DAO",
            Tab::NodeManager => "NODE",
            Tab::Accounts => "ACCT",
            Tab::Multisig => "MSIG",
            Tab::Wallets => "WLLT",
        }
    }

    /// Full module name shown next to the code.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Transfer => "Transfer",
            Tab::DaoOperations => "Nervos DAO",
            Tab::NodeManager => "Networks",
            Tab::Accounts => "Accounts",
            Tab::Multisig => "Multisig",
            Tab::Wallets => "Wallets",
        }
    }
}

/// Snapshot of the currently-active backend's live status, cached on `App`
/// and refreshed periodically by `fetch_node_status`. Fields are `Option`
/// so the UI can show "—" for metrics that haven't landed yet or aren't
/// applicable to the active backend (e.g. peer count for PublicRpc).
#[derive(Debug, Clone, Default)]
pub(crate) struct NodeStatus {
    /// Full tip header from `get_tip_header`. Contains DAO AR data
    /// needed for estimating deposited-cell interest at render time.
    pub tip_header: Option<ckb_types::core::HeaderView>,
    /// Header from ~7 days ago, used with `tip_header` to compute APC.
    pub apc_baseline_header: Option<ckb_types::core::HeaderView>,
    /// Full peer list from `get_peers`.
    pub peers: Vec<ckb_jsonrpc_types::RemoteNode>,
    /// RPC port parsed from `config.rpc_url`.
    pub rpc_port: Option<u16>,
    /// Min synced block across all registered scripts (light client only).
    /// `None` for PublicRpc/FullNode and when no scripts are registered.
    pub synced_block: Option<u64>,
    /// Full node IBD state — phase (header sync / block download /
    /// verifying / synced) and the network's best-known tip. `None`
    /// outside `FullNode`.
    pub sync_state: Option<ckb_jsonrpc_types::SyncState>,
    /// Chain-level metadata (chain name, difficulty, IBD flag, median time).
    /// `None` for light client (RPC not available).
    /// Wrapped in `Arc` because `ChainInfo` does not implement `Clone`.
    pub blockchain_info: Option<std::sync::Arc<ckb_jsonrpc_types::ChainInfo>>,
    /// Transaction pool snapshot. `None` for light client.
    pub tx_pool_info: Option<ckb_jsonrpc_types::TxPoolInfo>,
    /// Local node identity (version, node ID, connections, protocols).
    /// `None` for public RPC (no local process).
    pub local_node_info: Option<ckb_jsonrpc_types::LocalNode>,
    /// True when the most recent poll reached the node successfully.
    pub online: bool,
    /// Per-script sync status from the LC's `get_scripts`. Each entry is
    /// `(lock_args_hex, block_number)`. Empty for non-LC backends.
    pub tracked_scripts: Vec<(String, u64)>,
}

impl NodeStatus {
    /// Tip block number derived from the cached header.
    pub fn tip_block(&self) -> Option<u64> {
        self.tip_header.as_ref().map(|h| h.number())
    }
}

/// Result type for the node-status background poll.
pub(crate) type NodeStatusUpdate = Result<NodeStatus, String>;

/// Application state machine.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Screen {
    /// No wallet exists yet — user chooses variant and creates one.
    Setup,
    /// Wallet exists — waiting for Touch ID to unlock.
    Locked,
    /// Wallet unlocked — show wallet info.
    Unlocked,
}

/// Status messages shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    None,
    Info(String),
    Error(String),
}

/// Tracks the state of an in-progress transfer transaction.
#[derive(Debug, Clone)]
pub(crate) enum TransactionStatus {
    /// No transfer in progress.
    Idle,
    /// Building the unsigned transaction.
    Building,
    /// Waiting for Touch ID to sign.
    AwaitingSignature,
    /// Multisig: waiting for co-signer responses.
    AwaitingCoSigners {
        kind: TransactionKind,
        // Boxed: `SigningRequest` is by far the largest field, and without
        // the indirection it would bloat every `TransactionStatus` value
        // (even `Idle`) to its size. See clippy::large_enum_variant.
        request: Box<qpv2_core::types::SigningRequest>,
        unsigned_tx: ckb_types::core::TransactionView,
        /// Signatures collected so far: (signer_index, raw_sig_bytes).
        signatures: Vec<(usize, Vec<u8>)>,
        /// Clipboard/paste buffer for importing a co-signer response.
        import_response_json: String,
    },
    /// Sending the signed transaction.
    Sending,
    /// Transaction sent successfully.
    Success(String),
    /// An error occurred.
    Error(String),
}

/// Which wallet modal is currently open, if any.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WalletModal {
    None,
    Create,
    Import,
}

/// Sub-view within the DAO tab.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum DaoView {
    /// Show overview with stats, action cards, and positions table.
    Overview,
    /// Deposit form.
    Deposit,
}

/// CKB uses 8 decimal places: 1 CKB = 100,000,000 shannons.
pub(crate) const CKB_DECIMAL_PLACES: u64 = 100_000_000;

/// "Flight Deck" color scheme: the wallet styled as a precision
/// instrument. Cool near-black canvas, neutral hairline separators,
/// one dominant cryo-cyan signal color, and green/red reserved for
/// strictly semantic meaning (online/positive vs offline/negative).
/// Cyan was chosen over amber, which reads as a caution color.
pub(crate) struct AppColors {
    /// Main canvas — cool near-black.
    pub(crate) bg: egui::Color32,
    /// Panel fill, one step above the canvas.
    pub(crate) surface: egui::Color32,
    /// Elevated fill for hover states and input fields.
    pub(crate) surface2: egui::Color32,
    /// 1px hairline separator. Solid (not alpha) so anti-aliasing
    /// doesn't brighten it against the dark bg.
    pub(crate) border: egui::Color32,
    /// Stronger hairline for hovered/active outlines.
    pub(crate) border2: egui::Color32,
    /// Cryo cyan — the single signal color for everything
    /// interactive or important.
    pub(crate) accent: egui::Color32,
    /// Semantic green: online, confirmed, incoming.
    pub(crate) accent2: egui::Color32,
    /// Dimmed cyan for secondary emphasis (inactive accents).
    pub(crate) accent3: egui::Color32,
    /// Low-alpha cyan fill for active rows and selected items.
    pub(crate) accent_tint: egui::Color32,
    /// Low-alpha warn fill used for pill/badge backgrounds.
    pub(crate) warn_tint: egui::Color32,
    /// Semantic red: offline, errors, outgoing warnings.
    pub(crate) danger: egui::Color32,
    /// Caution yellow.
    pub(crate) warn: egui::Color32,
    /// Primary text — cool off-white, phosphor-adjacent.
    pub(crate) text: egui::Color32,
    /// Secondary text — cool gray.
    pub(crate) text_muted: egui::Color32,
}

impl Default for AppColors {
    fn default() -> Self {
        Self {
            bg: egui::Color32::from_rgb(10, 12, 13),        // #0a0c0d
            surface: egui::Color32::from_rgb(15, 18, 20),   // #0f1214
            surface2: egui::Color32::from_rgb(22, 27, 30),  // #161b1e
            border: egui::Color32::from_rgb(35, 42, 45),    // #232a2d
            border2: egui::Color32::from_rgb(60, 71, 76),   // #3c474c
            accent: egui::Color32::from_rgb(34, 211, 238),  // #22d3ee
            accent2: egui::Color32::from_rgb(61, 214, 124), // #3dd67c
            accent3: egui::Color32::from_rgb(14, 116, 144), // #0e7490
            accent_tint: egui::Color32::from_rgba_unmultiplied(34, 211, 238, 22),
            warn_tint: egui::Color32::from_rgba_unmultiplied(255, 209, 102, 26),
            danger: egui::Color32::from_rgb(255, 84, 62), // #ff543e
            warn: egui::Color32::from_rgb(255, 209, 102), // #ffd166
            text: egui::Color32::from_rgb(221, 232, 234), // #dde8ea
            text_muted: egui::Color32::from_rgb(109, 125, 130), // #6d7d82
        }
    }
}

/// Font for big display numerals and screen titles (Martian Mono
/// Condensed Bold).
pub(crate) fn display_font(size: f32) -> egui::FontId {
    egui::FontId::new(size, egui::FontFamily::Name("display".into()))
}

/// Font for tiny uppercase labels, badges, and module codes (Martian
/// Mono Condensed Regular).
pub(crate) fn label_font(size: f32) -> egui::FontId {
    egui::FontId::new(size, egui::FontFamily::Name("label".into()))
}
