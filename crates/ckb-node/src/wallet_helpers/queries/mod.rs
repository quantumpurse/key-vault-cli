//! Read-only queries against a CKB node.
//!
//! Every function here takes a `&dyn Client` and returns domain data —
//! balances, spendable capacity, DAO cells, transaction history. These are
//! wallet-domain operations that use the RPC, distinct from:
//!
//! - the `rpc` module (the `Client` trait and its concrete clients), and
//! - the `tx_builder` module (which constructs transactions).
//!
//! The `LocalNodeProcess` facade in `lib.rs` exposes these as methods so callers
//! don't need to touch the raw RPC handle.

pub mod balance;
pub mod dao_cells;
pub mod qr_adoption;
pub mod spendable;
pub mod tx_history;

pub use balance::fetch_quantum_lock_balance;
pub use dao_cells::{categorize_dao_cells, DepositedCell, PreparedCell};
pub use qr_adoption::fetch_qr_adoption_series;
pub use spendable::spendable_capacity;
pub use tx_history::fetch_recent_transactions;
