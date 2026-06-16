//! Wallet-domain composition over the protocol layer.
//!
//! Free functions that take an RPC handle (typically `&dyn Client`) plus
//! wallet-specific arguments and return wallet-meaningful results — a
//! balance, a tx-history list, an unsigned transaction, the outcome of a
//! script-registration call. Stateless: no per-instance state, no shared
//! ownership, no threads of their own.
//!
//! This module is the home for QPV2-specific knowledge: which lock script
//! is "ours", which cell-dep deployments to reference, what start-block
//! policy to apply when re-registering on a light client. The protocol
//! layer below (`crate::rpc`) deliberately doesn't know any of that —
//! keeping the protocol speakers reusable beyond this wallet.

pub mod lc;
pub mod queries;
pub mod tx_builder;
pub mod utils;
