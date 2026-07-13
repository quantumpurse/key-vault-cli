//! Transaction builders for CKB.
//!
//! This module provides builders for constructing various types of CKB transactions:
//! - Transfer transactions (sending CKB)
//! - DAO deposit transactions
//! - DAO prepare transactions (withdraw phase 1)
//! - DAO withdraw transactions (withdraw phase 2)
//! - Signing utilities for quantum-resistant locks

pub mod dao;
pub mod signing;
pub mod transfer;
pub mod utils;

pub use dao::{QpDaoDepositBuilder, QpDaoPrepareBuilder, QpDaoWithdrawBuilder};
pub use signing::{
    assemble_multisig_witness, build_signing_request, compute_signing_message, fetch_input_cells,
    fetch_prev_txs, fill_witness, send_transaction,
};
pub use transfer::QpTransferBuilder;
