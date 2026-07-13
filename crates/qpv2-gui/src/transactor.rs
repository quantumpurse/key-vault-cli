//! Transaction building, signing, and sending.

use crate::types::{Status, TransactionKind, TransactionStatus};
use crate::App;
use ckb_node::{NodeType, QpClient};
use qpv2_core::{types::AuthKey, KeyVault};
use std::sync::mpsc;

/// Pre-flight check before building any tx that uses the QR-lock-script
/// cell dep. The light client only stores cells whose lock matches a
/// registered filter script, so the dep cell isn't auto-indexed —
/// `rpc::fetch_qr_lock_dep` is what pulls it. This wrapper gates the
/// build path on whether the dep has finished fetching.
///
/// `Ok(())` for non-LightClient backends (full nodes / public RPC have
/// every cell); `Ok(())` for LightClient when the dep is already in the
/// store. Otherwise returns a user-facing message ready for `App.status`.
fn check_qr_lock_dep_ready(qp_client: &QpClient, node_type: NodeType) -> Result<(), String> {
    if node_type != NodeType::LightClient {
        return Ok(());
    }
    match ckb_node::wallet_helpers::lc::fetch_qr_lock_dep(qp_client) {
        Ok(true) => Ok(()),
        Ok(false) => Err(
            "Light client hasn't fetched the lock-script cell dep yet. Try again in a moment."
                .to_string(),
        ),
        Err(e) => Err(format!("Failed to check lock-script cell dep: {}", e)),
    }
}

impl App {
    /// Kick off a transfer: validate inputs, then build the unsigned tx in a background thread.
    pub(crate) fn transfer_async(&mut self) {
        // Claim the tx slot for this screen BEFORE any validation:
        // pre-flight errors must display under the flow that caused
        // them, and the status log is gated on this kind.
        self.active_tx_kind = Some(TransactionKind::Transfer);

        // Validate inputs
        if self.accounts.is_empty() {
            tracing::error!("No accounts available.");
            self.tx_status = TransactionStatus::Error("No accounts available.".to_string());
            return;
        }

        // validate from account
        let from_idx = self.transfer_from_account.min(self.accounts.len() - 1);
        let lock_args = self.accounts[from_idx].lock_args.clone();

        let is_mainnet = self.qp_client.is_mainnet();
        let from_address = match crate::utils::lock_args_to_address(&lock_args, is_mainnet) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("Invalid sender address: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Error(msg);
                return;
            }
        };
        let from_addr_str = from_address.to_string();

        // validate recipient address
        let to_addr_str = self.transfer_recipient.trim().to_string();
        if to_addr_str.is_empty() {
            tracing::error!("Recipient address is empty.");
            self.tx_status = TransactionStatus::Error("Recipient address is empty.".to_string());
            return;
        }

        // check if sender and receiver share the same network prefix.
        if !to_addr_str.starts_with(&from_addr_str[..3]) {
            let from_net = if is_mainnet { "mainnet" } else { "testnet" };
            let to_net = if to_addr_str.starts_with("ckb") {
                "mainnet"
            } else {
                "testnet"
            };
            self.tx_status = TransactionStatus::Error(format!(
                "Network mismatch: sending from {} to a {} address.",
                from_net, to_net
            ));
            return;
        }

        // check if recipient address is valid
        let to_address: ckb_sdk::Address = match to_addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                self.tx_status =
                    TransactionStatus::Error(format!("Invalid recipient address: {}", e));
                return;
            }
        };
        let expected_net = if is_mainnet {
            ckb_sdk::NetworkType::Mainnet
        } else {
            ckb_sdk::NetworkType::Testnet
        };
        if to_address.network() != expected_net {
            self.tx_status =
                TransactionStatus::Error("Recipient address is for the wrong network.".to_string());
            return;
        }

        let fee_rate: u64 = match self.transfer_fee_rate.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("Invalid fee rate.");
                self.tx_status = TransactionStatus::Error("Invalid fee rate.".to_string());
                return;
            }
        };

        let account = &self.accounts[from_idx];
        let max_witness_lock_size = account.config.max_witness_lock_size();

        let send_all = self.transfer_all;

        // Parse amount only when not sending all. Integer parsing —
        // f64 mis-converts amounts by a shannon (see BACKLOG.md).
        let capacity_sh = if send_all {
            0 // Unused; build_unsigned_transfer_all computes the amount internally.
        } else {
            match qpv2_core::utilities::parse_ckb_to_shannons(&self.transfer_amount) {
                Ok(sh) if sh > 0 => sh,
                Ok(_) => {
                    self.tx_status =
                        TransactionStatus::Error("Amount must be greater than zero.".to_string());
                    return;
                }
                Err(e) => {
                    tracing::error!("Invalid amount: {}", e);
                    self.tx_status = TransactionStatus::Error(e);
                    return;
                }
            }
        };

        tracing::info!(
            "Transfer started: to={}, amount={}, send_all={}, wallet_id={}",
            &to_addr_str.get(..8).unwrap_or(&to_addr_str),
            if send_all {
                "all".to_string()
            } else {
                self.transfer_amount.clone()
            },
            send_all,
            self.wallet_id
        );
        self.tx_status = TransactionStatus::Building;
        let qp_client = self.qp_client.clone();
        let node_type = self.qp_client.config().node_type;
        let is_mainnet = self.qp_client.is_mainnet();

        let (tx, rx) = mpsc::channel();
        self.transaction_build_rx = Some(rx);

        std::thread::spawn(move || {
            let result = (|| -> Result<_, String> {
                check_qr_lock_dep_ready(&qp_client, node_type)?;

                let builder = ckb_node::QpTransferBuilder::new(&qp_client, is_mainnet)
                    .with_placeholder_lock_size(max_witness_lock_size);

                let unsigned_tx = if send_all {
                    let (tx, _) = builder
                        .build_unsigned_transfer_all(&from_address, &to_address, fee_rate, None)
                        .map_err(|e| format!("Failed to build transaction: {}", e))?;
                    tx
                } else {
                    builder
                        .build_unsigned_transfer(
                            &from_address,
                            &to_address,
                            capacity_sh,
                            fee_rate,
                            None,
                        )
                        .map_err(|e| format!("Failed to build transaction: {}", e))?
                };

                // Fetch input cells for CKB_TX_MESSAGE_ALL
                let input_cells = ckb_node::wallet_helpers::tx_builder::fetch_input_cells(
                    &qp_client,
                    &unsigned_tx,
                )
                .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

                Ok((
                    TransactionKind::Transfer,
                    unsigned_tx,
                    input_cells,
                    lock_args,
                ))
            })();

            let _ = tx.send(result);
        });
    }

    /// Start building a DAO deposit transaction in a background thread.
    pub(crate) fn dao_deposit_async(&mut self) {
        // Claim the tx slot for this screen BEFORE any validation:
        // pre-flight errors must display under the flow that caused
        // them, and the status log is gated on this kind.
        self.active_tx_kind = Some(TransactionKind::DaoDeposit);

        if self.accounts.is_empty() {
            tracing::error!("No accounts available.");
            self.tx_status = TransactionStatus::Error("No accounts available.".to_string());
            return;
        }

        let from_idx = self.dao_deposit_from_account.min(self.accounts.len() - 1);
        let lock_args = self.accounts[from_idx].lock_args.clone();

        let is_mainnet = self.qp_client.is_mainnet();
        let from_address = match crate::utils::lock_args_to_address(&lock_args, is_mainnet) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("Invalid sender address: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Error(msg);
                return;
            }
        };

        let fee_rate: u64 = match self.dao_deposit_fee_rate.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("Invalid fee rate.");
                self.tx_status = TransactionStatus::Error("Invalid fee rate.".to_string());
                return;
            }
        };

        let account = &self.accounts[from_idx];
        let max_witness_lock_size = account.config.max_witness_lock_size();

        let deposit_all = self.dao_deposit_all;

        // Parse amount only when not depositing all. Integer parsing —
        // f64 mis-converts amounts by a shannon (see BACKLOG.md).
        let capacity_sh = if deposit_all {
            0 // Unused; build_unsigned_deposit_all computes the amount internally.
        } else {
            match qpv2_core::utilities::parse_ckb_to_shannons(&self.dao_deposit_amount) {
                Ok(sh) if sh > 0 => sh,
                Ok(_) => {
                    self.tx_status =
                        TransactionStatus::Error("Amount must be greater than zero.".to_string());
                    return;
                }
                Err(e) => {
                    tracing::error!("Invalid amount: {}", e);
                    self.tx_status = TransactionStatus::Error(e);
                    return;
                }
            }
        };

        tracing::info!(
            "DAO deposit started: deposit_all={}, wallet_id={}",
            deposit_all,
            self.wallet_id
        );
        self.tx_status = TransactionStatus::Building;
        let qp_client = self.qp_client.clone();
        let node_type = self.qp_client.config().node_type;
        let is_mainnet = self.qp_client.is_mainnet();

        let (tx, rx) = mpsc::channel();
        self.transaction_build_rx = Some(rx);

        std::thread::spawn(move || {
            let result = (|| -> Result<_, String> {
                check_qr_lock_dep_ready(&qp_client, node_type)?;

                let builder = ckb_node::QpDaoDepositBuilder::new(&qp_client, is_mainnet)
                    .with_placeholder_lock_size(max_witness_lock_size);

                let unsigned_tx = if deposit_all {
                    let (tx, _) = builder
                        .build_unsigned_deposit_all(&from_address, fee_rate)
                        .map_err(|e| format!("Failed to build DAO deposit: {}", e))?;
                    tx
                } else {
                    builder
                        .build_unsigned_deposit(&from_address, capacity_sh, fee_rate)
                        .map_err(|e| format!("Failed to build DAO deposit: {}", e))?
                };

                let input_cells = ckb_node::wallet_helpers::tx_builder::fetch_input_cells(
                    &qp_client,
                    &unsigned_tx,
                )
                .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

                Ok((
                    TransactionKind::DaoDeposit,
                    unsigned_tx,
                    input_cells,
                    lock_args,
                ))
            })();

            let _ = tx.send(result);
        });
    }

    /// Start building a DAO prepare transaction in a background thread.
    pub(crate) fn dao_withdraw_request_async(
        &mut self,
        deposit_out_point: ckb_types::packed::OutPoint,
        lock_args: String,
    ) {
        // Claim the tx slot for this screen BEFORE any validation:
        // pre-flight errors must display under the flow that caused
        // them, and the status log is gated on this kind.
        self.active_tx_kind = Some(TransactionKind::DaoPrepare);

        let is_mainnet = self.qp_client.is_mainnet();
        let from_address = match crate::utils::lock_args_to_address(&lock_args, is_mainnet) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("Invalid sender address: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Error(msg);
                return;
            }
        };

        let fee_rate: u64 = self.dao_deposit_fee_rate.trim().parse().unwrap_or(1000);

        let account = match self.accounts.iter().find(|a| a.lock_args == lock_args) {
            Some(a) => a,
            None => {
                self.tx_status = TransactionStatus::Error("Account not found.".to_string());
                return;
            }
        };
        let max_witness_lock_size = account.config.max_witness_lock_size();

        tracing::info!("DAO prepare started: wallet_id={}", self.wallet_id);
        self.tx_status = TransactionStatus::Building;
        let qp_client = self.qp_client.clone();
        let node_type = self.qp_client.config().node_type;
        let is_mainnet = self.qp_client.is_mainnet();

        let (tx, rx) = mpsc::channel();
        self.transaction_build_rx = Some(rx);

        std::thread::spawn(move || {
            let result = (|| -> Result<_, String> {
                check_qr_lock_dep_ready(&qp_client, node_type)?;

                let unsigned_tx = ckb_node::QpDaoPrepareBuilder::new(&qp_client, is_mainnet)
                    .with_placeholder_lock_size(max_witness_lock_size)
                    .build_unsigned_dao_request_withdraw(
                        &from_address,
                        vec![deposit_out_point],
                        fee_rate,
                    )
                    .map_err(|e| format!("Failed to build DAO prepare: {}", e))?;

                let input_cells = ckb_node::wallet_helpers::tx_builder::fetch_input_cells(
                    &qp_client,
                    &unsigned_tx,
                )
                .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

                Ok((
                    TransactionKind::DaoPrepare,
                    unsigned_tx,
                    input_cells,
                    lock_args,
                ))
            })();

            let _ = tx.send(result);
        });
    }

    /// Start building a DAO withdraw transaction in a background thread.
    pub(crate) fn dao_withdraw_async(
        &mut self,
        prepared_out_point: ckb_types::packed::OutPoint,
        lock_args: String,
    ) {
        // Claim the tx slot for this screen BEFORE any validation:
        // pre-flight errors must display under the flow that caused
        // them, and the status log is gated on this kind.
        self.active_tx_kind = Some(TransactionKind::DaoWithdraw);

        let is_mainnet = self.qp_client.is_mainnet();
        let from_address = match crate::utils::lock_args_to_address(&lock_args, is_mainnet) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("Invalid sender address: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Error(msg);
                return;
            }
        };

        let fee_rate: u64 = self.dao_deposit_fee_rate.trim().parse().unwrap_or(1000);

        let account = match self.accounts.iter().find(|a| a.lock_args == lock_args) {
            Some(a) => a,
            None => {
                self.tx_status = TransactionStatus::Error("Account not found.".to_string());
                return;
            }
        };
        let max_witness_lock_size = account.config.max_witness_lock_size();

        tracing::info!("DAO withdraw started: wallet_id={}", self.wallet_id);
        self.tx_status = TransactionStatus::Building;
        let qp_client = self.qp_client.clone();
        let node_type = self.qp_client.config().node_type;
        let is_mainnet = self.qp_client.is_mainnet();

        let (tx, rx) = mpsc::channel();
        self.transaction_build_rx = Some(rx);

        std::thread::spawn(move || {
            let result = (|| -> Result<_, String> {
                check_qr_lock_dep_ready(&qp_client, node_type)?;

                let unsigned_tx = ckb_node::QpDaoWithdrawBuilder::new(&qp_client, is_mainnet)
                    .with_placeholder_lock_size(max_witness_lock_size)
                    .build_unsigned_dao_withdraw(&from_address, vec![prepared_out_point], fee_rate)
                    .map_err(|e| format!("Failed to build DAO withdraw: {}", e))?;

                let input_cells = ckb_node::wallet_helpers::tx_builder::fetch_input_cells(
                    &qp_client,
                    &unsigned_tx,
                )
                .map_err(|e| format!("Failed to fetch input cells: {}", e))?;

                Ok((
                    TransactionKind::DaoWithdraw,
                    unsigned_tx,
                    input_cells,
                    lock_args,
                ))
            })();

            let _ = tx.send(result);
        });
    }

    /// Prompt for the wallet password and hand the resulting
    /// `AuthKey::Password` to the sign-and-send core. Synchronous;
    /// blocks the egui update loop while the dialog is up.
    pub(crate) fn sign_and_send_with_password(
        &mut self,
        kind: crate::types::TransactionKind,
        unsigned_tx: ckb_types::core::TransactionView,
        input_cells: Vec<(ckb_types::packed::CellOutput, ckb_types::bytes::Bytes)>,
        lock_args: String,
    ) {
        let pw = match qpv2_core::pinentry::prompt_password(
            "Enter your wallet password to authorize this transaction.",
            "Password:",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Password prompt failed: {}", e);
                self.tx_status = TransactionStatus::Idle;
                self.status = Status::Error(e);
                return;
            }
        };
        self.sign_and_send(
            kind,
            AuthKey::Password(pw),
            unsigned_tx,
            input_cells,
            lock_args,
        );
    }

    /// Retrieve the key from the platform credential store and sign.
    pub(crate) fn sign_and_send_with_keychain(
        &mut self,
        kind: TransactionKind,
        unsigned_tx: ckb_types::core::TransactionView,
        input_cells: Vec<(ckb_types::packed::CellOutput, ckb_types::bytes::Bytes)>,
        lock_args: String,
    ) {
        let key = match keychain::retrieve_key(self.wallet_id) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Keychain retrieval failed: {}", e);
                self.tx_status = TransactionStatus::Idle;
                self.status = Status::Error(e);
                return;
            }
        };
        self.sign_and_send(
            kind,
            AuthKey::CryptoKey(key),
            unsigned_tx,
            input_cells,
            lock_args,
        );
    }

    /// Retrieve the vault key from a FIDO2 device and sign.
    pub(crate) fn sign_and_send_with_fido2(
        &mut self,
        credential_id: &str,
        kind: TransactionKind,
        unsigned_tx: ckb_types::core::TransactionView,
        input_cells: Vec<(ckb_types::packed::CellOutput, ckb_types::bytes::Bytes)>,
        lock_args: String,
    ) {
        let cred_bytes = match hex::decode(credential_id) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("Invalid credential ID: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Idle;
                self.status = Status::Error(msg);
                return;
            }
        };

        let pin = match qpv2_core::pinentry::prompt_password(
            "Enter your FIDO2 security key PIN to sign this transaction.",
            "PIN:",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FIDO2 PIN prompt failed: {}", e);
                self.tx_status = TransactionStatus::Idle;
                self.status = Status::Error(e);
                return;
            }
        };

        let hmac_output = match keychain::fido2::authenticate(&cred_bytes, &pin) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("FIDO2 authentication failed: {}", e);
                self.tx_status = TransactionStatus::Idle;
                self.status = Status::Error(e);
                return;
            }
        };

        let key = match qpv2_core::utilities::derive_vault_enc_key(&hmac_output) {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Key derivation failed: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Idle;
                self.status = Status::Error(msg);
                return;
            }
        };

        self.sign_and_send(
            kind,
            AuthKey::CryptoKey(key),
            unsigned_tx,
            input_cells,
            lock_args,
        );
    }

    /// Sign a transaction with a Trezor device and broadcast it.
    ///
    /// Unlike the software paths, the device recomputes the signing message
    /// itself, so `input_cells` is unused here; instead the full previous
    /// transactions are streamed to the device for its trustless capacity
    /// check. The whole round-trip (fetch previous txs, on-device confirmation
    /// and signing, broadcast) runs on a worker thread so the UI stays
    /// responsive while the user confirms on the device. This handles single-sig
    /// accounts only, since the firmware cannot co-sign a multisig group.
    pub(crate) fn sign_and_send_with_trezor(
        &mut self,
        kind: TransactionKind,
        unsigned_tx: ckb_types::core::TransactionView,
        _input_cells: Vec<(ckb_types::packed::CellOutput, ckb_types::bytes::Bytes)>,
        lock_args: String,
    ) {
        let account = match self.accounts.iter().find(|a| a.lock_args == lock_args) {
            Some(a) => a.clone(),
            None => {
                self.tx_status = TransactionStatus::Error("Account not found.".to_string());
                return;
            }
        };

        if !account.config.is_single_sig() {
            self.tx_status = TransactionStatus::Error(
                "Signing a multisig transaction on a Trezor is not supported yet.".to_string(),
            );
            return;
        }

        let variant = account.config.signers[0].variant;
        let account_index = account.index;
        let signing_lock_size = account.config.max_witness_lock_size();
        let is_mainnet = self.qp_client.is_mainnet();
        let qp_client = self.qp_client.clone();

        tracing::info!(
            "Trezor signing initiated: account_index={}, variant={:?}",
            account_index,
            variant
        );

        // Poller set AwaitingSignature; the worker does fetch → sign → send and
        // reports over the shared send channel, finalized by poll_transaction_send.
        let (tx_send, rx_send) = mpsc::channel();
        self.transaction_send_rx = Some(rx_send);

        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                let sign_group: Vec<u32> =
                    (0..unsigned_tx.inputs().len() as u32).collect();

                let prev_txs =
                    ckb_node::wallet_helpers::tx_builder::fetch_prev_txs(&qp_client, &unsigned_tx)
                        .map_err(|e| format!("Failed to fetch previous transactions: {}", e))?;

                let mut device = trezor_signer::open()
                    .map_err(|e| format!("Could not connect to Trezor: {}", e))?;

                let signed = device
                    .sign_tx(
                        account_index,
                        variant,
                        is_mainnet,
                        &unsigned_tx,
                        signing_lock_size,
                        &prev_txs,
                        &sign_group,
                    )
                    .map_err(|e| format!("Trezor signing failed: {}", e))?;

                let signed_tx = ckb_node::fill_witness(unsigned_tx, 0, signed.witness_lock)
                    .map_err(|e| format!("Failed to fill witness: {}", e))?;

                ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
                    .map(|hash| format!("{:#x}", hash))
                    .map_err(|e| format!("Failed to send transaction: {}", e))
            })();
            let _ = tx_send.send((kind, result));
        });
    }

    /// Auth-mechanism-agnostic signing core. Computes the CKB tx-message
    /// hash, then branches:
    /// - **Single-sig**: signs, fills witness, and broadcasts in one shot.
    /// - **Multisig**: signs locally (one of M), builds a `SigningRequest`,
    ///   and transitions to `AwaitingCoSigners` so the user can export the
    ///   request and import co-signer responses.
    pub(crate) fn sign_and_send(
        &mut self,
        kind: TransactionKind,
        auth: qpv2_core::types::AuthKey,
        unsigned_tx: ckb_types::core::TransactionView,
        input_cells: Vec<(ckb_types::packed::CellOutput, ckb_types::bytes::Bytes)>,
        lock_args: String,
    ) {
        let account = match self.accounts.iter().find(|a| a.lock_args == lock_args) {
            Some(a) => a.clone(),
            None => {
                self.tx_status = TransactionStatus::Error("Account not found.".to_string());
                return;
            }
        };

        let variant = match KeyVault::get_spx_variant(self.wallet_id) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Failed to read variant: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Error(msg);
                return;
            }
        };

        tracing::info!(
            "Signing initiated: variant={:?}, wallet_id={}",
            variant,
            self.wallet_id
        );

        let message = match ckb_node::compute_signing_message(&unsigned_tx, &input_cells, 0) {
            Ok(m) => m,
            Err(e) => {
                let msg = format!("Failed to compute tx message: {}", e);
                tracing::error!("{}", msg);
                self.tx_status = TransactionStatus::Error(msg);
                return;
            }
        };

        if account.config.is_single_sig() {
            // ── Single-sig fast path: sign, fill, send ──
            let vault = KeyVault::new(variant, self.wallet_id);
            let signature_bytes = match vault.ckb_sign(auth, lock_args, message.to_vec()) {
                Ok(sig) => sig,
                Err(e) => {
                    let msg = format!("Signing failed: {}", e);
                    tracing::error!("{}", msg);
                    self.tx_status = TransactionStatus::Error(msg);
                    return;
                }
            };

            let signed_tx = match ckb_node::fill_witness(unsigned_tx, 0, signature_bytes) {
                Ok(tx) => tx,
                Err(e) => {
                    let msg = format!("Failed to fill witness: {}", e);
                    tracing::error!("{}", msg);
                    self.tx_status = TransactionStatus::Error(msg);
                    return;
                }
            };

            tracing::info!("Transaction signed successfully, sending to network.");
            self.tx_status = TransactionStatus::Sending;
            let qp_client = self.qp_client.clone();
            let (tx_send, rx_send) = mpsc::channel();
            self.transaction_send_rx = Some(rx_send);

            std::thread::spawn(move || {
                let result =
                    ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
                        .map(|hash| format!("{:#x}", hash))
                        .map_err(|e| format!("Failed to send transaction: {}", e));
                let _ = tx_send.send((kind, result));
            });
        } else {
            // ── Multisig path: sign locally, then wait for co-signers ──
            let vault = KeyVault::new(variant, self.wallet_id);

            let local_lock_args = match &account.initiating_signer_lock_args {
                Some(la) => la.clone(),
                None => {
                    self.tx_status = TransactionStatus::Error(
                        "Multisig account has no local signer recorded.".to_string(),
                    );
                    return;
                }
            };

            let (raw_sig, _pubkey) = match vault.raw_sign(auth, local_lock_args, message.to_vec()) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("Signing failed: {}", e);
                    tracing::error!("{}", msg);
                    self.tx_status = TransactionStatus::Error(msg);
                    return;
                }
            };

            let signer_index = match account
                .config
                .signers
                .iter()
                .position(|s| s.pubkey == _pubkey && s.variant == variant)
            {
                Some(i) => i,
                None => {
                    self.tx_status = TransactionStatus::Error(
                        "Local signer pubkey not found in multisig config.".to_string(),
                    );
                    return;
                }
            };

            let is_mainnet = self.qp_client.is_mainnet();
            let from_addr = crate::utils::lock_args_to_address(&lock_args, is_mainnet)
                .map(|a| a.to_string())
                .unwrap_or_else(|_| format!("0x{}", &lock_args));

            let request = match ckb_node::build_signing_request(
                &unsigned_tx,
                &input_cells,
                &account.config,
                0,
                is_mainnet,
                qpv2_core::types::SigningMetadata {
                    from_address: from_addr,
                    to_address: None,
                    amount_ckb: None,
                    tx_type: kind.label().to_string(),
                },
            ) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("Failed to build signing request: {}", e);
                    tracing::error!("{}", msg);
                    self.tx_status = TransactionStatus::Error(msg);
                    return;
                }
            };

            tracing::info!(
                "Multisig: local signer {} signed, awaiting {} more signature(s).",
                signer_index,
                account.config.threshold as usize - 1
            );

            self.tx_status = TransactionStatus::AwaitingCoSigners {
                kind,
                request: Box::new(request),
                unsigned_tx,
                signatures: vec![(signer_index, raw_sig)],
                import_response_json: String::new(),
            };
        }
    }

    /// Assemble the collected multisig signatures and broadcast.
    /// Called from the co-signer coordination UI when M signatures are collected.
    pub(crate) fn submit_multisig_transaction(&mut self) {
        let (kind, request, unsigned_tx, signatures) =
            match std::mem::replace(&mut self.tx_status, TransactionStatus::Idle) {
                TransactionStatus::AwaitingCoSigners {
                    kind,
                    request,
                    unsigned_tx,
                    signatures,
                    ..
                } => (kind, request, unsigned_tx, signatures),
                other => {
                    self.tx_status = other;
                    return;
                }
            };

        let witness_lock =
            match ckb_node::assemble_multisig_witness(&request.multisig_config, &signatures) {
                Ok(w) => w,
                Err(e) => {
                    let msg = format!("Failed to assemble witness: {}", e);
                    tracing::error!("{}", msg);
                    self.tx_status = TransactionStatus::Error(msg);
                    return;
                }
            };

        let signed_tx =
            match ckb_node::fill_witness(unsigned_tx, request.script_group_index, witness_lock) {
                Ok(tx) => tx,
                Err(e) => {
                    let msg = format!("Failed to fill witness: {}", e);
                    tracing::error!("{}", msg);
                    self.tx_status = TransactionStatus::Error(msg);
                    return;
                }
            };

        tracing::info!("Multisig transaction assembled, sending to network.");
        self.tx_status = TransactionStatus::Sending;
        let qp_client = self.qp_client.clone();
        let (tx_send, rx_send) = mpsc::channel();
        self.transaction_send_rx = Some(rx_send);

        std::thread::spawn(move || {
            let result =
                ckb_node::wallet_helpers::tx_builder::send_transaction(&qp_client, &signed_tx)
                    .map(|hash| format!("{:#x}", hash))
                    .map_err(|e| format!("Failed to send transaction: {}", e));
            let _ = tx_send.send((kind, result));
        });
    }
}
