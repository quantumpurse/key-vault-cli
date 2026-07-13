//! Async polling for background operations (balances, transactions).

use crate::types::{
    BalanceResult, DaoQueryEvent, Status, TransactionKind, TransactionStatus, TxHistoryEvent,
    TxKind,
};
use crate::App;
use std::sync::mpsc;

impl App {
    /// Poll the transaction from channel and trigger signing on success.
    pub(crate) fn poll_transaction_build(&mut self) {
        let rx = match &self.transaction_build_rx {
            Some(rx) => rx,
            None => return,
        };

        match rx.try_recv() {
            Ok(Ok((kind, unsigned_tx, input_cells, lock_args))) => {
                self.transaction_build_rx = None;

                use qpv2_core::types::AuthMethod;
                self.tx_status = TransactionStatus::AwaitingSignature;
                match &self.auth_method {
                    Some(AuthMethod::Password) => {
                        self.sign_and_send_with_password(kind, unsigned_tx, input_cells, lock_args);
                    }
                    Some(AuthMethod::Keychain) => {
                        self.sign_and_send_with_keychain(kind, unsigned_tx, input_cells, lock_args);
                    }
                    Some(AuthMethod::Fido2 { credential_id }) => {
                        let cred_id = credential_id.clone();
                        self.sign_and_send_with_fido2(
                            &cred_id,
                            kind,
                            unsigned_tx,
                            input_cells,
                            lock_args,
                        );
                    }
                    Some(AuthMethod::Trezor { .. }) => {
                        self.sign_and_send_with_trezor(kind, unsigned_tx, input_cells, lock_args);
                    }
                    None => {
                        tracing::error!("No authentication method set.");
                        self.tx_status =
                            TransactionStatus::Error("No authentication method set.".to_string());
                    }
                }
            }
            Ok(Err(e)) => {
                self.transaction_build_rx = None;
                tracing::error!("Transaction build failed: {}", e);
                self.tx_status = TransactionStatus::Error(e);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.transaction_build_rx = None;
                if matches!(self.tx_status, TransactionStatus::Building) {
                    tracing::error!("Build thread terminated unexpectedly.");
                    self.tx_status = TransactionStatus::Error(
                        "Build thread terminated unexpectedly.".to_string(),
                    );
                }
            }
        }
    }

    /// Poll the shared transaction send channel and dispatch follow-up work by kind.
    pub(crate) fn poll_transaction_send(&mut self) {
        let rx = match &self.transaction_send_rx {
            Some(rx) => rx,
            None => return,
        };

        match rx.try_recv() {
            Ok((kind, Ok(tx_hash))) => {
                self.transaction_send_rx = None;
                let hash = tx_hash.trim_start_matches("0x").to_string();
                self.tx_status = TransactionStatus::Success(hash);

                match kind {
                    TransactionKind::Transfer => {
                        self.transfer_recipient.clear();
                        self.transfer_amount.clear();
                        self.transfer_all = false;
                    }
                    TransactionKind::DaoDeposit
                    | TransactionKind::DaoPrepare
                    | TransactionKind::DaoWithdraw => {
                        self.dao_deposit_amount.clear();
                        self.dao_deposit_all = false;
                    }
                }
            }
            Ok((_, Err(e))) => {
                self.transaction_send_rx = None;
                tracing::error!("Transaction send failed: {}", e);
                self.tx_status = TransactionStatus::Error(e);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.transaction_send_rx = None;
                if matches!(self.tx_status, TransactionStatus::Sending) {
                    tracing::error!("Send thread terminated unexpectedly.");
                    self.tx_status = TransactionStatus::Error(
                        "Send thread terminated unexpectedly.".to_string(),
                    );
                }
            }
        }
    }

    /// Drain available balance results from the background thread.
    pub(crate) fn poll_all_balances(&mut self) {
        let rx = match &self.balance_receiver {
            Some(rx) => rx,
            None => return,
        };

        // Drain the channel buffer into a local batch first, so the immutable
        // borrow of `self.balance_receiver` ends before we mutate `self` below.
        let mut batch: Vec<BalanceResult> = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(result) => batch.push(result),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Background thread finished; drop the receiver.
                    self.balance_receiver = None;
                    break;
                }
            }
        }

        for (lock_args, total, spendable) in batch {
            // Update each cache only on success. On a transient RPC error,
            // leave the previous value untouched.
            match total {
                Ok(t) => {
                    self.balances.insert(lock_args.clone(), Some(t));
                }
                Err(e) => self.report_balance_error(&e),
            }
            match spendable {
                Ok(s) => {
                    self.spendable_balances.insert(lock_args, Some(s));
                }
                Err(e) => self.report_balance_error(&e),
            }
        }
    }

    /// Log a balance-fetch error, surfacing it in the UI only when it is not a
    /// transient HTTP error. Transient HTTP errors are expected when the local
    /// RPC node is momentarily busy (light client compaction, full node sync
    /// bursts), so logging them to file avoids noisy false alarms.
    fn report_balance_error(&mut self, e: &str) {
        let msg = format!("Failed to fetch balance: {}", e);
        tracing::error!("{}", msg);
        if !e.contains("http error") {
            self.status = Status::Error(msg);
        }
    }

    /// Poll the DAO cell query channel.
    pub(crate) fn poll_dao_cells(&mut self) {
        let rx = match &self.dao_cells_query_rx {
            Some(rx) => rx,
            None => return,
        };

        // Drain all available DAO query events from the channel buffer.
        loop {
            match rx.try_recv() {
                Ok(Ok(DaoQueryEvent::Deposited(lock_args, cell))) => {
                    self.dao_deposited_staging.push((lock_args, cell));
                }
                Ok(Ok(DaoQueryEvent::Prepared(lock_args, cell))) => {
                    self.dao_prepared_staging.push((lock_args, cell));
                }
                Ok(Ok(DaoQueryEvent::Done)) => {
                    // Sort newest block first so rows keep their position across
                    // refreshes (the indexer doesn't guarantee a stable return order).
                    // out_point bytes break ties if two cells share a block.
                    use ckb_types::prelude::Entity;
                    self.dao_deposited_staging.sort_by(|(_, a), (_, b)| {
                        b.block_number
                            .cmp(&a.block_number)
                            .then_with(|| a.out_point.as_slice().cmp(b.out_point.as_slice()))
                    });
                    self.dao_prepared_staging.sort_by(|(_, a), (_, b)| {
                        b.prepare_header
                            .number()
                            .cmp(&a.prepare_header.number())
                            .then_with(|| a.out_point.as_slice().cmp(b.out_point.as_slice()))
                    });

                    // Atomic swap: replace display vectors with complete staging data.
                    std::mem::swap(
                        &mut self.dao_deposited_cells,
                        &mut self.dao_deposited_staging,
                    );
                    std::mem::swap(&mut self.dao_prepared_cells, &mut self.dao_prepared_staging);
                    self.dao_cells_query_rx = None;

                    // Fetch deposit block headers we haven't cached yet.
                    self.fetch_deposit_headers();
                    break;
                }
                Ok(Err(e)) => {
                    self.dao_cells_query_rx = None;
                    // Transient HTTP errors are expected when the local RPC node is
                    // momentarily busy (light client compaction, full node sync bursts).
                    // Log to file but don't surface in the UI to avoid noisy false alarms.
                    tracing::error!("{}", e);
                    if !e.contains("http error") {
                        self.status = Status::Error(e);
                    }
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.dao_cells_query_rx = None;
                    break;
                }
            }
        }
    }

    /// Poll the deposit headers channel and merge into the cache.
    pub(crate) fn poll_deposit_headers(&mut self) {
        let rx = match &self.deposit_headers_rx {
            Some(rx) => rx,
            None => return,
        };

        match rx.try_recv() {
            Ok(headers) => {
                self.deposit_headers.extend(headers);
                self.deposit_headers_rx = None;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.deposit_headers_rx = None;
            }
        }
    }

    /// Poll the transaction history channel.
    pub(crate) fn poll_tx_history(&mut self) {
        let rx = match &self.tx_history_rx {
            Some(rx) => rx,
            None => return,
        };

        loop {
            match rx.try_recv() {
                Ok(Ok(TxHistoryEvent::Record(record))) => {
                    // Live display: a re-fetched provisional row
                    // replaces its old copy in place instead of showing
                    // twice while the sync streams. The batch keeps the
                    // authoritative set for the reconcile below.
                    match self
                        .tx_history
                        .iter_mut()
                        .find(|r| r.tx_hash == record.tx_hash)
                    {
                        Some(row) => *row = record.clone(),
                        None => self.tx_history.push(record.clone()),
                    }
                    self.unconfirmed_tx_records.push(record);
                }
                Ok(Ok(TxHistoryEvent::Done)) => {
                    self.tx_history_rx = None;
                    let tip = self.node_status.tip_block().unwrap_or(0);
                    let watermark = self.confirmed_watermark;

                    // Reconcile the provisional window (records above
                    // the watermark): the batch just re-fetched it
                    // from the chain, so the batch replaces it — a
                    // reorg-moved tx comes back at its new block, a
                    // reorged-away tx simply doesn't come back. Kept
                    // from the old vector: final records at or below
                    // the watermark, and pending rows the indexer can't
                    // return yet (unless the batch superseded them).
                    let batch = std::mem::take(&mut self.unconfirmed_tx_records);
                    let batch_hashes: std::collections::HashSet<String> =
                        batch.iter().map(|r| r.tx_hash.clone()).collect();
                    self.tx_history.retain(|r| {
                        !batch_hashes.contains(&r.tx_hash)
                            && (r.block_number <= watermark || r.is_pending)
                    });
                    self.tx_history.extend(batch);

                    // Sort newest-first and de-duplicate by tx hash.
                    // Each fetch batch arrives sorted, but incremental
                    // syncs append to the existing vector — without this
                    // pass, [old-newest, ..., old-oldest, new-newest,
                    // ..., new-oldest] would render in the wrong order.
                    // Secondary key tx_hash so same-hash records from
                    // different accounts are adjacent even when several
                    // txs share a block.
                    self.tx_history.sort_by(|a, b| {
                        b.block_number
                            .cmp(&a.block_number)
                            .then_with(|| a.tx_hash.cmp(&b.tx_hash))
                    });
                    // Merge same-hash records instead of dropping them:
                    // a tx paying several wallet accounts yields one
                    // record per account, each carrying only that
                    // account's portion — plain dedup under-reported
                    // the amount. External incoming portions sum; for
                    // other kinds (internal pairs, outgoing — whose
                    // amount already covers the whole tx) the first
                    // record stands.
                    self.tx_history.dedup_by(|dup, keep| {
                        if dup.tx_hash != keep.tx_hash {
                            return false;
                        }
                        if keep.tx_kind == TxKind::Incoming
                            && dup.tx_kind == TxKind::Incoming
                            && keep.internal_counterparty_lock_args.is_none()
                            && dup.internal_counterparty_lock_args.is_none()
                        {
                            keep.amount = keep.amount.saturating_add(dup.amount);
                        }
                        true
                    });

                    // Persist only final records — once written they
                    // are never edited or re-checked; the provisional
                    // window above them is rebuilt from the chain on
                    // every sync. Rows at or below the watermark are
                    // already on disk — they re-enter untouched. A
                    // write failure is non-fatal: the watermark stays
                    // put, so unsaved records are re-fetched next sync.
                    let store = crate::tx_history::TxHistoryStore {
                        records: self
                            .tx_history
                            .iter()
                            .filter(|r| {
                                (!r.is_pending && r.block_number <= watermark)
                                    || r.is_confirmed(tip)
                            })
                            .cloned()
                            .collect(),
                    };
                    // Skip the write when nothing crossed the
                    // confirmation depth since the last save: rows at or
                    // below the file floor are on disk already, so the
                    // rewrite would be byte-identical — and syncs
                    // complete every second.
                    let has_new_confirmed = store
                        .records
                        .iter()
                        .any(|r| r.block_number > self.confirmed_watermark);
                    if has_new_confirmed {
                        match store.save(self.wallet_id, self.qp_client.network().tag()) {
                            Ok(()) => {
                                self.confirmed_watermark = store
                                    .records
                                    .iter()
                                    .map(|r| r.block_number)
                                    .max()
                                    .unwrap_or(0)
                                    .max(self.confirmed_watermark);
                            }
                            Err(e) => tracing::error!("tx_history: failed to persist: {}", e),
                        }
                    }
                    break;
                }
                Ok(Ok(TxHistoryEvent::Aborted)) => {
                    self.tx_history_rx = None;
                    self.rollback_tx_history();
                    break;
                }
                Ok(Err(e)) => {
                    // Transient HTTP errors are expected when the local RPC node is
                    // momentarily busy (light client compaction, full node sync bursts).
                    // Log to file but don't surface in the UI to avoid noisy false alarms.
                    tracing::error!("tx_history: {}", e);
                    if !e.contains("http error") {
                        self.status = Status::Error(e);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // The sync thread died without a terminal event
                    // (panic); its partial batch is as unsafe as an
                    // aborted one.
                    self.tx_history_rx = None;
                    self.rollback_tx_history();
                    break;
                }
            }
        }
    }

    /// Restores `tx_history` to the last saved snapshot, discarding
    /// records streamed by a sync that didn't finish. A history sync
    /// emits newest-first, so a partial batch holds the newest records
    /// only — the watermark derived from it would sit above the older
    /// transactions that were never emitted, and the next incremental
    /// sync would skip them for good. Disk is written only on `Done`,
    /// so it is always a consistent baseline.
    fn rollback_tx_history(&mut self) {
        // so polling in the next frame doesn't see the stale records.
        self.unconfirmed_tx_records.clear();
        self.tx_history =
            crate::tx_history::TxHistoryStore::load(self.wallet_id, self.qp_client.network().tag())
                .unwrap_or_else(|e| {
                    tracing::error!("tx_history: rollback failed to load snapshot: {}", e);
                    None
                })
                .map(|store| store.records)
                .unwrap_or_default();
        self.confirmed_watermark = self
            .tx_history
            .iter()
            .filter(|r| !r.is_pending)
            .map(|r| r.block_number)
            .max()
            .unwrap_or(0);
        tracing::warn!(
            "tx_history: sync did not finish; rolled back to {} saved records",
            self.tx_history.len()
        );
    }

    /// Drain the node-status channel into `self.node_status`. A status
    /// refresh is scheduled every `POLL_INTERVAL` by `update()`.
    ///
    /// Also acts as the local-node watchdog: when the slot is occupied
    /// (`has_local_process()`) but the child has exited on its own
    /// (`!is_alive()`), surface the failure as a `Status::Error`
    /// banner. Replaces the synchronous early-exit check that used to
    /// live in `wait_for_rpc` — same coverage, just one tick of poll
    /// latency.
    pub(crate) fn poll_node_status(&mut self) {
        if self.local_node.has_local_process() && !self.local_node.is_alive() {
            tracing::error!("Local node exited unexpectedly. See node.log in the data dir.");
            self.status = Status::Error(
                "Local node exited unexpectedly. See node.log in the data dir.".to_string(),
            );
            // Clear the slot so the status pill reflects reality and
            // the user can retry the spawn from the node selector.
            self.local_node.stop();
        }

        if let Some(t) = self.node_status_reconnected_at {
            if t.elapsed() >= std::time::Duration::from_secs(3) {
                self.node_status_reconnected_at = None;
            }
        }

        let rx = match &self.node_status_rx {
            Some(rx) => rx,
            None => return,
        };

        match rx.try_recv() {
            Ok(Ok(status)) => {
                let was_offline = !self.node_status.online;
                if was_offline && status.online {
                    self.node_status_reconnected_at = Some(std::time::Instant::now());
                }
                if !status.online {
                    self.node_status_reconnected_at = None;
                }
                self.node_status = status;
                self.node_status_rx = None;
            }
            Ok(Err(e)) => {
                self.node_status_rx = None;
                tracing::error!("node status: {}", e);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.node_status_rx = None;
            }
        }

        // QR-lock-script cell-dep warmup. Used to run synchronously
        // right after `LocalNodeProcess::spawn()` in App::new and the
        // node-selector apply handler — but with `wait_for_rpc` gone,
        // those calls raced ahead of the LC's `bind()` and surfaced as
        // "Failed to request lock-script cell dep fetch" on the lock
        // screen. Doing it here gates the call on `online == true`,
        // which is exactly the signal we needed.
        //
        // Idempotent locally (`fetch_transaction` is a memoized
        // localhost roundtrip after the first hit), so the worst case
        // is one cheap RPC per ~10 s tick until `Ok(true)` latches the
        // flag. Errors are logged, not banner'd — by definition we'll
        // try again next tick.
        if self.node_status.online
            && self.qp_client.config().node_type == ckb_node::NodeType::LightClient
        {
            if !self.lc_qr_dep_warmup_done {
                match ckb_node::wallet_helpers::lc::fetch_qr_lock_dep(&self.qp_client) {
                    Ok(true) => self.lc_qr_dep_warmup_done = true,
                    Ok(false) => {} // pending — retry next tick
                    Err(e) => tracing::error!("lc warmup: fetch_qr_lock_dep: {}", e),
                }
            }

            // Register all accounts' lock scripts with the LC once it
            // is online. Covers the case where accounts were created on
            // a different backend and the user then switches to LC.
            // Anchored at the min synced block of existing scripts so
            // new accounts don't skip history; falls back to 0 when no
            // scripts are tracked yet (fresh LC after remove+recreate).
            if !self.lc_scripts_registered && !self.accounts.is_empty() {
                let lock_args: Vec<String> =
                    self.accounts.iter().map(|a| a.lock_args.clone()).collect();
                let start_block = self.qp_client.synced_block().ok().flatten().unwrap_or(0);
                match ckb_node::wallet_helpers::lc::register_lock_scripts(
                    &self.qp_client,
                    &lock_args,
                    start_block,
                ) {
                    Ok(()) => self.lc_scripts_registered = true,
                    Err(e) => tracing::error!("lc warmup: register_lock_scripts: {}", e),
                }
            }
        }
    }

    /// Pick up the result of a `detect_earliest_funding_block_async`
    /// call. On success, write the discovered block (minus 1 — see
    /// `FullNodeClient::find_earliest_funding_block` doc) into
    /// `set_block_input` so the user can review and click Set. We do
    /// **not** auto-submit (option B from the design discussion).
    pub(crate) fn poll_earliest_funding_block(&mut self) {
        let rx = match &self.earliest_funding_block_rx {
            Some(rx) => rx,
            None => return,
        };

        match rx.try_recv() {
            Ok(Ok(Some(earliest))) => {
                // off-by-one: LC's stored block_number means "filtered up
                // to AND INCLUDING N", sync resumes at N+1. To capture
                // the tx at `earliest`, register at `earliest - 1`.
                let target = earliest.saturating_sub(1);
                self.set_block_input = target.to_string();
                self.set_block_editing = true;
                self.status = Status::Info(format!(
                    "Earliest funding at block {}. Pre-filled {} (off-by-one). Review and click Set.",
                    earliest, target
                ));
                self.earliest_funding_block_rx = None;
            }
            Ok(Ok(None)) => {
                self.status = Status::Info("No funding history found.".to_string());
                self.earliest_funding_block_rx = None;
            }
            Ok(Err(e)) => {
                let msg = format!("Auto-detect failed: {}", e);
                // Transient HTTP errors are expected when the local RPC node is
                // momentarily busy (light client compaction, full node sync bursts).
                // Log to file but don't surface in the UI to avoid noisy false alarms.
                tracing::error!("{}", msg);
                if !e.contains("http error") {
                    self.status = Status::Error(msg);
                }
                self.earliest_funding_block_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.earliest_funding_block_rx = None;
            }
        }
    }

    /// Pick up a freshly built QR-lock adoption series. Failures are
    /// logged and rescheduled on the short retry cadence so a transient
    /// public-RPC error doesn't strand the UI in "Querying..." for the
    /// full refresh interval.
    pub(crate) fn poll_qr_adoption(&mut self) {
        let rx = match &self.qr_adoption_rx {
            Some(rx) => rx,
            None => return,
        };
        match rx.try_recv() {
            Ok(Ok(series)) => {
                self.qr_adoption_rx = None;
                crate::qr_adoption::save_series(self.qp_client.network().tag(), &series);
                self.qr_adoption_series = series;
            }
            Ok(Err(e)) => {
                self.qr_adoption_rx = None;
                tracing::error!("qr adoption: fetch: {}", e);
                self.qr_adoption_next_fetch =
                    Some(std::time::Instant::now() + crate::QR_ADOPTION_RETRY);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.qr_adoption_rx = None;
                self.qr_adoption_next_fetch =
                    Some(std::time::Instant::now() + crate::QR_ADOPTION_RETRY);
            }
        }
    }
}
