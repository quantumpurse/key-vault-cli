//! Wallet lifecycle: create, unlock, lock, new account, config.

use qpv2_core::types::{AuthKey, AuthMethod, SingleSigConvention, SpxVariant};
use qpv2_core::KeyVault;

use crate::tx_history::TxHistoryStore;
use crate::types::{CurrentWallet, Screen, Status, TransactionStatus};
use crate::App;

impl App {
    /// Build the wallet cache from disk. Called as an associated function
    /// during `App::new` (before `self` exists) and as a method thereafter.
    pub(crate) fn current_wallet_cache() -> Vec<CurrentWallet> {
        let wallets = KeyVault::list_wallets().unwrap_or_default();
        wallets
            .into_iter()
            .filter_map(|entry| {
                let info = KeyVault::read_wallet_info(entry.id).ok()?;
                let account_count = KeyVault::get_all_lock_args(entry.id)
                    .map(|a| a.len())
                    .unwrap_or(0);
                let path = qpv2_core::db::get_wallet_dir(entry.id)
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                Some(CurrentWallet {
                    id: entry.id,
                    name: entry.name,
                    spx_variant: info.spx_variant,
                    auth_method: info.auth_method,
                    single_sig_convention: info.single_sig_convention,
                    account_count,
                    path,
                })
            })
            .collect()
    }

    /// Refresh the in-memory wallet cache from disk.
    pub(crate) fn refresh_wallet_cache(&mut self) {
        self.wallet_cache = Self::current_wallet_cache();
    }

    /// Tells the running light client to start indexing the given
    /// accounts from the current tip onward, in a single `set_scripts`
    /// RPC call. No-op when the backend isn't LightClient, no local
    /// process is running, or the input is empty — full nodes / public
    /// RPC index everything by default, and a stopped light client has
    /// nothing to register against.
    ///
    /// Import-existing-wallet (register every account with an earlier
    /// start block per account) is deliberately not covered here; that
    /// flow isn't implemented yet.
    pub(crate) fn register_lock_scripts_with_light_client(&mut self, lock_args_list: &[String]) {
        if self.qp_client.config().node_type != ckb_node::NodeType::LightClient
            || !self.local_node.has_local_process()
            || lock_args_list.is_empty()
        {
            return;
        }
        let start_block = match self.qp_client.get_tip_header() {
            Ok(h) => h.inner.number.value(),
            Err(e) => {
                let msg = format!("Failed to get tip header: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };
        if let Err(e) = ckb_node::wallet_helpers::lc::register_lock_scripts(
            &self.qp_client,
            lock_args_list,
            start_block,
        ) {
            let msg = format!("Failed to register scripts: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
        }
    }

    /// Common transition from Setup to Unlocked after successful wallet
    /// creation or import. Loads accounts, registers LC scripts, sets
    /// the screen, and kicks off all background fetches.
    fn finalize_wallet_setup(
        &mut self,
        auth_method: AuthMethod,
        success_msg: &str,
        wallet_id: u32,
        wallet_name: String,
    ) {
        // Same wipe as `switch_wallet`: creating or importing switches
        // the active wallet too, and the previous wallet's runtime state
        // (balance maps, DAO caches, in-flight receivers) would
        // otherwise bleed into the new wallet's dashboard.
        self.clear_wallet_state();
        self.wallet_id = wallet_id;
        self.wallet_name = wallet_name;
        match KeyVault::get_all_accounts(self.wallet_id) {
            Ok(accounts) => {
                self.accounts = accounts;
                self.auth_method = Some(auth_method);
                let lock_args: Vec<String> =
                    self.accounts.iter().map(|a| a.lock_args.clone()).collect();
                self.register_lock_scripts_with_light_client(&lock_args);
                self.screen = Screen::Unlocked;
                self.status = Status::Info(success_msg.to_string());
                self.last_poll_time = std::time::Instant::now();
                self.new_wallet_name.clear();
                self.wallet_selector_open = false;
                save_last_wallet_id(self.wallet_id);
                self.refresh_wallet_cache();
                self.load_tx_history_from_disk();
                self.fetch_all_balances();
                self.fetch_tx_history(true);
                self.fetch_dao_cells();
                self.fetch_node_status();
                tracing::info!("Wallet setup finalized (wallet_id={})", self.wallet_id);
            }
            Err(e) => {
                let msg = format!("Failed to read accounts: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                self.auth_method = Some(auth_method);
            }
        }
    }

    /// Kicks off a background detection of the earliest funding block
    /// across all accounts via an ad-hoc `FullNodeClient` against the
    /// public RPC endpoint for the active network. Result lands in
    /// `earliest_funding_block_rx`; the poller writes it into
    /// `set_block_input`. No-op when accounts is empty or another
    /// detection is already in flight.
    pub(crate) fn detect_earliest_funding_block_async(&mut self) {
        if self.earliest_funding_block_rx.is_some() || self.accounts.is_empty() {
            return;
        }

        let network = self.qp_client.network();
        // Always use the network's public RPC — even if the active
        // backend is already PublicRpc, building a fresh client keeps
        // this a self-contained one-shot.
        let public_rpc_url =
            ckb_node::NodeConfig::default_rpc_url_for(ckb_node::NodeType::PublicRpc, network)
                .to_string();
        let lock_args: Vec<String> = self.accounts.iter().map(|a| a.lock_args.clone()).collect();

        let (tx, rx) = std::sync::mpsc::channel();
        self.earliest_funding_block_rx = Some(rx);

        std::thread::spawn(move || {
            let pub_rpc_client = ckb_node::client::FullNodeClient::new(&public_rpc_url);
            let result = pub_rpc_client
                .find_earliest_funding_block(&lock_args, network)
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    /// Manual override: force the running light client to start scanning
    /// every account from `start_block`. Bypasses the cursor-preservation
    /// filter — use only from a UI control where the user explicitly
    /// asked for it. No-op outside LightClient or with no local process.
    pub(crate) fn set_all_accounts_lock_script_block(&mut self, start_block: u64) {
        if self.qp_client.config().node_type != ckb_node::NodeType::LightClient
            || !self.local_node.has_local_process()
            || self.accounts.is_empty()
        {
            return;
        }
        let lock_args: Vec<String> = self.accounts.iter().map(|a| a.lock_args.clone()).collect();
        if let Err(e) = ckb_node::wallet_helpers::lc::register_all_lock_scripts(
            &self.qp_client,
            &lock_args,
            start_block,
        ) {
            let msg = format!("Failed to set scan block: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
        } else {
            // Reflect the new value in the Synced cell immediately.
            self.node_status.synced_block = Some(start_block);
            self.status = Status::Info(format!("Rescan from block {} requested.", start_block));
        }
    }

    /// Highest confirmed block persisted to the history file. Records
    /// at or below it are final; everything above is provisional and
    /// re-fetched on every sync.
    pub(crate) fn tx_history_watermark(&self) -> u64 {
        self.confirmed_watermark
    }

    /// Wipe all wallet-specific runtime state: accounts, balances,
    /// in-flight receivers, form inputs, and DAO caches. Does NOT
    /// change `screen` or `status` — callers decide what transition
    /// follows.
    fn clear_wallet_state(&mut self) {
        self.accounts.clear();
        self.balances.clear();
        self.spendable_balances.clear();
        self.rename_wallet_id = None;
        self.rename_wallet_buf.clear();
        self.import_mode = false;
        self.wallet_modal = crate::types::WalletModal::None;
        self.set_block_editing = false;
        self.set_block_input.clear();

        // Drop all in-flight receivers so background threads from the
        // previous wallet can't land stale results into the new one.
        self.tx_history_rx = None;
        self.balance_receiver = None;
        self.transaction_build_rx = None;
        self.transaction_send_rx = None;
        self.node_status_rx = None;
        self.earliest_funding_block_rx = None;

        self.tx_history.clear();
        self.unconfirmed_tx_records.clear();
        self.confirmed_watermark = 0;

        self.transfer_recipient.clear();
        self.transfer_amount.clear();
        self.transfer_all = false;
        self.transfer_from_account = 0;
        self.multisig_local_signer_idx = 0;
        self.dao_deposit_amount.clear();
        self.dao_deposit_all = false;
        self.dao_deposit_from_account = 0;
        self.tx_status = TransactionStatus::Idle;

        self.dao_deposited_cells.clear();
        self.dao_prepared_cells.clear();
        self.dao_deposited_staging.clear();
        self.dao_prepared_staging.clear();
        self.dao_cells_query_rx = None;
        self.deposit_headers.clear();
        self.deposit_headers_rx = None;
    }

    /// Lock the wallet: clear state and return to the Locked screen.
    pub(crate) fn lock_wallet(&mut self) {
        self.clear_wallet_state();
        self.screen = Screen::Locked;
        self.status = Status::None;
        tracing::info!("Wallet locked (wallet_id={})", self.wallet_id);
    }

    /// Trim the wallet name and claim the next available wallet ID.
    /// Name uniqueness is enforced by core during creation/import.
    pub(crate) fn prepare_new_wallet(&self) -> Result<(u32, String), String> {
        let trimmed = self.new_wallet_name.trim();
        let name = if trimmed.is_empty() {
            names::Generator::default()
                .next()
                .unwrap_or_else(|| "wallet".to_string())
        } else {
            trimmed.to_string()
        };
        let wallet_id = qpv2_core::db::wallets::next_wallet_id().map_err(|e| e.to_string())?;
        Ok((wallet_id, name))
    }

    /// Switch the active wallet. Clears previous wallet state, loads
    /// the new wallet's metadata, and transitions directly to Unlocked.
    pub(crate) fn switch_wallet(&mut self, wallet_id: u32, wallet_name: &str) {
        tracing::info!(
            "Switching wallet (wallet_id={}, name={})",
            wallet_id,
            wallet_name
        );
        self.clear_wallet_state();
        self.wallet_id = wallet_id;
        self.wallet_name = wallet_name.to_string();
        save_last_wallet_id(wallet_id);

        self.auth_method = KeyVault::read_wallet_info(wallet_id)
            .ok()
            .map(|w| w.auth_method);

        self.lc_scripts_registered = false;
        self.accounts = KeyVault::get_all_accounts(wallet_id).unwrap_or_default();
        self.screen = Screen::Unlocked;
        self.needs_initial_fetch = true;
        self.wallet_selector_open = false;
        self.refresh_wallet_cache();
    }

    /// Called when the node type or network changes in the UI. Refreshes
    /// `settings_rpc_url` to the default URL for the pending
    /// `(node_type, network)` pair so the form preview matches
    /// what the user is about to commit.
    pub(crate) fn on_node_type_changed(&mut self) {
        self.settings_rpc_url =
            ckb_node::NodeConfig::default_rpc_url_for(self.node_type, self.network).to_string();
    }

    /// Commit the staged settings edits as the active node config:
    ///
    /// 1. Build the new `NodeConfig` from the settings-buffer fields
    ///    (`settings_*`, `temp_*`) on top of the current
    ///    `qp_client.config()` snapshot. There is no separate mutable
    ///    `node_config` on `App`, so this is the only place where an
    ///    edit becomes committed state.
    /// 2. Persist the config to disk.
    /// 3. Replace `qp_client` and `local_node` with fresh instances
    ///    bound to it.
    /// 4. Wipe cached metrics (`node_status`) and drop any in-flight
    ///    poll receiver from the previous backend so its result can't
    ///    land after the swap and resurrect stale values.
    /// 5. Kick off fresh balance + node-status fetches.
    pub(crate) fn apply_node_config(&mut self) {
        let mut new_cfg = self.qp_client.config().clone();
        new_cfg.node_type = self.node_type;
        new_cfg.network = self.network;
        new_cfg.rpc_url = self.settings_rpc_url.clone();

        if new_cfg.requires_binary() && !self.settings_binary_path.is_empty() {
            new_cfg.binary_path = Some(self.settings_binary_path.clone().into());
        } else if !new_cfg.requires_binary() {
            new_cfg.binary_path = None;
        }

        if !self.settings_data_dir.is_empty() {
            new_cfg.data_dir = self.settings_data_dir.clone().into();
        }

        if let Err(e) = new_cfg.save() {
            let msg = format!("Failed to save config: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        // Replace the manager + client with fresh ones bound to the
        // newly-saved config. The old LocalNodeProcess's drop stops its
        // child cleanly via the inner *Process::drop; the old
        // QpClient lives on inside any in-flight thread until that
        // thread finishes its unit of work.
        self.qp_client = ckb_node::QpClient::new(new_cfg.clone());
        self.local_node = ckb_node::LocalNodeProcess::new(new_cfg);

        // Cached node-status metrics — tip block, peer count, RPC
        // port, DB size, synced block — are all backend-specific and
        // instantly stale on switch. Drop any in-flight poll from the
        // previous backend at the same time so its result can't land
        // *after* the reset and resurrect old values.
        self.node_status = crate::types::NodeStatus::default();
        self.node_status_rx = None;
        self.deposit_headers.clear();
        self.deposit_headers_rx = None;

        // Both LC latches are per-instance. Reset so the poller
        // re-warms the cell dep and re-registers lock scripts against
        // the new backend (and skips both for FullNode / PublicRpc).
        self.lc_qr_dep_warmup_done = false;
        self.lc_scripts_registered = false;

        // The adoption series is per-network: drop any in-flight
        // fetch, show the new network's cached series immediately, and
        // rebuild against the chain on the next tick.
        self.qr_adoption_rx = None;
        self.qr_adoption_next_fetch = None;
        self.qr_adoption_series = crate::qr_adoption::load_series(self.qp_client.network().tag());

        // Balances, tx history, and DAO cells are network-scoped but
        // keyed by lock args alone — left in place they keep rendering
        // the previous network's numbers (and the balance chart would
        // replay the previous network's tape against the new total)
        // until a successful fetch overwrites them, which a slow-to-
        // boot local node can delay indefinitely. Drop them together
        // with their in-flight receivers; the per-network tx history
        // reloads from disk and the poller refetches the rest.
        self.balances.clear();
        self.spendable_balances.clear();
        self.balance_receiver = None;
        self.dao_deposited_cells.clear();
        self.dao_prepared_cells.clear();
        self.dao_deposited_staging.clear();
        self.dao_prepared_staging.clear();
        self.dao_cells_query_rx = None;
        self.tx_history.clear();
        self.unconfirmed_tx_records.clear();
        self.tx_history_rx = None;
        self.balance_chart_cache = None;
        self.load_tx_history_from_disk();

        self.status = Status::Info("Configuration saved. RPC reconnected.".to_string());
        tracing::info!(
            "Node config applied (node_type={:?}, network={:?})",
            self.node_type,
            self.network
        );

        // Refresh balances + node status against the new connection so
        // the card repopulates promptly instead of waiting for the
        // next ~10s tick.
        self.fetch_all_balances();
        self.fetch_node_status();
    }

    /// Seeds `tx_history` from the active network's on-disk cache so the
    /// dashboard renders instantly on unlock instead of waiting for the
    /// first sync tick. The incremental-sync floor (`tx_history_watermark`)
    /// is derived from the loaded records. Silent on absence (fresh wallet
    /// or first time on this network) or read failure (corrupted file →
    /// surfaces as a status warning; next sync rebuilds from scratch).
    pub(crate) fn load_tx_history_from_disk(&mut self) {
        match TxHistoryStore::load(self.wallet_id, self.qp_client.network().tag()) {
            Ok(Some(store)) => {
                // The file holds only confirmed records, so its highest
                // block is the sync floor. Pending rows are skipped
                // defensively — files written by older builds may
                // contain them.
                self.confirmed_watermark = store
                    .records
                    .iter()
                    .filter(|r| !r.is_pending)
                    .map(|r| r.block_number)
                    .max()
                    .unwrap_or(0);
                self.tx_history = store.records;
            }
            Ok(None) => {
                self.tx_history.clear();
                self.confirmed_watermark = 0;
            }
            Err(e) => {
                self.tx_history.clear();
                self.confirmed_watermark = 0;
                let msg = format!("Failed to read cached tx history: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
            }
        }
    }

    /// Create a password-mode wallet. Opens the pinentry dialog with
    /// a confirmation field — the dialog itself enforces the match
    /// (the user can't submit until both fields agree). On submit,
    /// validates strength via `password_checker`, generates the
    /// master seed, derives the first account, and transitions to
    /// `Screen::Unlocked`. Cancellation surfaces as a quiet info
    /// banner; nothing else changes.
    pub(crate) fn create_wallet_with_password(&mut self, variant: SpxVariant) {
        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };
        let pw = match qpv2_core::pinentry::prompt_password_with_confirmation(
            "Choose a password for your wallet. You'll be prompted for it \
             again on every signing operation.",
            "Password:",
            "Confirm:",
            "Passwords do not match.",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let strength_str = match qpv2_core::utilities::password_checker(&pw) {
            Ok(bits) => format!(" Password strength: {} bits.", bits),
            Err(e) => {
                let msg = format!("Weak password: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let pw_for_account = pw.clone();
        let vault = KeyVault::new(variant, wallet_id);
        if let Err(e) =
            vault.generate_master_seed(AuthKey::Password(pw), AuthMethod::Password, &wallet_name)
        {
            let msg = format!("Failed to create wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        if let Err(e) = vault.gen_singlesig_account(AuthKey::Password(pw_for_account)) {
            let msg = format!("Failed to create first account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            self.auth_method = Some(AuthMethod::Password);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Password,
            &format!("Wallet created successfully!{}", strength_str),
            wallet_id,
            wallet_name,
        );
    }

    /// Resolve the authentication key based on the current auth method.
    /// Synchronous: may block the egui update loop for pinentry dialogs
    /// (password/FIDO2 paths).
    fn resolve_auth_key(&self, purpose: &str) -> Result<AuthKey, String> {
        match &self.auth_method {
            Some(AuthMethod::Password) => qpv2_core::pinentry::prompt_password(
                &format!("Enter your wallet password to {}.", purpose),
                "Password:",
            )
            .map(AuthKey::Password),
            Some(AuthMethod::Keychain) => {
                keychain::retrieve_key(self.wallet_id).map(AuthKey::CryptoKey)
            }
            Some(AuthMethod::Fido2 { credential_id }) => {
                let cred_bytes = hex::decode(credential_id)
                    .map_err(|e| format!("Invalid credential ID: {}", e))?;
                let pin = qpv2_core::pinentry::prompt_password(
                    &format!("Enter your FIDO2 security key PIN to {}.", purpose),
                    "PIN:",
                )?;
                let hmac_output = keychain::fido2::authenticate(&cred_bytes, &pin)?;
                qpv2_core::utilities::derive_vault_enc_key(&hmac_output)
                    .map(AuthKey::CryptoKey)
                    .map_err(|e| format!("Key derivation failed: {}", e))
            }
            Some(AuthMethod::Trezor { .. }) => Err(
                "This is a Trezor wallet; approve the action on your device instead.".to_string(),
            ),
            None => Err("No authentication method set.".to_string()),
        }
    }

    pub(crate) fn create_singlesig_account(&mut self) {
        if KeyVault::is_device_backed(self.wallet_id) {
            self.create_device_account();
            return;
        }

        let auth = match self.resolve_auth_key("create a new account") {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let variant = match KeyVault::get_spx_variant(self.wallet_id) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Failed to read wallet variant: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };
        let vault = KeyVault::new(variant, self.wallet_id);
        match vault.gen_singlesig_account(auth) {
            Ok(account) => {
                tracing::info!(
                    "Account created (wallet_id={}, lock_args={}...)",
                    self.wallet_id,
                    &account.lock_args[..8.min(account.lock_args.len())]
                );
                self.balances.insert(account.lock_args.clone(), Some(0));
                self.spendable_balances
                    .insert(account.lock_args.clone(), Some(0));
                self.register_lock_scripts_with_light_client(std::slice::from_ref(
                    &account.lock_args,
                ));
                self.accounts.push(account);
                self.refresh_wallet_cache();
                self.status = Status::Info("New account created!".to_string());
            }
            Err(e) => {
                let msg = format!("Failed to create account: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
            }
        }
    }

    /// Import the next account (index = current account count) from a connected
    /// Trezor. Accounts are contiguous from index 0, so position equals index.
    fn create_device_account(&mut self) {
        let variant = match KeyVault::get_spx_variant(self.wallet_id) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Failed to read wallet variant: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };
        let next_index = self.accounts.len() as u32;
        let is_mainnet = self.qp_client.is_mainnet();

        let mut device = match trezor_signer::open() {
            Ok(d) => d,
            Err(e) => {
                let msg = format!("Could not connect to Trezor: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let addr = match device.get_address(next_index, variant, is_mainnet, true) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("Failed to import account {} from Trezor: {}", next_index, e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let config = qpv2_core::types::MultisigConfig::single_sig(
            variant,
            addr.pubkey,
            trezor_signer::TREZOR_CONVENTION,
        );
        let account = qpv2_core::types::SphincsPlusAccount {
            index: next_index,
            lock_args: hex::encode(&addr.lock_args),
            config,
            initiating_signer_lock_args: None,
        };

        if let Err(e) = qpv2_core::db::add_singlesig_account(self.wallet_id, account.clone()) {
            let msg = format!("Failed to store account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        self.balances.insert(account.lock_args.clone(), Some(0));
        self.spendable_balances
            .insert(account.lock_args.clone(), Some(0));
        self.register_lock_scripts_with_light_client(std::slice::from_ref(&account.lock_args));
        self.accounts.push(account);
        self.refresh_wallet_cache();
        self.status = Status::Info("New Trezor account imported!".to_string());
    }

    pub(crate) fn import_seed_phrase_with_password(
        &mut self,
        variant: SpxVariant,
        single_sig_convention: SingleSigConvention,
    ) {
        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };
        let seed_phrase = match qpv2_core::pinentry::prompt_seed_phrase(variant) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let pw = match qpv2_core::pinentry::prompt_password_with_confirmation(
            "Choose a password for your imported wallet. You'll be prompted for it \
             again on every signing operation.",
            "Password:",
            "Confirm:",
            "Passwords do not match.",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let strength_str = match qpv2_core::utilities::password_checker(&pw) {
            Ok(bits) => format!(" Password strength: {} bits.", bits),
            Err(e) => {
                let msg = format!("Weak password: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let pw_for_account = pw.clone();
        let vault = KeyVault::new(variant, wallet_id);

        if let Err(e) = vault.import_seed_phrase(
            seed_phrase,
            AuthKey::Password(pw),
            AuthMethod::Password,
            &wallet_name,
            single_sig_convention,
        ) {
            let msg = format!("Failed to import wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        if let Err(e) = vault.gen_singlesig_account(AuthKey::Password(pw_for_account)) {
            let msg = format!("Failed to create first account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            self.auth_method = Some(AuthMethod::Password);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Password,
            &format!("Wallet imported successfully!{}", strength_str),
            wallet_id,
            wallet_name,
        );
    }

    pub(crate) fn export_seed_phrase(&mut self) {
        let auth = match self.resolve_auth_key("export the seed phrase") {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let variant = match KeyVault::get_spx_variant(self.wallet_id) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Failed to read wallet variant: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };
        let vault = KeyVault::new(variant, self.wallet_id);
        match vault.export_seed_phrase(auth) {
            Ok(phrase) => {
                if let Err(e) = qpv2_core::pinentry::show_seed_phrase(&phrase) {
                    tracing::error!("{}", e);
                    self.status = Status::Error(e);
                } else {
                    tracing::info!("Seed phrase exported (wallet_id={})", self.wallet_id);
                }
            }
            Err(e) => {
                let msg = format!("Failed to export seed phrase: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
            }
        }
    }

    /// Create a Keychain wallet. Generates a random 32-byte key,
    /// stores it in the platform credential store, then creates the
    /// wallet and first account.
    pub(crate) fn create_wallet_with_keychain(&mut self, variant: SpxVariant) {
        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };
        let key = match qpv2_core::utilities::get_random_bytes(32) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("Failed to generate key: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        if let Err(e) = keychain::store_key(wallet_id, &key) {
            let msg = format!("Failed to store key in Keychain: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        let key_for_account = key.clone();

        let vault = KeyVault::new(variant, wallet_id);
        if let Err(e) =
            vault.generate_master_seed(AuthKey::CryptoKey(key), AuthMethod::Keychain, &wallet_name)
        {
            let _ = keychain::delete_key(wallet_id);
            let msg = format!("Failed to create wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        if let Err(e) = vault.gen_singlesig_account(AuthKey::CryptoKey(key_for_account)) {
            let msg = format!("Failed to create first account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            self.auth_method = Some(AuthMethod::Keychain);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Keychain,
            &format!("Wallet created with {}!", keychain::short_name()),
            wallet_id,
            wallet_name,
        );
    }

    /// Connect a Trezor and import its accounts as a new watch-only wallet.
    ///
    /// The device is queried for `account_count` addresses (indices 0..N),
    /// each shown on the device for confirmation, and stored as single-sig
    /// accounts with no vault seed. Signing later streams transactions to the
    /// device. The connect/import round-trip is synchronous and blocks the UI
    /// briefly while the user confirms on the device.
    pub(crate) fn create_wallet_with_trezor(&mut self, variant: SpxVariant, account_count: u32) {
        // Connect and import before allocating a wallet id, so a device
        // failure leaves no empty wallet behind.
        let mut device = match trezor_signer::open() {
            Ok(d) => d,
            Err(e) => {
                let msg = format!("Could not connect to Trezor: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };
        let model = device.model();
        let is_mainnet = self.qp_client.is_mainnet();

        let mut accounts = Vec::with_capacity(account_count as usize);
        for i in 0..account_count {
            match device.get_address(i, variant, is_mainnet, true) {
                Ok(addr) => {
                    let config = qpv2_core::types::MultisigConfig::single_sig(
                        variant,
                        addr.pubkey,
                        trezor_signer::TREZOR_CONVENTION,
                    );
                    accounts.push(qpv2_core::types::SphincsPlusAccount {
                        index: i,
                        lock_args: hex::encode(&addr.lock_args),
                        config,
                        initiating_signer_lock_args: None,
                    });
                }
                Err(e) => {
                    let msg = format!("Failed to import account {} from Trezor: {}", i, e);
                    tracing::error!("{}", msg);
                    self.status = Status::Error(msg);
                    return;
                }
            }
        }

        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        if let Err(e) =
            KeyVault::create_device_wallet(wallet_id, &wallet_name, variant, &model, accounts)
        {
            let msg = format!("Failed to create Trezor wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Trezor { model },
            "Trezor wallet connected!",
            wallet_id,
            wallet_name,
        );
    }

    /// Unlock via the platform credential store, then transition to
    /// Unlocked.
    pub(crate) fn unlock_with_keychain(&mut self) {
        match keychain::retrieve_key(self.wallet_id) {
            Ok(_) => match KeyVault::get_all_accounts(self.wallet_id) {
                Ok(accounts) => {
                    self.accounts = accounts;
                    self.screen = Screen::Unlocked;
                    self.status = Status::None;
                    self.last_poll_time = std::time::Instant::now();
                    self.load_tx_history_from_disk();
                    self.fetch_all_balances();
                    self.fetch_tx_history(true);
                    self.fetch_dao_cells();
                    self.fetch_node_status();
                    tracing::info!(
                        "Wallet unlocked via keychain (wallet_id={})",
                        self.wallet_id
                    );
                }
                Err(e) => {
                    let msg = format!("Failed to unlock: {}", e);
                    tracing::error!("{}", msg);
                    self.status = Status::Error(msg);
                }
            },
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
            }
        }
    }

    /// Create a multisig account from the modal form state.
    pub(crate) fn create_multisig_account(&mut self) {
        let singlesig: Vec<_> = self
            .accounts
            .iter()
            .filter(|a| a.config.signers.len() == 1)
            .collect();

        let local_lock_args = match singlesig.get(self.multisig_local_signer_idx) {
            Some(a) => a.lock_args.clone(),
            None => {
                self.status = Status::Error("No single-sig account selected.".to_string());
                return;
            }
        };

        let co_signers: Vec<qpv2_core::types::Signer> = match self
            .multisig_co_signers
            .iter()
            .map(|(hex, variant)| {
                let pubkey =
                    hex::decode(hex.trim()).map_err(|e| format!("Invalid pubkey hex: {}", e))?;
                Ok(qpv2_core::types::Signer {
                    variant: *variant,
                    pubkey,
                })
            })
            .collect::<Result<Vec<_>, String>>()
        {
            Ok(v) => v,
            Err(e) => {
                self.status = Status::Error(e);
                return;
            }
        };

        match KeyVault::gen_multisig_account(
            self.wallet_id,
            &local_lock_args,
            co_signers,
            self.multisig_threshold,
            self.multisig_required_first_n,
        ) {
            Ok(account) => {
                tracing::info!(
                    "Multisig account created (wallet_id={}, lock_args={}...)",
                    self.wallet_id,
                    &account.lock_args[..8.min(account.lock_args.len())]
                );
                self.balances.insert(account.lock_args.clone(), Some(0));
                self.spendable_balances
                    .insert(account.lock_args.clone(), Some(0));
                self.register_lock_scripts_with_light_client(std::slice::from_ref(
                    &account.lock_args,
                ));
                self.accounts.push(account);
                self.refresh_wallet_cache();
                self.status = Status::Info("Multisig account created!".to_string());
            }
            Err(e) => {
                let msg = format!("Failed to create multisig account: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
            }
        }
    }

    pub(crate) fn import_seed_phrase_with_keychain(
        &mut self,
        variant: SpxVariant,
        single_sig_convention: SingleSigConvention,
    ) {
        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };
        let seed_phrase = match qpv2_core::pinentry::prompt_seed_phrase(variant) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let key = match qpv2_core::utilities::get_random_bytes(32) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("Failed to generate key: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        if let Err(e) = keychain::store_key(wallet_id, &key) {
            let msg = format!("Failed to store key in Keychain: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        let key_for_account = key.clone();
        let vault = KeyVault::new(variant, wallet_id);

        if let Err(e) = vault.import_seed_phrase(
            seed_phrase,
            AuthKey::CryptoKey(key),
            AuthMethod::Keychain,
            &wallet_name,
            single_sig_convention,
        ) {
            let _ = keychain::delete_key(wallet_id);
            let msg = format!("Failed to import wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        if let Err(e) = vault.gen_singlesig_account(AuthKey::CryptoKey(key_for_account)) {
            let msg = format!("Failed to create first account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            self.auth_method = Some(AuthMethod::Keychain);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Keychain,
            &format!("Wallet imported with {}!", keychain::short_name()),
            wallet_id,
            wallet_name,
        );
    }

    /// Create a FIDO2-authenticated wallet. Prompts for the device PIN
    /// via pinentry, registers a credential, then derives the encryption
    /// key via hmac-secret.
    pub(crate) fn create_wallet_with_fido2(&mut self, variant: SpxVariant) {
        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };
        let pin = match qpv2_core::pinentry::prompt_password(
            "Enter your FIDO2 security key PIN to register a new credential.",
            "PIN:",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let credential = match keychain::fido2::register(&pin) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("FIDO2 registration failed: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let credential_id = hex::encode(&credential.credential_id);

        let hmac_output = match keychain::fido2::authenticate(&credential.credential_id, &pin) {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("FIDO2 authentication failed: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let key = match qpv2_core::utilities::derive_vault_enc_key(&hmac_output) {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Key derivation failed: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let key_for_account = key.clone();
        let auth_method = AuthMethod::Fido2 {
            credential_id: credential_id.clone(),
        };

        let vault = KeyVault::new(variant, wallet_id);
        if let Err(e) =
            vault.generate_master_seed(AuthKey::CryptoKey(key), auth_method.clone(), &wallet_name)
        {
            let msg = format!("Failed to create wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        if let Err(e) = vault.gen_singlesig_account(AuthKey::CryptoKey(key_for_account)) {
            let msg = format!("Failed to create first account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            self.auth_method = Some(auth_method);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Fido2 { credential_id },
            "Wallet created with FIDO2 security key!",
            wallet_id,
            wallet_name,
        );
    }

    /// Unlock via FIDO2 hmac-secret, then transition to Unlocked.
    pub(crate) fn unlock_with_fido2(&mut self, credential_id: &str) {
        let cred_bytes = match hex::decode(credential_id) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("Invalid credential ID: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let pin = match qpv2_core::pinentry::prompt_password(
            "Enter your FIDO2 security key PIN to unlock.",
            "PIN:",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        match keychain::fido2::authenticate(&cred_bytes, &pin) {
            Ok(_) => match KeyVault::get_all_accounts(self.wallet_id) {
                Ok(accounts) => {
                    self.accounts = accounts;
                    self.screen = Screen::Unlocked;
                    self.status = Status::None;
                    self.last_poll_time = std::time::Instant::now();
                    self.load_tx_history_from_disk();
                    self.fetch_all_balances();
                    self.fetch_tx_history(true);
                    self.fetch_dao_cells();
                    self.fetch_node_status();
                    tracing::info!("Wallet unlocked via FIDO2 (wallet_id={})", self.wallet_id);
                }
                Err(e) => {
                    let msg = format!("Failed to unlock: {}", e);
                    tracing::error!("{}", msg);
                    self.status = Status::Error(msg);
                }
            },
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
            }
        }
    }

    pub(crate) fn import_seed_phrase_with_fido2(
        &mut self,
        variant: SpxVariant,
        single_sig_convention: SingleSigConvention,
    ) {
        let (wallet_id, wallet_name) = match self.prepare_new_wallet() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let seed_phrase = match qpv2_core::pinentry::prompt_seed_phrase(variant) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let pin = match qpv2_core::pinentry::prompt_password(
            "Enter your FIDO2 security key PIN to register a new credential.",
            "PIN:",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                self.status = Status::Error(e);
                return;
            }
        };

        let credential = match keychain::fido2::register(&pin) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("FIDO2 registration failed: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let credential_id = hex::encode(&credential.credential_id);

        let hmac_output = match keychain::fido2::authenticate(&credential.credential_id, &pin) {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("FIDO2 authentication failed: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let key = match qpv2_core::utilities::derive_vault_enc_key(&hmac_output) {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Key derivation failed: {}", e);
                tracing::error!("{}", msg);
                self.status = Status::Error(msg);
                return;
            }
        };

        let key_for_account = key.clone();
        let auth_method = AuthMethod::Fido2 {
            credential_id: credential_id.clone(),
        };
        let vault = KeyVault::new(variant, wallet_id);

        if let Err(e) = vault.import_seed_phrase(
            seed_phrase,
            AuthKey::CryptoKey(key),
            auth_method.clone(),
            &wallet_name,
            single_sig_convention,
        ) {
            let msg = format!("Failed to import wallet: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            return;
        }

        if let Err(e) = vault.gen_singlesig_account(AuthKey::CryptoKey(key_for_account)) {
            let msg = format!("Failed to create first account: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
            self.auth_method = Some(auth_method);
            return;
        }

        self.finalize_wallet_setup(
            AuthMethod::Fido2 { credential_id },
            "Wallet imported with FIDO2 security key!",
            wallet_id,
            wallet_name,
        );
    }
}

// ── Last-wallet persistence ──

const LAST_WALLET_FILE: &str = "last_wallet.json";

pub(crate) fn save_last_wallet_id(wallet_id: u32) {
    if let Ok(dir) = qpv2_core::db::get_data_dir() {
        let path = dir.join(LAST_WALLET_FILE);
        let json = format!("{{\"wallet_id\":{}}}", wallet_id);
        let _ = std::fs::write(path, json);
    }
}

pub(crate) fn load_last_wallet_id() -> Option<u32> {
    let dir = qpv2_core::db::get_data_dir().ok()?;
    let path = dir.join(LAST_WALLET_FILE);
    let data = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    v.get("wallet_id")?.as_u64().map(|id| id as u32)
}
