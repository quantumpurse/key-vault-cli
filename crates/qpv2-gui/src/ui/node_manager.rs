//! Networks tab: backend selection and live node instrumentation.

use ckb_node::{NetworkType, NodeConfig, NodeType};
use eframe::egui;

use crate::types::{display_font, label_font, Status};
use crate::ui::utils::{
    breathing_dot, ckb_split, data_row, data_row_colored, draw_trend_chart, ghost_button,
    group_thousands, lerp_color, panel_frame, row_hover, section_header, truncate_middle_to,
    truncate_tail, value_flash, SectionCounter,
};
use crate::App;

const DASH: &str = "\u{2014}";

impl App {
    pub(crate) fn show_node_manager_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 24.0);

                // ── Screen header + network toggle ──────────
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("NETWORKS")
                                    .font(display_font(16.0))
                                    .color(self.colors.text),
                            );
                            if let Some((text, color)) = self.foreign_node_note() {
                                ui.label(
                                    egui::RichText::new(format!("({})", text))
                                        .size(13.0)
                                        .color(color),
                                );
                            }
                        });
                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new("Configure and monitor your CKB node.")
                                .size(11.0)
                                .color(self.colors.text_muted),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        self.draw_network_toggle(ui);
                    });
                });

                ui.add_space(14.0);
                let switch_to = self.draw_tab_bar(ui);
                ui.add_space(12.0);

                let backend = self.qp_client.config().node_type;
                // Sections are numbered in render order because two of
                // them are backend-conditional; fixed codes would leave
                // gaps whenever one is skipped.
                let mut sec = SectionCounter::new();

                // ── Chain ────────────────────────────────────
                panel_frame(&self.colors).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    section_header(ui, &self.colors, &sec.next_code(), "Chain");
                    ui.add_space(6.0);
                    self.draw_blockchain_metrics(ui);
                });

                // ── Tx Pool (not available on LC) ────────────
                if backend != NodeType::LightClient {
                    ui.add_space(12.0);
                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 6.0;
                        section_header(ui, &self.colors, &sec.next_code(), "Tx Pool");
                        ui.add_space(6.0);
                        self.draw_tx_pool_metrics(ui);
                    });
                }

                // ── Node ─────────────────────────────────────
                ui.add_space(12.0);
                panel_frame(&self.colors).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    section_header(ui, &self.colors, &sec.next_code(), "Node");
                    ui.add_space(6.0);
                    self.draw_node_metrics(ui, backend);
                });

                // ── Peers ────────────────────────────────────
                ui.add_space(12.0);
                panel_frame(&self.colors).show(ui, |ui| {
                    section_header(
                        ui,
                        &self.colors,
                        &sec.next_code(),
                        &format!("Peers ({})", self.node_status.peers.len()),
                    );
                    if !self.node_status.peers.is_empty() {
                        ui.add_space(6.0);
                        self.draw_peer_table(ui);
                    }
                });

                // ── Tracked Scripts (LC only) ────────────────
                if backend == NodeType::LightClient && !self.node_status.tracked_scripts.is_empty()
                {
                    ui.add_space(12.0);
                    panel_frame(&self.colors).show(ui, |ui| {
                        self.draw_tracked_scripts_section(ui, &sec.next_code());
                    });
                }

                // ── QR Lock Adoption ─────────────────────────
                ui.add_space(12.0);
                panel_frame(&self.colors).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    self.draw_qr_adoption_section(ui, &sec.next_code());
                });

                // Applied after rendering so the frame draws against the
                // pre-switch state instead of half-updated config.
                if let Some(backend) = switch_to {
                    self.switch_to_backend(backend);
                }

                ui.add_space(20.0);
            });
        });
    }

    /// Network-wide adoption of the quantum-resistant lock script:
    /// headline CKB total plus the weekly chart. Chain telemetry, so it
    /// lives here with the rest of the node instrumentation — data via
    /// a public RPC indexer (the light client only sees its registered
    /// scripts), reconstructed from live cells' creation blocks.
    fn draw_qr_adoption_section(&mut self, ui: &mut egui::Ui, code: &str) {
        section_header(ui, &self.colors, code, "QR Lock Adoption");
        ui.add_space(8.0);

        match self.qr_adoption_series.last().copied() {
            Some((ts, total)) => {
                let (int, frac) = ckb_split(total);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        egui::RichText::new(int)
                            .font(display_font(20.0))
                            .color(self.colors.text),
                    );
                    ui.label(
                        egui::RichText::new(format!(".{}", &frac[..2]))
                            .font(display_font(13.0))
                            .color(self.colors.text_muted),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("CKB")
                            .font(label_font(9.0))
                            .color(self.colors.accent),
                    );
                });
                ui.label(
                    egui::RichText::new("SECURED BY THE QUANTUM-RESISTANT LOCK · NETWORK-WIDE")
                        .font(label_font(8.0))
                        .color(self.colors.text_muted),
                );
                ui.add_space(8.0);

                draw_trend_chart(
                    ui,
                    &self.colors,
                    &self.qr_adoption_series,
                    110.0,
                    "QUERYING PUBLIC INDEXER",
                    "Network-wide CKB under the quantum-resistant lock, weekly, \
                     reconstructed from live cells via public RPC.",
                );

                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(format!(
                        "VIA PUBLIC RPC · WEEKLY · UPDATED {}",
                        crate::utils::format_relative_time(ts).to_uppercase()
                    ))
                    .font(label_font(7.5))
                    .color(self.colors.text_muted),
                );
            }
            None => {
                ui.label(
                    egui::RichText::new("Querying public indexer...")
                        .size(11.0)
                        .color(self.colors.text_muted),
                );
            }
        }
    }

    fn backend_label(backend: NodeType) -> &'static str {
        match backend {
            NodeType::LightClient => "LIGHT CLIENT",
            NodeType::FullNode => "FULL NODE",
            NodeType::PublicRpc => "PUBLIC RPC",
        }
    }

    // ── Network toggle ───────────────────────────────────────

    fn draw_network_toggle(&mut self, ui: &mut egui::Ui) {
        let current_network = self.qp_client.config().network;
        let mut selected = current_network;

        let seg_w = 86.0;
        let seg_h = 26.0;
        let gap = 6.0;
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(seg_w * 2.0 + gap, seg_h), egui::Sense::hover());

        // Mainnet signals in accent cyan; testnet in caution yellow so the
        // non-production network is always visually distinct.
        let segments = [
            (
                NetworkType::Mainnet,
                "MAINNET",
                self.colors.accent,
                self.colors.accent_tint,
            ),
            (
                NetworkType::Testnet,
                "TESTNET",
                self.colors.warn,
                self.colors.warn_tint,
            ),
        ];

        for (i, &(net, label, signal, tint)) in segments.iter().enumerate() {
            let cell = egui::Rect::from_min_size(
                egui::pos2(rect.left() + i as f32 * (seg_w + gap), rect.top()),
                egui::vec2(seg_w, seg_h),
            );
            let resp = ui.interact(cell, ui.id().with(("net-seg", i)), egui::Sense::click());
            let painter = ui.painter();
            let is_active = selected == net;

            if is_active {
                painter.rect_filled(cell, 0.0, tint);
            }
            let stroke_color = if is_active {
                signal
            } else if resp.hovered() {
                self.colors.border2
            } else {
                self.colors.border
            };
            painter.rect_stroke(
                cell,
                0.0,
                egui::Stroke::new(1.0, stroke_color),
                egui::StrokeKind::Inside,
            );

            let text_color = if is_active {
                signal
            } else if resp.hovered() {
                self.colors.text
            } else {
                self.colors.text_muted
            };
            painter.text(
                cell.center(),
                egui::Align2::CENTER_CENTER,
                label,
                label_font(9.5),
                text_color,
            );

            if resp.clicked() {
                selected = net;
            }
            if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
        }

        if selected != current_network {
            self.network = selected;
            self.node_type = self.qp_client.config().node_type;
            if self.node_type == NodeType::PublicRpc {
                self.settings_rpc_url =
                    NodeConfig::default_rpc_url_for(self.node_type, self.network).to_string();
            }
            self.commit_node_switch();
        }
    }

    pub(crate) fn switch_to_backend(&mut self, backend: NodeType) {
        let current = self.qp_client.config();
        if current.node_type == backend {
            return;
        }
        self.node_type = backend;
        self.network = current.network;
        self.on_node_type_changed();
        self.commit_node_switch();
    }

    fn commit_node_switch(&mut self) {
        let old_network = self.qp_client.config().network;
        self.local_node.stop();
        self.apply_node_config();
        if let Err(e) = self.local_node.spawn() {
            let msg = format!("Failed to start local node: {}", e);
            tracing::error!("{}", msg);
            self.status = Status::Error(msg);
        }
        if self.network != old_network {
            self.tx_history_rx = None;
            self.load_tx_history_from_disk();
        }
        if !matches!(self.status, Status::Error(_)) {
            self.status = Status::Info("Connecting...".to_string());
        }
    }

    pub(crate) fn sync_pct(&self, backend: NodeType) -> f32 {
        match backend {
            NodeType::LightClient => {
                match (self.node_status.synced_block, self.node_status.tip_block()) {
                    (Some(s), Some(t)) if t > 0 => (s as f64 / t as f64).clamp(0.0, 1.0) as f32,
                    _ => 0.0,
                }
            }
            NodeType::FullNode => full_node_sync_pct(self.node_status.sync_state.as_ref()),
            NodeType::PublicRpc => 0.0,
        }
    }

    // ── Backend tab bar ──────────────────────────────────────

    fn draw_tab_bar(&mut self, ui: &mut egui::Ui) -> Option<NodeType> {
        let backends = [
            NodeType::LightClient,
            NodeType::FullNode,
            NodeType::PublicRpc,
        ];
        let current = self.qp_client.config().node_type;
        let mut switch_to = None;

        let gap = 6.0;
        let cell_h = 40.0;
        let total_w = ui.available_width();
        let seg_w = (total_w - gap * (backends.len() as f32 - 1.0)) / backends.len() as f32;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(total_w, cell_h), egui::Sense::hover());
        let t = ui.input(|i| i.time) as f32;

        for (i, &backend) in backends.iter().enumerate() {
            let active = current == backend;
            let cell = egui::Rect::from_min_size(
                egui::pos2(rect.left() + i as f32 * (seg_w + gap), rect.top()),
                egui::vec2(seg_w, cell_h),
            );
            let resp = ui.interact(cell, ui.id().with(("backend-tab", i)), egui::Sense::click());
            let painter = ui.painter();

            if active {
                painter.rect_filled(cell, 0.0, self.colors.accent_tint);
            }
            let stroke_color = if active {
                self.colors.accent
            } else if resp.hovered() {
                self.colors.border2
            } else {
                self.colors.border
            };
            painter.rect_stroke(
                cell,
                0.0,
                egui::Stroke::new(1.0, stroke_color),
                egui::StrokeKind::Inside,
            );

            let name_color = if active {
                self.colors.accent
            } else if resp.hovered() {
                self.colors.text
            } else {
                self.colors.text_muted
            };
            painter.text(
                egui::pos2(cell.center().x, cell.top() + 13.0),
                egui::Align2::CENTER_CENTER,
                Self::backend_label(backend),
                label_font(10.0),
                name_color,
            );

            // Status line: breathing dot + state code. The sync
            // percentage lives in the header's quick node switcher.
            let (code, status_color, urgent) = self.backend_status(backend, active);
            let galley = painter.layout_no_wrap(code.to_string(), label_font(8.5), status_color);
            let dot_w = if active { 11.0 } else { 0.0 };
            let start_x = cell.center().x - (galley.rect.width() + dot_w) / 2.0;
            let status_y = cell.bottom() - 12.0;
            if active {
                breathing_dot(
                    painter,
                    egui::pos2(start_x + 3.0, status_y),
                    status_color,
                    t,
                    urgent,
                );
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(50));
            }
            painter.galley(
                egui::pos2(start_x + dot_w, status_y - galley.rect.height() / 2.0),
                galley,
                status_color,
            );

            if resp.hovered() && !active {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if resp.clicked() && !active {
                switch_to = Some(backend);
            }
        }

        switch_to
    }

    /// State code + semantic color + urgency for a backend tab.
    fn backend_status(
        &self,
        backend: NodeType,
        active: bool,
    ) -> (&'static str, egui::Color32, bool) {
        let is_local_node = backend != NodeType::PublicRpc;
        if !active {
            ("STANDBY", self.colors.text_muted, false)
        } else if is_local_node && !self.local_node.has_local_process() {
            // Whatever else answers on the port is reported by `foreign_node_note`.
            ("OFFLINE", self.colors.danger, true)
        } else if self.node_status.online {
            ("ONLINE", self.colors.accent2, false)
        } else if is_local_node {
            ("STARTING", self.colors.warn, true)
        } else {
            ("OFFLINE", self.colors.danger, true)
        }
    }

    /// Heading note for when QPV2 is talking to a node it did not start:
    /// a local backend is selected, its own child is gone, and the port
    /// still answers. Red when that node is on another chain.
    fn foreign_node_note(&self) -> Option<(String, egui::Color32)> {
        if self.qp_client.config().node_type == NodeType::PublicRpc
            || self.local_node.has_local_process()
        {
            return None;
        }
        let port = self.node_status.rpc_port?;
        let network = self.qp_client.config().network;
        if let Some(detected) = &self.node_status.network_mismatch {
            return Some((
                format!("Foreign {} node detected at port {}", detected, port),
                self.colors.warn,
            ));
        }
        if self.node_status.online {
            return Some((
                format!("Foreign {} node detected at port {}", network, port),
                self.colors.warn,
            ));
        }
        None
    }

    // ── Tracked scripts ──────────────────────────────────────

    fn draw_tracked_scripts_section(&self, ui: &mut egui::Ui, code: &str) {
        let scripts = &self.node_status.tracked_scripts;
        section_header(
            ui,
            &self.colors,
            code,
            &format!("Tracked Scripts ({})", scripts.len()),
        );
        ui.add_space(6.0);

        // Build a map: wallet_id -> (wallet_name, Vec<lock_args>)
        let mut wallet_accounts: Vec<(String, Vec<String>)> = Vec::new();
        for cw in &self.wallet_cache {
            let accounts = qpv2_core::KeyVault::get_all_lock_args(cw.id).unwrap_or_default();
            wallet_accounts.push((cw.name.clone(), accounts));
        }

        // Classify each script into a wallet or "Orphaned"
        struct ScriptEntry {
            args_short: String,
            block_number: u64,
            account_idx: Option<usize>,
        }

        let mut grouped: std::collections::BTreeMap<String, Vec<ScriptEntry>> =
            std::collections::BTreeMap::new();

        for (args_hex, block) in scripts {
            let mut found = false;
            for (wallet_name, accounts) in &wallet_accounts {
                if let Some(idx) = accounts.iter().position(|a| a == args_hex) {
                    grouped
                        .entry(wallet_name.clone())
                        .or_default()
                        .push(ScriptEntry {
                            args_short: args_hex.clone(),
                            block_number: *block,
                            account_idx: Some(idx),
                        });
                    found = true;
                    break;
                }
            }
            if !found {
                grouped
                    .entry("Orphaned".to_string())
                    .or_default()
                    .push(ScriptEntry {
                        args_short: args_hex.clone(),
                        block_number: *block,
                        account_idx: None,
                    });
            }
        }

        // Flatten into a single list with wallet name for the table
        struct FlatEntry {
            wallet_name: String,
            wallet_color: egui::Color32,
            account_idx: Option<usize>,
            args: String,
            block_number: u64,
        }

        let mut flat: Vec<FlatEntry> = Vec::new();
        for (wallet_name, entries) in &mut grouped {
            entries.sort_by_key(|e| e.account_idx.unwrap_or(usize::MAX));
            // Orphaned scripts are an error state; owned ones stay
            // neutral (green is reserved for online/synced).
            let color = if wallet_name == "Orphaned" {
                self.colors.danger
            } else {
                self.colors.text
            };
            for entry in entries.iter() {
                flat.push(FlatEntry {
                    wallet_name: wallet_name.clone(),
                    wallet_color: color,
                    account_idx: entry.account_idx,
                    args: entry.args_short.clone(),
                    block_number: entry.block_number,
                });
            }
        }

        let c_border = self.colors.border;
        let c_muted = self.colors.text_muted;
        let w = ui.available_width();
        let col_acct = 0.24 * w;
        let col_args = 0.34 * w;
        // ~6.5px per glyph at 10.5pt mono; leave room for the synced column.
        let args_chars = (((w - col_args) - 120.0) / 6.5).max(12.0) as usize;

        let (hr, _) = ui.allocate_exact_size(egui::vec2(w, 18.0), egui::Sense::hover());
        let painter = ui.painter();
        for (label, x) in [
            ("WALLET", 6.0),
            ("ACCOUNT", col_acct),
            ("LOCK SCRIPT ARGS", col_args),
        ] {
            painter.text(
                egui::pos2(hr.left() + x, hr.center().y),
                egui::Align2::LEFT_CENTER,
                label,
                label_font(9.0),
                c_muted,
            );
        }
        painter.text(
            egui::pos2(hr.right(), hr.center().y),
            egui::Align2::RIGHT_CENTER,
            "SYNCED BLOCK",
            label_font(9.0),
            c_muted,
        );
        painter.hline(
            hr.x_range(),
            hr.bottom() - 0.5,
            egui::Stroke::new(1.0, c_border),
        );

        let mut prev_wallet = String::new();
        for entry in &flat {
            let (rr, resp) = ui.allocate_exact_size(egui::vec2(w, 22.0), egui::Sense::hover());
            let painter = ui.painter();
            if resp.hovered() {
                row_hover(painter, rr, &self.colors);
            }
            let cy = rr.center().y;

            let wallet_label = if entry.wallet_name != prev_wallet {
                prev_wallet = entry.wallet_name.clone();
                entry.wallet_name.clone()
            } else {
                "\u{2502}".to_string()
            };
            painter.text(
                egui::pos2(rr.left() + 6.0, cy),
                egui::Align2::LEFT_CENTER,
                wallet_label,
                egui::FontId::proportional(10.5),
                entry.wallet_color,
            );
            let idx_str = match entry.account_idx {
                Some(idx) => format!("#{}", idx),
                None => "?".to_string(),
            };
            painter.text(
                egui::pos2(rr.left() + col_acct, cy),
                egui::Align2::LEFT_CENTER,
                idx_str,
                egui::FontId::proportional(10.5),
                self.colors.text,
            );
            painter.text(
                egui::pos2(rr.left() + col_args, cy),
                egui::Align2::LEFT_CENTER,
                truncate_middle_to(&entry.args, args_chars),
                egui::FontId::proportional(10.5),
                c_muted,
            );
            painter.text(
                egui::pos2(rr.right(), cy),
                egui::Align2::RIGHT_CENTER,
                format!("#{}", group_thousands(entry.block_number)),
                egui::FontId::proportional(10.5),
                self.colors.text,
            );
            painter.hline(
                rr.x_range(),
                rr.bottom() - 0.5,
                egui::Stroke::new(1.0, c_border),
            );
        }
    }

    // ── Node metrics ─────────────────────────────────────────

    fn draw_node_metrics(&self, ui: &mut egui::Ui, backend: NodeType) {
        for (label, value) in self.node_metrics(backend) {
            if label == "Protocols" {
                // Protocol lists run long; stack the value under the
                // label so it can wrap instead of colliding with it.
                ui.label(
                    egui::RichText::new("PROTOCOLS")
                        .font(label_font(9.5))
                        .color(self.colors.text_muted),
                );
                ui.label(
                    egui::RichText::new(value)
                        .size(11.0)
                        .color(self.colors.text),
                );
            } else {
                data_row(ui, &self.colors, label, &value);
            }
        }
    }

    fn node_metrics(&self, backend: NodeType) -> Vec<(&'static str, String)> {
        let node = self.node_status.local_node_info.as_ref();
        let version = node
            .map(|n| n.version.clone())
            .unwrap_or_else(|| DASH.into());
        let protocols = node
            .map(|n| {
                n.protocols
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_else(|| DASH.into());
        let node_id = node
            .map(|n| n.node_id.clone())
            .unwrap_or_else(|| DASH.into());

        let mut m = match backend {
            NodeType::PublicRpc => {
                let url = self.qp_client.config().rpc_url.clone();
                vec![
                    ("Endpoint", hostname_of(&url)),
                    ("Port", port_text(self.node_status.rpc_port)),
                ]
            }
            NodeType::LightClient | NodeType::FullNode => {
                vec![("RPC Port", port_text(self.node_status.rpc_port))]
            }
        };
        m.push(("Version", version));
        m.push(("Node ID", node_id));
        m.push(("Protocols", protocols));
        m
    }

    fn draw_sync_edit_inline(&mut self, ui: &mut egui::Ui) {
        let tip = self.node_status.tip_block();

        let response = ui.add(
            egui::TextEdit::singleline(&mut self.set_block_input)
                .desired_width(90.0)
                .font(egui::FontId::monospace(12.0))
                .text_color(self.colors.accent),
        );

        let parsed = self.set_block_input.trim().replace(',', "").parse::<u64>();
        let valid = matches!(&parsed, Ok(b) if tip.is_none_or(|t| *b <= t));

        let btn_size = egui::vec2(58.0, 20.0);
        let set_btn = ui.add_enabled(valid, ghost_button(&self.colors, "SET", btn_size));
        let cancel_btn = ui.add(ghost_button(&self.colors, "CANCEL", btn_size));

        let auto_running = self.earliest_funding_block_rx.is_some();
        let auto_enabled = auto_running.eq(&false) && !self.accounts.is_empty();
        let auto_label = if auto_running { "AUTO..." } else { "AUTO" };
        let auto_btn = ui.add_enabled(
            auto_enabled,
            ghost_button(&self.colors, auto_label, btn_size),
        );

        let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        let escape = ui.input(|i| i.key_pressed(egui::Key::Escape));

        if (set_btn.clicked() || enter) && valid {
            if let Ok(block) = parsed {
                self.set_all_accounts_lock_script_block(block);
                self.set_block_editing = false;
                self.set_block_input.clear();
            }
        } else if cancel_btn.clicked() || escape {
            self.set_block_editing = false;
            self.set_block_input.clear();
        } else if auto_btn.clicked() {
            self.detect_earliest_funding_block_async();
        }
    }

    // ── Blockchain metrics ───────────────────────────────────

    fn draw_blockchain_metrics(&mut self, ui: &mut egui::Ui) {
        let backend = self.qp_client.config().node_type;
        let c_text = self.colors.text;
        let c_muted = self.colors.text_muted;

        // Pre-compute info-dependent values as owned strings so the
        // borrow of blockchain_info doesn't conflict with &mut self below.
        let info = self.node_status.blockchain_info.as_deref();
        let chain = info.map(|i| i.chain.clone()).unwrap_or_else(|| DASH.into());
        let difficulty = info
            .map(|i| format!("{:#x}", i.difficulty))
            .unwrap_or_else(|| DASH.into());
        let ibd = info
            .map(|i| {
                if i.is_initial_block_download {
                    "Yes"
                } else {
                    "No"
                }
            })
            .unwrap_or(DASH)
            .to_string();
        let median = info
            .map(|i| format_timestamp_ms(i.median_time.value()))
            .unwrap_or_else(|| DASH.into());
        let tip_label = match backend {
            NodeType::PublicRpc => "Block Height",
            NodeType::FullNode => "Local Tip",
            NodeType::LightClient => "Tip",
        };
        let tip_value = match backend {
            NodeType::PublicRpc => block_height_text(self.node_status.tip_block()),
            _ => target_tip_value(backend, &self.node_status),
        };
        // Tip flash mirrors the telemetry strip: accent flash ~1s on change.
        let tip_raw = match backend {
            NodeType::FullNode => self
                .node_status
                .sync_state
                .as_ref()
                .map(|s| s.best_known_block_number.value())
                .unwrap_or(0),
            _ => self.node_status.tip_block().unwrap_or(0),
        };
        let flash = value_flash(ui, egui::Id::new("nm-tip-flash"), tip_raw);
        data_row_colored(
            ui,
            &self.colors,
            tip_label,
            &tip_value,
            lerp_color(c_text, self.colors.accent, flash),
        );

        // Synced block (LC and FN only)
        if backend != NodeType::PublicRpc {
            if backend == NodeType::LightClient && self.set_block_editing {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("SYNCED")
                            .font(label_font(9.5))
                            .color(c_muted),
                    );
                    self.draw_sync_edit_inline(ui);
                });
            } else {
                let synced_value = match backend {
                    NodeType::LightClient => self
                        .node_status
                        .synced_block
                        .map(|b| format!("#{}", group_thousands(b)))
                        .unwrap_or_else(|| DASH.into()),
                    NodeType::FullNode => self
                        .node_status
                        .sync_state
                        .as_ref()
                        .map(|s| format!("#{}", group_thousands(s.tip_number.value())))
                        .unwrap_or_else(|| DASH.into()),
                    NodeType::PublicRpc => unreachable!(),
                };
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("SYNCED")
                            .font(label_font(9.5))
                            .color(c_muted),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if backend == NodeType::LightClient {
                            let edit = ui.add(
                                egui::Button::new(
                                    egui::RichText::new("EDIT")
                                        .font(label_font(8.5))
                                        .color(self.colors.accent),
                                )
                                .fill(egui::Color32::TRANSPARENT)
                                .frame(false),
                            );
                            if edit.clicked() {
                                self.set_block_editing = true;
                                self.set_block_input = self
                                    .node_status
                                    .synced_block
                                    .map(|b| b.to_string())
                                    .unwrap_or_default();
                            }
                            ui.add_space(6.0);
                        }
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&synced_value).size(12.5).color(c_text),
                            )
                            .selectable(true),
                        );
                    });
                });
            }

            self.draw_sync_bar(ui, backend);
        }

        let epoch = self
            .node_status
            .tip_header
            .as_ref()
            .map(|h| group_thousands(h.epoch().number()))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, &self.colors, "Epoch", &epoch);

        data_row(ui, &self.colors, "Chain", &chain);
        data_row(ui, &self.colors, "Difficulty", &difficulty);
        data_row(ui, &self.colors, "IBD", &ibd);
        data_row(ui, &self.colors, "Network Time", &median);
    }

    /// Compact segmented block meter (htop idiom), right-aligned like
    /// every other value row: cyan cells while catching up, green once
    /// fully synced (the one semantic green).
    fn draw_sync_bar(&self, ui: &mut egui::Ui, backend: NodeType) {
        const SEGS: usize = 20;
        const SEG_W: f32 = 6.0;
        const SEG_GAP: f32 = 2.0;

        let pct = self.sync_pct(backend);
        let fill = if pct >= 0.999 {
            self.colors.accent2
        } else {
            self.colors.accent
        };
        let c_off = self.colors.border;
        let c_muted = self.colors.text_muted;

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("SYNC")
                    .font(label_font(9.5))
                    .color(c_muted),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(format!("{:.1}%", pct * 100.0))
                        .size(11.5)
                        .color(fill),
                );
                ui.add_space(6.0);
                let meter_w = SEGS as f32 * (SEG_W + SEG_GAP) - SEG_GAP;
                let (meter, _) =
                    ui.allocate_exact_size(egui::vec2(meter_w, 9.0), egui::Sense::hover());
                let painter = ui.painter();
                let lit = ((pct * SEGS as f32).round() as usize).min(SEGS);
                for s in 0..SEGS {
                    let x = meter.left() + s as f32 * (SEG_W + SEG_GAP);
                    let cell = egui::Rect::from_min_size(
                        egui::pos2(x, meter.top()),
                        egui::vec2(SEG_W, meter.height()),
                    );
                    painter.rect_filled(cell, 0.0, if s < lit { fill } else { c_off });
                }
            });
        });
    }

    // ── Tx Pool metrics ──────────────────────────────────────

    fn draw_tx_pool_metrics(&self, ui: &mut egui::Ui) {
        let pool = self.node_status.tx_pool_info.as_ref();
        let c = &self.colors;

        let pending = pool
            .map(|p| group_thousands(p.pending.value()))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, c, "Pending", &pending);

        let proposed = pool
            .map(|p| group_thousands(p.proposed.value()))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, c, "Proposed", &proposed);

        let orphan = pool
            .map(|p| group_thousands(p.orphan.value()))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, c, "Orphan", &orphan);

        let fee = pool
            .map(|p| format!("{} sh/KB", group_thousands(p.min_fee_rate.value())))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, c, "Min Fee", &fee);

        let cycles = pool
            .map(|p| group_thousands(p.total_tx_cycles.value()))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, c, "Cycles", &cycles);

        let size = pool
            .map(|p| format!("{} B", group_thousands(p.total_tx_size.value())))
            .unwrap_or_else(|| DASH.into());
        data_row(ui, c, "Tx Size", &size);
    }

    // ── Peer table ───────────────────────────────────────────

    fn draw_peer_table(&self, ui: &mut egui::Ui) {
        let c_border = self.colors.border;
        let c_muted = self.colors.text_muted;
        let c_text = self.colors.text;
        let w = ui.available_width();
        let col_ver = 0.44 * w;
        let col_dir = 0.78 * w;
        // ~6.5px per glyph at 10.5pt mono drives the truncation budgets.
        let id_chars = ((col_ver - 18.0) / 6.5).max(12.0) as usize;
        let ver_chars = (((col_dir - col_ver) - 12.0) / 6.5).max(8.0) as usize;

        let (hr, _) = ui.allocate_exact_size(egui::vec2(w, 18.0), egui::Sense::hover());
        let painter = ui.painter();
        for (label, x) in [
            ("NODE ID", 6.0),
            ("VERSION", col_ver),
            ("DIRECTION", col_dir),
        ] {
            painter.text(
                egui::pos2(hr.left() + x, hr.center().y),
                egui::Align2::LEFT_CENTER,
                label,
                label_font(9.0),
                c_muted,
            );
        }
        painter.text(
            egui::pos2(hr.right(), hr.center().y),
            egui::Align2::RIGHT_CENTER,
            "PING",
            label_font(9.0),
            c_muted,
        );
        painter.hline(
            hr.x_range(),
            hr.bottom() - 0.5,
            egui::Stroke::new(1.0, c_border),
        );

        for peer in &self.node_status.peers {
            let (rr, resp) = ui.allocate_exact_size(egui::vec2(w, 22.0), egui::Sense::hover());
            let painter = ui.painter();
            if resp.hovered() {
                row_hover(painter, rr, &self.colors);
            }
            let cy = rr.center().y;

            painter.text(
                egui::pos2(rr.left() + 6.0, cy),
                egui::Align2::LEFT_CENTER,
                truncate_middle_to(&peer.node_id, id_chars),
                egui::FontId::proportional(10.5),
                c_text,
            );
            painter.text(
                egui::pos2(rr.left() + col_ver, cy),
                egui::Align2::LEFT_CENTER,
                truncate_tail(&peer.version, ver_chars),
                egui::FontId::proportional(10.5),
                c_muted,
            );
            let dir = if peer.is_outbound {
                "OUTBOUND"
            } else {
                "INBOUND"
            };
            painter.text(
                egui::pos2(rr.left() + col_dir, cy),
                egui::Align2::LEFT_CENTER,
                dir,
                label_font(9.0),
                c_muted,
            );
            let ping = peer
                .last_ping_duration
                .as_ref()
                .map(|d| format!("{}ms", d.value()))
                .unwrap_or_else(|| DASH.into());
            painter.text(
                egui::pos2(rr.right(), cy),
                egui::Align2::RIGHT_CENTER,
                ping,
                egui::FontId::proportional(10.5),
                c_text,
            );
            painter.hline(
                rr.x_range(),
                rr.bottom() - 0.5,
                egui::Stroke::new(1.0, c_border),
            );
        }
    }
}

// ── Free functions ───────────────────────────────────────────

fn full_node_sync_pct(sync_state: Option<&ckb_jsonrpc_types::SyncState>) -> f32 {
    let Some(s) = sync_state else {
        return 0.0;
    };
    let tip = s.tip_number.value();
    let best = s.best_known_block_number.value();
    if best > 0 {
        (tip as f64 / best as f64).clamp(0.0, 1.0) as f32
    } else {
        0.0
    }
}

fn target_tip_value(backend: NodeType, status: &crate::types::NodeStatus) -> String {
    match backend {
        NodeType::FullNode => match status.sync_state.as_ref() {
            Some(s) => format!("#{}", group_thousands(s.best_known_block_number.value())),
            None => DASH.into(),
        },
        NodeType::LightClient => match status.tip_block() {
            Some(t) => format!("#{}", group_thousands(t)),
            None => DASH.into(),
        },
        NodeType::PublicRpc => DASH.into(),
    }
}

fn block_height_text(tip: Option<u64>) -> String {
    tip.map(|n| format!("#{}", group_thousands(n)))
        .unwrap_or_else(|| DASH.to_string())
}

fn port_text(port: Option<u16>) -> String {
    port.map(|p| p.to_string())
        .unwrap_or_else(|| DASH.to_string())
}

fn hostname_of(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    stripped
        .split('/')
        .next()
        .unwrap_or(stripped)
        .split(':')
        .next()
        .unwrap_or(stripped)
        .to_string()
}

fn format_timestamp_ms(ms: u64) -> String {
    chrono::DateTime::from_timestamp((ms / 1000) as i64, 0)
        .map(|dt| dt.format("%b %d %Y %H:%M").to_string())
        .unwrap_or_else(|| DASH.into())
}
