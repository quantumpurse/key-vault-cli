//! App chrome (telemetry strip, module rail, status line) and the
//! Setup / Locked terminal screens.

use crate::types::{display_font, label_font, Status, Tab};
use crate::ui::utils::{
    accent_button, blinking_cursor, breathing_dot, ghost_button, panel_frame, section_header,
    v1_import_checkbox, value_flash,
};
use crate::App;
use ckb_node::NodeType;
use eframe::egui;
use qpv2_core::types::{AuthMethod, SingleSigConvention, SpxVariant};

/// Height of the top telemetry strip.
const TELEMETRY_H: f32 = 38.0;
/// Height of the bottom status line.
const STATUSLINE_H: f32 = 26.0;
/// Width of the left module rail.
const RAIL_W: f32 = 138.0;
/// Width of a telemetry segment's dropdown caret, glyph plus its 2px offset.
/// The carets are decoration only — the segment beside each one is the click
/// target — but the wallet's sits in a right-to-left layout with nothing to its
/// right to paint into, so it has to reserve this width to hold its place.
const ARROW_W: f32 = 12.0;

impl App {
    // ────────────────────────────────────────────────────────────────
    // Unlocked chrome
    // ────────────────────────────────────────────────────────────────

    pub(crate) fn show_unlocked(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx();
        self.handle_module_shortcuts(ctx);

        // ── Top telemetry strip ──
        egui::Panel::top("telemetry")
            .exact_size(TELEMETRY_H)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(self.colors.surface))
            .show(ui, |ui| {
                self.draw_telemetry_strip(ui);
                let r = ui.clip_rect();
                ui.painter().hline(
                    r.x_range(),
                    r.bottom() - 0.5,
                    egui::Stroke::new(1.0, self.colors.border),
                );
            });

        // ── Bottom status line ──
        egui::Panel::bottom("statusline")
            .exact_size(STATUSLINE_H)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(self.colors.surface))
            .show(ui, |ui| {
                self.draw_status_line(ui);
                let r = ui.clip_rect();
                ui.painter().hline(
                    r.x_range(),
                    r.top() + 0.5,
                    egui::Stroke::new(1.0, self.colors.border),
                );
            });

        // ── Left module rail ──
        egui::Panel::left("rail")
            .resizable(false)
            .show_separator_line(false)
            .exact_size(RAIL_W)
            .frame(egui::Frame::new().fill(self.colors.surface))
            .show(ui, |ui| {
                self.draw_module_rail(ui);
                let r = ui.clip_rect();
                ui.painter().vline(
                    r.right() - 0.5,
                    r.y_range(),
                    egui::Stroke::new(1.0, self.colors.border),
                );
            });

        // ── Main content area ──
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(self.colors.bg))
            .show(ui, |ui| {
                self.draw_unlocked_bg(ui);

                egui::ScrollArea::vertical()
                    .scroll_source(egui::containers::scroll_area::ScrollSource::ALL)
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.add_space(18.0);

                        match self.active_tab {
                            Tab::Dashboard => self.show_dashboard_tab(ui),
                            Tab::Transfer => self.show_transfer_tab(ui),
                            Tab::DaoOperations => self.show_dao_tab(ui),
                            Tab::NodeManager => self.show_node_manager_tab(ui),
                            Tab::Accounts => self.show_accounts_tab(ui),
                            Tab::Multisig => self.show_multisig_tab(ui),
                            Tab::Wallets => self.show_wallets_tab(ui),
                        }
                    });
            });
    }

    /// Number keys 1–7 switch modules when no text field is focused.
    fn handle_module_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.memory(|m| m.focused().is_some()) {
            return;
        }
        const KEYS: [egui::Key; 7] = [
            egui::Key::Num1,
            egui::Key::Num2,
            egui::Key::Num3,
            egui::Key::Num4,
            egui::Key::Num5,
            egui::Key::Num6,
            egui::Key::Num7,
        ];
        for (key, tab) in KEYS.iter().zip(Tab::ALL) {
            if ctx.input(|i| i.key_pressed(*key)) && self.active_tab != tab {
                self.reset_finished_tx_status();
                self.active_tab = tab;
            }
        }
    }

    /// Full-width strip: ident, node telemetry, tip block, network,
    /// then wallet identity and lock on the right.
    ///
    /// Each block is its own `draw_*` below. A block that can disappear owns
    /// its leading divider so the two vanish together; the rest are free-
    /// standing here, which is what makes the run's order readable in one view.
    fn draw_telemetry_strip(&mut self, ui: &mut egui::Ui) {
        let t = ui.input(|i| i.time) as f32;

        ui.horizontal_centered(|ui| {
            ui.add_space(12.0);

            self.draw_ident_block(ui);
            self.strip_divider(ui);
            self.draw_node_segment(ui, t);
            self.strip_divider(ui);
            self.draw_tip_block(ui);
            // Draws its own leading divider, and only when peers are reported.
            self.draw_peers_block(ui);
            // Draws its own leading divider, and only for device wallets.
            self.draw_device_segment(ui, t);
            self.strip_divider(ui);
            self.draw_wallet_group(ui, t);
        });
    }

    /// Ident block: the qp∞ mark knocked out of the accent chip.
    fn draw_ident_block(&self, ui: &mut egui::Ui) {
        let (logo, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
        draw_qp_logo_chip(ui.painter(), logo, self.colors.accent, self.colors.bg);
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("QUANTUM PURSE")
                .font(display_font(12.0))
                .color(self.colors.text),
        );
        ui.label(
            egui::RichText::new(concat!("V", env!("CARGO_PKG_VERSION")).to_uppercase())
                .font(label_font(9.0))
                .color(self.colors.text_muted),
        );
    }

    /// Node segment — clickable, opens the node selector.
    fn draw_node_segment(&mut self, ui: &mut egui::Ui, t: f32) {
        let c_muted = self.colors.text_muted;
        let node_name = match self.qp_client.config().node_type {
            NodeType::PublicRpc => "REMOTE",
            NodeType::LightClient => "LIGHT",
            NodeType::FullNode => "FULL",
        };
        let network = match self.qp_client.network() {
            ckb_node::NetworkType::Mainnet => "MAIN",
            ckb_node::NetworkType::Testnet => "TEST",
        };
        let network_color = if self.qp_client.is_mainnet() {
            self.colors.accent
        } else {
            self.colors.warn
        };
        let online = self.node_status.online;
        let dot_color = if online {
            self.colors.accent2
        } else {
            self.colors.danger
        };

        // Sync percentage rides along for local backends — this is
        // its home; the Networks tab's backend cards show state only.
        // Green once fully synced, accent while catching up.
        let node_type = self.qp_client.config().node_type;
        let sync_suffix = if online && node_type != NodeType::PublicRpc {
            let pct = self.sync_pct(node_type);
            let color = if pct >= 0.999 {
                self.colors.accent2
            } else {
                self.colors.accent
            };
            Some((format!("{:.1}%", pct * 100.0), color))
        } else {
            None
        };
        let node_text = format!("{} / {}", node_name, network);
        let seg = self.strip_segment(
            ui,
            "NODE",
            &node_text,
            sync_suffix.as_ref().map(|(s, c)| (s.as_str(), *c)),
            Some((dot_color, !online)),
            t,
        );
        ui.painter().text(
            seg.rect.right_center() + egui::vec2(2.0, 2.0),
            egui::Align2::LEFT_CENTER,
            "▾",
            egui::FontId::proportional(16.0),
            c_muted,
        );
        ui.add_space(10.0);
        self.node_selector_rect = Some(seg.rect);
        if seg.clicked() {
            self.node_selector_open = !self.node_selector_open;
            self.wallet_selector_open = false;
            self.device_popup_open = false;
            if self.node_selector_open {
                let cfg = self.qp_client.config();
                self.network = cfg.network;
                self.node_type = cfg.node_type;
            }
        }
        // Recolor of the network half happens via badge color below
        // the generic segment; repaint while offline so the dot
        // breathes.
        if !online {
            ui.ctx().request_repaint();
        }
        let _ = network_color;
    }

    /// Tip block, flashing bright on each new block.
    fn draw_tip_block(&self, ui: &mut egui::Ui) {
        let c_muted = self.colors.text_muted;
        let tip = self.node_status.tip_block();
        let tip_text = tip
            .map(crate::ui::utils::group_thousands)
            .unwrap_or_else(|| "------".into());
        ui.label(
            egui::RichText::new("TIP")
                .font(label_font(9.0))
                .color(c_muted),
        );
        ui.add_space(2.0);
        // Tip lives in the accent; a new block flashes it bright.
        let flash = value_flash(ui, egui::Id::new("tip-flash"), tip.unwrap_or(0));
        let tip_color = crate::ui::utils::lerp_color(self.colors.accent, self.colors.text, flash);
        ui.label(egui::RichText::new(tip_text).size(11.5).color(tip_color));
    }

    /// Peer count, when the backend reports peers.
    ///
    /// Draws its own leading divider: the block is conditional, so the divider
    /// has to disappear with it rather than leave a stray line behind.
    fn draw_peers_block(&self, ui: &mut egui::Ui) {
        if self.node_status.peers.is_empty() {
            return;
        }
        self.strip_divider(ui);
        ui.label(
            egui::RichText::new("PEERS")
                .font(label_font(9.0))
                .color(self.colors.text_muted),
        );
        ui.add_space(2.0);
        // Green: peers present means healthy connectivity (the
        // segment is hidden entirely at zero peers).
        ui.label(
            egui::RichText::new(format!("{}", self.node_status.peers.len()))
                .size(11.5)
                .color(self.colors.accent2),
        );
    }

    /// Right side: lock + wallet, right-aligned against the strip's edge.
    fn draw_wallet_group(&mut self, ui: &mut egui::Ui, t: f32) {
        let c_muted = self.colors.text_muted;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(12.0);

            // Password is the only method without lock/unlock, deliberately
            // (see the startup gate in `main.rs`): its passwords are 20+
            // characters, too much friction to re-enter just to look at
            // balances. Every other method locks — stated as an exclusion,
            // like the startup gate, so a new method gets a lock by default.
            if !matches!(self.auth_method, Some(AuthMethod::Password)) {
                let lock = ghost_button(&self.colors, "LOCK", egui::vec2(56.0, 22.0));
                if ui.add(lock).clicked() {
                    self.lock_wallet();
                }
                ui.add_space(10.0);
            }

            let wallet_text = self.wallet_name.to_uppercase();
            // Dropdown arrow, mirroring the node selector's. RTL
            // flow: allocated before the segment so it renders to
            // the segment's right, clear of the LOCK button.
            //
            // Unlike the other two this arrow is a real allocation, because
            // RTL leaves no room to its right to paint into. That means
            // egui's 8px item spacing lands between it and the label, which
            // is what made this gap the widest of the three. Scoped to zero
            // so the caret sits the same 2px off the label as the others,
            // without disturbing the LOCK gap or the right margin outside.
            let seg = ui
                .scope(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let (arrow, _) = ui.allocate_exact_size(
                        egui::vec2(ARROW_W, TELEMETRY_H - 10.0),
                        egui::Sense::hover(),
                    );
                    ui.painter().text(
                        arrow.left_center() + egui::vec2(2.0, 2.0),
                        egui::Align2::LEFT_CENTER,
                        "▾",
                        egui::FontId::proportional(16.0),
                        c_muted,
                    );
                    self.strip_segment(ui, "WALLET", &wallet_text, None, None, t)
                })
                .inner;
            self.wallet_selector_rect = Some(seg.rect);
            if seg.clicked() {
                self.wallet_selector_open = !self.wallet_selector_open;
                self.node_selector_open = false;
                self.device_popup_open = false;
            }
        });
    }

    /// Trezor link segment — only for device-backed wallets.
    ///
    /// Speaks the same grammar as the node segment beside it: breathing dot,
    /// condensed label, clickable. It reports *availability*, not readiness —
    /// whether the device is unlocked cannot be known without starting a
    /// handshake, which would prompt the user and so cannot be polled.
    fn draw_device_segment(&mut self, ui: &mut egui::Ui, t: f32) {
        use qpv2_core::types::AuthMethod;
        use trezor_connect::DeviceStatus;

        if !matches!(self.auth_method, Some(AuthMethod::Trezor { .. })) {
            return;
        }
        self.strip_divider(ui);

        // Any device operation in flight outranks the probe. Probe results
        // arrive through a channel, so one can be dispatched while the device
        // is free and consumed after a session has taken it — displaying
        // LINKED over a device that is mid-signature. Live state is authoritative
        // for "busy"; the probe only answers what we cannot observe directly.
        let connecting = self.trezor_reconnect_rx.is_some();
        let link = if self.trezor_operation_in_flight() {
            DeviceStatus::Working
        } else {
            self.device_status
        };

        let (value, dot_color, urgent) = match link {
            DeviceStatus::Linked => ("LINKED", self.colors.accent2, false),
            DeviceStatus::Emulator => ("EMULATOR", self.colors.accent2, false),
            DeviceStatus::Busy => ("IN USE", self.colors.warn, true),
            DeviceStatus::Absent => ("OFFLINE", self.colors.danger, true),
            DeviceStatus::Working => (
                if connecting { "CONNECTING" } else { "WORKING" },
                self.colors.accent,
                false,
            ),
        };

        let seg = self.strip_segment(ui, "TREZOR", value, None, Some((dot_color, urgent)), t);
        ui.painter().text(
            seg.rect.right_center() + egui::vec2(2.0, 2.0),
            egui::Align2::LEFT_CENTER,
            "▾",
            egui::FontId::proportional(16.0),
            self.colors.text_muted,
        );
        ui.add_space(10.0);

        // Opens the detail dropdown; reconnecting is a deliberate choice made
        // in there, never a side effect of clicking the strip.
        self.device_popup_rect = Some(seg.rect);
        if seg.clicked() {
            self.device_popup_open = !self.device_popup_open;
            self.node_selector_open = false;
            self.wallet_selector_open = false;
        }
        if urgent || connecting {
            ui.ctx().request_repaint();
        }
    }

    /// One clickable label/value segment in the telemetry strip.
    /// `dot` paints a breathing status dot before the value:
    /// `(color, urgent)`.
    fn strip_segment(
        &self,
        ui: &mut egui::Ui,
        label: &str,
        value: &str,
        suffix: Option<(&str, egui::Color32)>,
        dot: Option<(egui::Color32, bool)>,
        t: f32,
    ) -> egui::Response {
        let label_w = label.len() as f32 * 6.0;
        let value_w = value.len() as f32 * 7.2;
        let suffix_w = suffix.map_or(0.0, |(s, _)| s.len() as f32 * 7.2 + 6.0);
        let dot_w = if dot.is_some() { 12.0 } else { 0.0 };
        let w = label_w + dot_w + value_w + suffix_w + 10.0;
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(w, TELEMETRY_H - 10.0), egui::Sense::click());
        let painter = ui.painter();

        if response.hovered() {
            painter.rect_filled(rect, 0.0, self.colors.accent_tint);
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        let mut x = rect.left() + 2.0;
        painter.text(
            egui::pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            label_font(9.0),
            self.colors.text_muted,
        );
        x += label_w + 4.0;
        if let Some((color, urgent)) = dot {
            breathing_dot(
                painter,
                egui::pos2(x + 3.0, rect.center().y),
                color,
                t,
                urgent,
            );
            x += dot_w;
        }
        let value_rect = painter.text(
            egui::pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            value,
            egui::FontId::proportional(11.5),
            self.colors.text,
        );
        if let Some((text, color)) = suffix {
            painter.text(
                egui::pos2(value_rect.right() + 6.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                text,
                egui::FontId::proportional(11.5),
                color,
            );
        }

        response
    }

    fn strip_divider(&self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(1.0, TELEMETRY_H - 14.0), egui::Sense::hover());
        ui.painter().vline(
            rect.center().x,
            rect.y_range(),
            egui::Stroke::new(1.0, self.colors.border),
        );
        ui.add_space(12.0);
    }

    /// Persistent one-line event log + key hints and UTC clock.
    fn draw_status_line(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_centered(|ui| {
            ui.add_space(12.0);
            match &self.status {
                Status::None => {
                    ui.label(
                        egui::RichText::new("STATUS")
                            .font(label_font(9.5))
                            .color(self.colors.text_muted),
                    );
                    let t = ui.input(|i| i.time) as f32;
                    let (r, _) =
                        ui.allocate_exact_size(egui::vec2(8.0, 12.0), egui::Sense::hover());
                    blinking_cursor(
                        ui.painter(),
                        egui::pos2(r.left() + 1.0, r.center().y),
                        10.0,
                        self.colors.text_muted,
                        t,
                    );
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(120));
                }
                _ => self.show_status(ui),
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(12.0);
                ui.label(
                    egui::RichText::new(chrono::Utc::now().format("%H:%M:%S UTC").to_string())
                        .font(label_font(9.5))
                        .color(self.colors.text_muted),
                );
                ui.add_space(14.0);
                ui.label(
                    egui::RichText::new("KEYS 1-7 · MODULES")
                        .font(label_font(9.0))
                        .color(self.colors.text_muted),
                );
            });
        });
    }

    /// Slim left rail: numbered module codes, accent active state with
    /// a blinking cursor.
    fn draw_module_rail(&mut self, ui: &mut egui::Ui) {
        let t = ui.input(|i| i.time) as f32;
        ui.add_space(10.0);

        for (i, tab) in Tab::ALL.into_iter().enumerate() {
            let is_active = self.active_tab == tab;
            let response =
                ui.allocate_response(egui::vec2(ui.available_width(), 40.0), egui::Sense::click());
            if response.clicked() && self.active_tab != tab {
                self.reset_finished_tx_status();
                self.active_tab = tab;
            }

            let rect = response.rect;
            let painter = ui.painter();

            if is_active {
                painter.rect_filled(rect, 0.0, self.colors.accent_tint);
                painter.rect_filled(
                    egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height())),
                    0.0,
                    self.colors.accent,
                );
            } else if response.hovered() {
                painter.rect_filled(rect, 0.0, self.colors.surface2);
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }

            let code_color = if is_active {
                self.colors.accent
            } else if response.hovered() {
                self.colors.text
            } else {
                self.colors.text_muted
            };

            // Index number.
            painter.text(
                egui::pos2(rect.left() + 14.0, rect.top() + 13.0),
                egui::Align2::LEFT_CENTER,
                format!("{:02}", i + 1),
                label_font(8.0),
                self.colors.text_muted,
            );
            // Module code.
            let code_pos = egui::pos2(rect.left() + 34.0, rect.top() + 13.0);
            painter.text(
                code_pos,
                egui::Align2::LEFT_CENTER,
                tab.code(),
                label_font(12.0),
                code_color,
            );
            if is_active {
                let code_w = tab.code().len() as f32 * 9.0;
                blinking_cursor(
                    painter,
                    egui::pos2(code_pos.x + code_w + 5.0, code_pos.y),
                    11.0,
                    self.colors.accent,
                    t,
                );
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(120));
            }
            // Module name.
            painter.text(
                egui::pos2(rect.left() + 34.0, rect.top() + 28.0),
                egui::Align2::LEFT_CENTER,
                tab.name(),
                egui::FontId::proportional(9.5),
                if is_active {
                    self.colors.text
                } else {
                    self.colors.text_muted
                },
            );
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Setup — vault bootstrap terminal
    // ────────────────────────────────────────────────────────────────

    pub(crate) fn show_welcome(&mut self, ui: &mut egui::Ui) {
        let panel_w = 600.0;

        ui.vertical_centered(|ui| {
            ui.add_space(15.0);

            // The qp∞ mark at full size — the one place it gets room.
            let (logo, _) = ui.allocate_exact_size(egui::vec2(36.0, 36.0), egui::Sense::hover());
            draw_qp_logo_chip(ui.painter(), logo, self.colors.accent, self.colors.bg);
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new("QUANTUM PURSE // POST-QUANTUM HARDENED // NERVOS CKB")
                    .font(label_font(10.0))
                    .color(self.colors.text_muted),
            );

            ui.add_space(15.0);

            ui.allocate_ui_with_layout(
                egui::vec2(panel_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    // Each section sits in its own panel with the dark
                    // background showing between them, so the areas read
                    // as separate blocks rather than one run-on column
                    // under tiny headers.
                    let gap = 10.0;
                    let inner_w = panel_w - 30.0;

                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.set_width(inner_w);
                        section_header(ui, &self.colors, "01", "Parameter Set");
                        ui.add_space(8.0);
                        self.draw_variant_grid(ui, inner_w);
                    });
                    ui.add_space(gap);

                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.set_width(inner_w);
                        section_header(ui, &self.colors, "02", "Create New Wallet");
                        ui.add_space(8.0);
                        self.draw_auth_row(ui, inner_w, false);
                    });
                    ui.add_space(gap);

                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.set_width(inner_w);
                        section_header(ui, &self.colors, "03", "Connect Hardware Wallet");
                        ui.add_space(8.0);
                        self.draw_trezor_connect_button(ui, inner_w);
                    });
                    ui.add_space(gap);

                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.set_width(inner_w);
                        section_header(ui, &self.colors, "04", "Restore From Seed Phrase");
                        ui.add_space(8.0);
                        // v1 web-wallet mnemonics derive the same keys but
                        // need the v1 single-sig address format for existing
                        // funds to stay visible.
                        v1_import_checkbox(ui, &self.colors, &mut self.import_from_v1);
                        ui.add_space(8.0);
                        self.draw_auth_row(ui, inner_w, true);
                    });
                },
            );

            ui.add_space(16.0);
            // Same centered block width as the panel above, so the
            // status line's left edge aligns with the panel's.
            ui.allocate_ui_with_layout(
                egui::vec2(panel_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| self.show_status(ui),
            );
        });
    }

    /// 6×2 table of SPHINCS+ parameter-set cells with shared hairline
    /// borders, so the picker reads as one unit instead of twelve chips.
    fn draw_variant_grid(&mut self, ui: &mut egui::Ui, width: f32) {
        // Row-major, so the first six are the top row (SHA2) and the
        // last six the bottom row (SHAKE): one hash family per line.
        const VARIANTS: [SpxVariant; 12] = [
            SpxVariant::Sha2128S,
            SpxVariant::Sha2128F,
            SpxVariant::Sha2192S,
            SpxVariant::Sha2192F,
            SpxVariant::Sha2256S,
            SpxVariant::Sha2256F,
            SpxVariant::Shake128S,
            SpxVariant::Shake128F,
            SpxVariant::Shake192S,
            SpxVariant::Shake192F,
            SpxVariant::Shake256S,
            SpxVariant::Shake256F,
        ];

        let cell_w = width / 6.0;
        let cell_h = 24.0;

        let (grid, response) =
            ui.allocate_exact_size(egui::vec2(width, 2.0 * cell_h), egui::Sense::click());

        let cell_rect = |row: usize, col: usize| {
            egui::Rect::from_min_size(
                grid.min + egui::vec2(col as f32 * cell_w, row as f32 * cell_h),
                egui::vec2(cell_w, cell_h),
            )
        };
        let cell_at = |pos: egui::Pos2| {
            let rel = pos - grid.min;
            (
                ((rel.y / cell_h).floor() as usize).min(1),
                ((rel.x / cell_w).floor() as usize).min(5),
            )
        };

        let hovered = response.hover_pos().map(cell_at);
        if hovered.is_some() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if response.clicked() {
            if let Some(pos) = response.interact_pointer_pos() {
                let (row, col) = cell_at(pos);
                self.selected_variant = VARIANTS[row * 6 + col];
            }
        }

        let painter = ui.painter();

        // Shared interior hairlines plus one outer border, so cells
        // form a contiguous table instead of separated chips.
        let hairline = egui::Stroke::new(1.0, self.colors.border);
        for col in 1..6 {
            let x = grid.left() + col as f32 * cell_w;
            painter.vline(x, grid.y_range(), hairline);
        }
        painter.hline(grid.x_range(), grid.center().y, hairline);
        painter.rect_stroke(grid, 0.0, hairline, egui::StrokeKind::Inside);

        for row in 0..2 {
            for col in 0..6 {
                let variant = VARIANTS[row * 6 + col];
                let selected = self.selected_variant == variant;
                let is_hovered = hovered == Some((row, col));
                let rect = cell_rect(row, col);

                if selected {
                    painter.rect_filled(rect, 0.0, self.colors.accent_tint);
                    painter.rect_stroke(
                        rect,
                        0.0,
                        egui::Stroke::new(1.0, self.colors.accent),
                        egui::StrokeKind::Inside,
                    );
                } else if is_hovered {
                    painter.rect_stroke(
                        rect,
                        0.0,
                        egui::Stroke::new(1.0, self.colors.border2),
                        egui::StrokeKind::Inside,
                    );
                }

                let (hash, param) = variant_parts(variant);
                let text_color = if selected {
                    self.colors.accent
                } else if is_hovered {
                    self.colors.text
                } else {
                    self.colors.text_muted
                };
                painter.text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    format!("{}-{}", hash, param),
                    label_font(10.0),
                    text_color,
                );
            }
        }
    }

    /// A single full-width button that imports accounts from a connected
    /// Trezor as a new watch-only wallet. While the import runs the button
    /// waits and points the user at the device, which is where the PIN and
    /// address confirmations are answered.
    fn draw_trezor_connect_button(&mut self, ui: &mut egui::Ui, width: f32) {
        let size = egui::vec2(width, 34.0);
        let waiting = self.trezor_import_rx.is_some();
        ui.horizontal(|ui| {
            let btn = ghost_button(&self.colors, "Connect Trezor", size);
            if ui.add_enabled(!waiting, btn).clicked() {
                self.create_trezor_watch_only_wallet(self.selected_variant, 1);
            }
        });
        if waiting {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let t = ui.input(|i| i.time) as f32;
                // Amber, and pulsing at the urgent rate: everything else on
                // this screen is cyan chrome or muted body text, so the one
                // line that is waiting on the user has the panel's only warm
                // colour. Accent cyan would have read as decoration.
                let attention = self.colors.warn;
                let (dot, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                breathing_dot(ui.painter(), dot.center(), attention, t, true);
                ui.label(
                    egui::RichText::new("Follow the instructions on your Trezor's screen.")
                        .font(label_font(10.0))
                        .color(attention),
                );
            });
        }
    }

    /// One row of three auth-method buttons (create or import).
    fn draw_auth_row(&mut self, ui: &mut egui::Ui, width: f32, import: bool) {
        let gap = 6.0;
        let btn_w = (width - 2.0 * gap) / 3.0;
        let size = egui::vec2(btn_w, 34.0);
        // A Trezor import in flight owns both the device and this screen's
        // outcome. Finishing another wallet here would strand that worker
        // mid-conversation, and it keeps the device claimed until it returns
        // — the next Trezor action would then fail as "in use by another
        // application". Cheaper to not let the two races start.
        let device_busy = self.trezor_import_rx.is_some();
        let labels = [
            keychain::short_name().to_string(),
            "Security Key".to_string(),
            "Password".to_string(),
        ];

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for (idx, label) in labels.iter().enumerate() {
                // Uniform ghost buttons: a solid one would read as a
                // selected state next to the parameter grid above,
                // and these are actions, not options.
                let btn = ghost_button(&self.colors, label, size);
                if ui.add_enabled(!device_busy, btn).clicked() {
                    let v = self.selected_variant;
                    let ssc = SingleSigConvention::new(self.import_from_v1);
                    match (import, idx) {
                        (false, 0) => self.create_wallet_with_keychain(v),
                        (false, 1) => self.create_wallet_with_fido2(v),
                        (false, _) => self.create_wallet_with_password(v),
                        (true, 0) => self.import_seed_phrase_with_keychain(v, ssc),
                        (true, 1) => self.import_seed_phrase_with_fido2(v, ssc),
                        (true, _) => self.import_seed_phrase_with_password(v, ssc),
                    }
                    // The v1 choice is consumed by this action; a stale
                    // `true` would pre-check the box on the next import.
                    self.import_from_v1 = false;
                }
            }
        });
    }

    // ────────────────────────────────────────────────────────────────
    // Locked — secure terminal login
    // ────────────────────────────────────────────────────────────────

    pub(crate) fn show_locked(&mut self, ui: &mut egui::Ui) {
        let t = ui.input(|i| i.time) as f32;
        let panel_w = 520.0;

        let variant = self
            .wallet_cache
            .iter()
            .find(|w| w.id == self.wallet_id)
            .map(|cw| format!("SPHINCS+ {}", cw.spx_variant))
            .unwrap_or_else(|| "SPHINCS+".to_string());

        ui.vertical_centered(|ui| {
            ui.add_space(90.0);

            ui.label(
                egui::RichText::new("POST QUANTUM HARDENED, POWERED BY CKB")
                    .font(label_font(10.0))
                    .color(self.colors.text_muted),
            );
            ui.add_space(14.0);

            ui.allocate_ui_with_layout(
                egui::vec2(panel_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.set_width(panel_w - 30.0);

                        boot_lines(
                            ui,
                            "locked-boot",
                            &format!(
                                "> VAULT .......... {}\n\
                                 > SCHEME ......... {}\n\
                                 > STATUS ......... SEALED",
                                self.wallet_name.to_uppercase(),
                                variant,
                            ),
                            90.0,
                            11.5,
                            self.colors.text_muted,
                        );

                        ui.add_space(18.0);

                        // The prompt: > AUTHENTICATE ▮
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("> AUTHENTICATE")
                                    .font(display_font(22.0))
                                    .color(self.colors.accent),
                            );
                            let (r, _) = ui
                                .allocate_exact_size(egui::vec2(16.0, 24.0), egui::Sense::hover());
                            blinking_cursor(
                                ui.painter(),
                                egui::pos2(r.left() + 4.0, r.center().y + 1.0),
                                18.0,
                                self.colors.accent,
                                t,
                            );
                            ui.ctx()
                                .request_repaint_after(std::time::Duration::from_millis(120));
                        });

                        ui.add_space(18.0);

                        let full_w = panel_w - 30.0;
                        match &self.auth_method {
                            Some(AuthMethod::Fido2 { credential_id }) => {
                                let cred_id = credential_id.clone();
                                let btn = accent_button(
                                    &self.colors,
                                    "Unlock // Security Key",
                                    egui::vec2(full_w, 42.0),
                                );
                                if ui.add(btn).clicked() {
                                    self.unlock_with_fido2(&cred_id);
                                }
                            }
                            Some(AuthMethod::Keychain) => {
                                let label = format!("Unlock // {}", keychain::short_name());
                                let btn =
                                    accent_button(&self.colors, &label, egui::vec2(full_w, 42.0));
                                if ui.add(btn).clicked() {
                                    self.unlock_with_keychain();
                                }
                            }
                            Some(AuthMethod::Trezor { .. }) => {
                                let btn = accent_button(
                                    &self.colors,
                                    "Open // Watch-only",
                                    egui::vec2(full_w, 42.0),
                                );
                                if ui.add(btn).clicked() {
                                    let id = self.wallet_id;
                                    let name = self.wallet_name.clone();
                                    self.switch_wallet(id, &name);
                                }
                            }
                            // Unreachable: Password skips the startup gate and
                            // has no LOCK button, and `list_wallets` drops any
                            // wallet whose info cannot be read, so `auth_method`
                            // is `Some` for anything that gets this far. Listed
                            // explicitly rather than `_` so that adding an auth
                            // method fails to compile here instead of silently
                            // rendering a screen with nothing to click.
                            Some(AuthMethod::Password) | None => {}
                        }
                    });
                },
            );

            ui.add_space(16.0);
            // Same centered block width as the panel above, so the
            // status line's left edge aligns with the panel's.
            ui.allocate_ui_with_layout(
                egui::vec2(panel_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| self.show_status(ui),
            );
        });
    }
}

/// Type-on boot lines in a fixed-size slot: the full text is measured
/// up front and its rect allocated immediately, so the reveal animation
/// never reflows the content below it.
fn boot_lines(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    text: &str,
    cps: f64,
    size: f32,
    color: egui::Color32,
) {
    let typed = type_on(ui, id, text, cps);
    let font = egui::FontId::proportional(size);
    let full = ui
        .painter()
        .layout_no_wrap(text.to_string(), font.clone(), color);
    let (rect, _) = ui.allocate_exact_size(full.size(), egui::Sense::hover());
    ui.painter()
        .text(rect.left_top(), egui::Align2::LEFT_TOP, typed, font, color);
}

/// The Quantum Purse mark: two rings forming a centred figure-eight (the
/// qp∞ infinity) with short q/p descenders dropping from the crossing.
/// A procedural rebuild of `assets/icon/icon.svg` — painter strokes only,
/// so it is resolution-independent and identical across platforms with no
/// font or image asset involved. Fractions are relative to the (square)
/// chip rect.
fn draw_qp_mark(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let s = rect.width().min(rect.height());
    let o = rect.left_top();
    let p = |x: f32, y: f32| egui::pos2(o.x + x * s, o.y + y * s);

    // The two infinity lobes, vertically centred.
    let ring = egui::Stroke::new((s * 0.066).max(1.4), color);
    let r = s * 0.198;
    painter.circle_stroke(p(0.323, 0.5), r, ring);
    painter.circle_stroke(p(0.677, 0.5), r, ring);

    // Descenders poking out the bottom of the crossing. Drawn longer than
    // icon.svg's tail (which ends ~0.73) so the tail still reads at the
    // 22px strip size, where the canonical short tail is sub-pixel.
    let stem = egui::Stroke::new((s * 0.061).max(1.3), color);
    painter.line_segment([p(0.481, 0.582), p(0.481, 0.77)], stem);
    painter.line_segment([p(0.519, 0.582), p(0.519, 0.77)], stem);
}

/// The app chip: solid accent rounded square with the qp∞ mark knocked
/// out in the canvas color, mirroring `assets/icon/icon.svg`. The icon's
/// gradient fill is rendered as a flat accent here — egui has no gradient
/// fill primitive and the difference is imperceptible at chip size.
fn draw_qp_logo_chip(
    painter: &egui::Painter,
    rect: egui::Rect,
    chip: egui::Color32,
    mark: egui::Color32,
) {
    let s = rect.width().min(rect.height());
    painter.rect_filled(rect, s * 0.222, chip);
    draw_qp_mark(painter, rect, mark);
    // Diagonal weave cut re-shows the chip color through the crossing.
    // Drawn heavier than icon.svg's thread (0.035) so it still reads at
    // the 22–56px sizes this chip renders at — a small-size optical bump.
    let o = rect.left_top();
    let p = |x: f32, y: f32| egui::pos2(o.x + x * s, o.y + y * s);
    painter.line_segment(
        [p(0.448, 0.568), p(0.552, 0.432)],
        egui::Stroke::new((s * 0.052).max(1.4), chip),
    );
}

/// Reveal `text` progressively at `cps` characters per second from the
/// first frame this id is seen — the terminal type-on effect.
fn type_on(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    text: &str,
    cps: f64,
) -> String {
    let id = egui::Id::new(id);
    let now = ui.input(|i| i.time);
    let start = ui
        .ctx()
        .memory_mut(|m| *m.data.get_temp_mut_or_insert_with(id, || now));
    let shown = ((now - start) * cps).max(0.0) as usize;
    if shown < text.chars().count() {
        ui.ctx().request_repaint();
        text.chars().take(shown).collect()
    } else {
        text.to_string()
    }
}

fn variant_parts(v: SpxVariant) -> (&'static str, &'static str) {
    match v {
        SpxVariant::Sha2128S => ("SHA2", "128S"),
        SpxVariant::Sha2128F => ("SHA2", "128F"),
        SpxVariant::Shake128S => ("SHAKE", "128S"),
        SpxVariant::Shake128F => ("SHAKE", "128F"),
        SpxVariant::Sha2192S => ("SHA2", "192S"),
        SpxVariant::Sha2192F => ("SHA2", "192F"),
        SpxVariant::Shake192S => ("SHAKE", "192S"),
        SpxVariant::Shake192F => ("SHAKE", "192F"),
        SpxVariant::Sha2256S => ("SHA2", "256S"),
        SpxVariant::Sha2256F => ("SHA2", "256F"),
        SpxVariant::Shake256S => ("SHAKE", "256S"),
        SpxVariant::Shake256F => ("SHAKE", "256F"),
    }
}
