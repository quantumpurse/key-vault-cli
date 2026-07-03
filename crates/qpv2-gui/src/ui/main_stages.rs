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

impl App {
    // ────────────────────────────────────────────────────────────────
    // Unlocked chrome
    // ────────────────────────────────────────────────────────────────

    pub(crate) fn show_unlocked(&mut self, ctx: &egui::Context) {
        self.handle_module_shortcuts(ctx);

        // ── Top telemetry strip ──
        egui::TopBottomPanel::top("telemetry")
            .exact_height(TELEMETRY_H)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(self.colors.surface))
            .show(ctx, |ui| {
                self.draw_telemetry_strip(ui);
                let r = ui.clip_rect();
                ui.painter().hline(
                    r.x_range(),
                    r.bottom() - 0.5,
                    egui::Stroke::new(1.0, self.colors.border),
                );
            });

        // ── Bottom status line ──
        egui::TopBottomPanel::bottom("statusline")
            .exact_height(STATUSLINE_H)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(self.colors.surface))
            .show(ctx, |ui| {
                self.draw_status_line(ui);
                let r = ui.clip_rect();
                ui.painter().hline(
                    r.x_range(),
                    r.top() + 0.5,
                    egui::Stroke::new(1.0, self.colors.border),
                );
            });

        // ── Left module rail ──
        egui::SidePanel::left("rail")
            .resizable(false)
            .show_separator_line(false)
            .exact_width(RAIL_W)
            .frame(egui::Frame::new().fill(self.colors.surface))
            .show(ctx, |ui| {
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
            .show(ctx, |ui| {
                self.draw_unlocked_bg(ui);

                egui::ScrollArea::vertical()
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
    fn draw_telemetry_strip(&mut self, ui: &mut egui::Ui) {
        let c_accent = self.colors.accent;
        let c_bg = self.colors.bg;
        let c_text = self.colors.text;
        let c_muted = self.colors.text_muted;
        let t = ui.input(|i| i.time) as f32;

        ui.horizontal_centered(|ui| {
            ui.add_space(12.0);

            // Ident block: the qp∞ mark knocked out of the accent chip.
            let (logo, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
            draw_qp_logo_chip(ui.painter(), logo, c_accent, c_bg);
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("QUANTUM PURSE")
                    .font(display_font(12.0))
                    .color(c_text),
            );
            ui.label(
                egui::RichText::new("V2")
                    .font(label_font(9.0))
                    .color(c_muted),
            );

            self.strip_divider(ui);

            // ── Node segment (clickable → node selector) ──
            let node_name = match self.qp_client.config().node_type {
                NodeType::PublicRpc => "REMOTE RPC",
                NodeType::LightClient => "LIGHT CLIENT",
                NodeType::FullNode => "FULL NODE",
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
                seg.rect.right_center() + egui::vec2(2.0, 0.0),
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

            self.strip_divider(ui);

            // ── Tip block (flashes on change) ──
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
            let tip_color = crate::ui::utils::lerp_color(c_accent, c_text, flash);
            ui.label(egui::RichText::new(tip_text).size(11.5).color(tip_color));

            // Peer count, when the backend reports peers.
            if !self.node_status.peers.is_empty() {
                self.strip_divider(ui);
                ui.label(
                    egui::RichText::new("PEERS")
                        .font(label_font(9.0))
                        .color(c_muted),
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

            // ── Right side: lock + wallet ──
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(12.0);

                if matches!(
                    self.auth_method,
                    Some(AuthMethod::Keychain) | Some(AuthMethod::Fido2 { .. })
                ) {
                    let lock = ghost_button(&self.colors, "LOCK", egui::vec2(56.0, 22.0));
                    if ui.add(lock).clicked() {
                        self.lock_wallet();
                    }
                    ui.add_space(10.0);
                }

                let variant = self
                    .wallet_cache
                    .iter()
                    .find(|w| w.id == self.wallet_id)
                    .map(|cw| format!("{}", cw.spx_variant));
                let wallet_text = match &variant {
                    Some(v) => format!("{} / {}", self.wallet_name.to_uppercase(), v),
                    None => self.wallet_name.to_uppercase(),
                };
                // Dropdown arrow, mirroring the node selector's. RTL
                // flow: allocated before the segment so it renders to
                // the segment's right, clear of the LOCK button.
                let (arrow, arrow_resp) = ui.allocate_exact_size(
                    egui::vec2(14.0, TELEMETRY_H - 10.0),
                    egui::Sense::click(),
                );
                ui.painter().text(
                    arrow.center(),
                    egui::Align2::CENTER_CENTER,
                    "▾",
                    egui::FontId::proportional(16.0),
                    c_muted,
                );
                let seg = self.strip_segment(ui, "VAULT", &wallet_text, None, None, t);
                self.wallet_selector_rect = Some(seg.rect);
                if seg.clicked() || arrow_resp.clicked() {
                    self.wallet_selector_open = !self.wallet_selector_open;
                    self.node_selector_open = false;
                }
            });
        });
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
                        egui::RichText::new("READY")
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
        let panel_w = 680.0;

        ui.vertical_centered(|ui| {
            ui.add_space(32.0);

            // The qp∞ mark at full size — the one place it gets room.
            let (logo, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            draw_qp_logo_chip(ui.painter(), logo, self.colors.accent, self.colors.bg);
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new("QUANTUM PURSE")
                    .font(display_font(28.0))
                    .color(self.colors.accent),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("POST-QUANTUM VAULT // NERVOS CKB")
                    .font(label_font(10.0))
                    .color(self.colors.text_muted),
            );

            ui.add_space(20.0);

            ui.allocate_ui_with_layout(
                egui::vec2(panel_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    panel_frame(&self.colors).show(ui, |ui| {
                        ui.set_width(panel_w - 30.0);

                        boot_lines(
                            ui,
                            "setup-boot",
                            "> SPHINCS+ SIGNATURE SUITE ............ READY\n\
                             > SCANNING FOR LOCAL VAULT ............ NONE FOUND\n\
                             > SELECT PARAMETER SET AND INITIALIZE",
                            90.0,
                            11.0,
                            self.colors.text_muted,
                        );
                        ui.add_space(14.0);

                        section_header(ui, &self.colors, "01", "Parameter Set");
                        ui.add_space(8.0);
                        self.draw_variant_grid(ui, panel_w - 30.0);

                        ui.add_space(16.0);
                        section_header(ui, &self.colors, "02", "Initialize New Vault");
                        ui.add_space(8.0);
                        self.draw_auth_row(ui, panel_w - 30.0, false);

                        ui.add_space(16.0);
                        section_header(ui, &self.colors, "03", "Restore From Seed Phrase");
                        ui.add_space(8.0);
                        // v1 web-wallet mnemonics derive the same keys but
                        // need the v1 single-sig address format for existing
                        // funds to stay visible.
                        v1_import_checkbox(ui, &self.colors, &mut self.import_from_v1);
                        ui.add_space(8.0);
                        self.draw_auth_row(ui, panel_w - 30.0, true);
                    });
                },
            );

            ui.add_space(16.0);
            ui.vertical_centered(|ui| self.show_status(ui));
        });
    }

    /// 4×3 grid of SPHINCS+ parameter-set cells.
    fn draw_variant_grid(&mut self, ui: &mut egui::Ui, width: f32) {
        const VARIANTS: [SpxVariant; 12] = [
            SpxVariant::Sha2128S,
            SpxVariant::Sha2128F,
            SpxVariant::Shake128S,
            SpxVariant::Shake128F,
            SpxVariant::Sha2192S,
            SpxVariant::Sha2192F,
            SpxVariant::Shake192S,
            SpxVariant::Shake192F,
            SpxVariant::Sha2256S,
            SpxVariant::Sha2256F,
            SpxVariant::Shake256S,
            SpxVariant::Shake256F,
        ];

        let gap = 6.0;
        let cell_w = (width - 3.0 * gap) / 4.0;
        let cell_h = 30.0;

        for row in 0..3 {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for col in 0..4 {
                    let variant = VARIANTS[row * 4 + col];
                    let selected = self.selected_variant == variant;
                    let (rect, response) =
                        ui.allocate_exact_size(egui::vec2(cell_w, cell_h), egui::Sense::click());
                    if response.clicked() {
                        self.selected_variant = variant;
                    }

                    let painter = ui.painter();
                    let (hash, param) = variant_parts(variant);

                    if selected {
                        painter.rect_filled(rect, 0.0, self.colors.accent_tint);
                        painter.rect_stroke(
                            rect,
                            0.0,
                            egui::Stroke::new(1.0, self.colors.accent),
                            egui::StrokeKind::Inside,
                        );
                    } else {
                        painter.rect_stroke(
                            rect,
                            0.0,
                            egui::Stroke::new(
                                1.0,
                                if response.hovered() {
                                    self.colors.border2
                                } else {
                                    self.colors.border
                                },
                            ),
                            egui::StrokeKind::Inside,
                        );
                    }
                    if response.hovered() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }

                    let text_color = if selected {
                        self.colors.accent
                    } else if response.hovered() {
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
            });
            if row < 2 {
                ui.add_space(gap);
            }
        }
    }

    /// One row of three auth-method buttons (create or import).
    fn draw_auth_row(&mut self, ui: &mut egui::Ui, width: f32, import: bool) {
        let gap = 6.0;
        let btn_w = (width - 2.0 * gap) / 3.0;
        let size = egui::vec2(btn_w, 34.0);
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
                if ui.add(btn).clicked() {
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
                            _ => {}
                        }
                    });
                },
            );

            ui.add_space(16.0);
            ui.vertical_centered(|ui| self.show_status(ui));
        });
    }
}

/// Type-on boot lines in a fixed-size slot: the full text is measured
/// up front and its rect allocated immediately, so the reveal animation
/// never reflows the content below it.
fn boot_lines(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
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
fn type_on(ui: &mut egui::Ui, id: impl std::hash::Hash, text: &str, cps: f64) -> String {
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
