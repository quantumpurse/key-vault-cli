//! Wallets tab rendering — vault registry: create, import, export,
//! rename, switch, and delete wallets.

use eframe::egui;
use qpv2_core::types::{AuthMethod, SingleSigConvention};
use qpv2_core::KeyVault;

use super::accounts::{header_cell, table_rule};
use super::utils::truncate_middle;
use super::utils::{
    accent_button, badge, breathing_dot, ghost_button, panel_frame, row_hover, section_header,
};
use crate::types::{display_font, label_font, Status};
use crate::App;

const COL_NAME: f32 = 210.0;
const COL_VAR: f32 = 110.0;
const COL_AUTH: f32 = 100.0;
const COL_ACCT: f32 = 56.0;
const ROW_H: f32 = 32.0;
/// Width reserved for the right-aligned SWITCH / DELETE actions.
const ACTIONS_W: f32 = 160.0;
/// Hold duration on DELETE before a wallet is removed — destructive,
/// so a plain click must never be enough.
const HOLD_SECS: f64 = 2.0;

impl App {
    pub(crate) fn show_wallets_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 24.0);

                ui.label(
                    egui::RichText::new("WALLETS")
                        .font(display_font(16.0))
                        .color(self.colors.text),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "Create, import, rename, switch, and remove local wallets.",
                    )
                    .size(11.0)
                    .color(self.colors.text_muted),
                );
                ui.add_space(14.0);

                // Targets are collected during the loop and applied after
                // it: the handlers mutate `wallet_cache` (the Vec being
                // iterated) via `refresh_wallet_cache` / `switch_wallet`.
                let mut delete_target: Option<u32> = None;
                let mut rename_target: Option<(u32, String)> = None;
                let mut switch_target: Option<(u32, String)> = None;

                panel_frame(&self.colors).show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    ui.horizontal(|ui| {
                        // NEW WALLET (solid accent) + IMPORT / EXPORT SEED (ghost).
                        let btns_w = 120.0 + 80.0 + 110.0 + 3.0 * 8.0;
                        let header_w = (ui.available_width() - btns_w).max(0.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(header_w, 24.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                section_header(
                                    ui,
                                    &self.colors,
                                    "01",
                                    &format!("Vault Registry // {}", self.wallet_cache.len()),
                                );
                            },
                        );
                        let export =
                            ghost_button(&self.colors, "EXPORT SEED", egui::vec2(110.0, 24.0));
                        if ui
                            .add(export)
                            .on_hover_text("Reveal the active wallet's seed phrase")
                            .clicked()
                        {
                            self.export_seed_phrase();
                        }
                        let import = ghost_button(&self.colors, "IMPORT", egui::vec2(80.0, 24.0));
                        if ui
                            .add(import)
                            .on_hover_text("Restore a wallet from a seed phrase")
                            .clicked()
                        {
                            self.wallet_modal = crate::types::WalletModal::Import;
                            self.new_wallet_name.clear();
                            self.new_wallet_variant = qpv2_core::types::SpxVariant::Sha2128S;
                            self.import_from_v1 = false;
                        }
                        let create =
                            accent_button(&self.colors, "NEW WALLET", egui::vec2(120.0, 24.0));
                        if ui.add(create).clicked() {
                            self.wallet_modal = crate::types::WalletModal::Create;
                            self.new_wallet_name.clear();
                            self.new_wallet_variant = qpv2_core::types::SpxVariant::Sha2128S;
                            self.import_from_v1 = false;
                        }
                    });
                    ui.add_space(10.0);

                    if self.wallet_cache.is_empty() {
                        ui.label(
                            egui::RichText::new("NO VAULTS REGISTERED — CREATE ONE TO BEGIN.")
                                .font(label_font(9.5))
                                .color(self.colors.text_muted),
                        );
                    } else {
                        self.wallets_table(
                            ui,
                            &mut delete_target,
                            &mut rename_target,
                            &mut switch_target,
                        );
                    }
                });

                if let Some(id) = delete_target {
                    let _ = keychain::delete_key(id);
                    let lock_args = KeyVault::get_all_lock_args(id).unwrap_or_default();
                    let _ = ckb_node::wallet_helpers::lc::clear_wallet_scripts(
                        &self.qp_client,
                        &lock_args,
                    );

                    match KeyVault::remove_wallet(id) {
                        Ok(()) => {
                            if id == self.wallet_id {
                                self.lock_wallet();
                                self.refresh_wallet_cache();
                                if let Some(first) = self.wallet_cache.first() {
                                    let fid = first.id;
                                    let fname = first.name.clone();
                                    self.switch_wallet(fid, &fname);
                                } else {
                                    self.wallet_id = 0;
                                    self.wallet_name.clear();
                                    self.screen = crate::types::Screen::Setup;
                                }
                            } else {
                                self.refresh_wallet_cache();
                            }
                            self.status = Status::Info("Wallet removed successfully.".to_string());
                        }
                        Err(e) => {
                            let msg = format!("Failed to remove wallet: {}", e);
                            tracing::error!("{}", msg);
                            self.status = Status::Error(msg);
                        }
                    }
                }

                if let Some((id, new_name)) = rename_target {
                    let trimmed = new_name.trim();
                    match qpv2_core::db::wallets::rename_wallet(id, trimmed) {
                        Ok(()) => {
                            if id == self.wallet_id {
                                self.wallet_name = trimmed.to_string();
                            }
                            self.refresh_wallet_cache();
                            self.status = Status::Info(format!("Wallet renamed to '{}'.", trimmed));
                        }
                        Err(e) => {
                            let msg = format!("Failed to rename wallet: {}", e);
                            tracing::error!("{}", msg);
                            self.status = Status::Error(msg);
                        }
                    }
                    self.rename_wallet_id = None;
                    self.rename_wallet_buf.clear();
                }

                if let Some((id, name)) = switch_target {
                    self.switch_wallet(id, &name);
                }

                ui.add_space(20.0);
            });
        });
    }

    fn wallets_table(
        &mut self,
        ui: &mut egui::Ui,
        delete_target: &mut Option<u32>,
        rename_target: &mut Option<(u32, String)>,
        switch_target: &mut Option<(u32, String)>,
    ) {
        ui.scope(|ui| {
            // Rows must sit flush against their hairlines.
            ui.spacing_mut().item_spacing.y = 0.0;

            ui.horizontal(|ui| {
                ui.add_space(6.0);
                header_cell(ui, &self.colors, COL_NAME, "NAME", false);
                header_cell(ui, &self.colors, COL_VAR, "VARIANT", false);
                header_cell(ui, &self.colors, COL_AUTH, "AUTH", false);
                header_cell(ui, &self.colors, COL_ACCT, "ACCTS", false);
                header_cell(ui, &self.colors, 120.0, "PATH", false);
            });
            ui.add_space(4.0);
            table_rule(ui, &self.colors);

            for i in 0..self.wallet_cache.len() {
                // Snapshot the row fields so the cell closures don't hold a
                // borrow of `wallet_cache` while mutating rename state.
                let cw = &self.wallet_cache[i];
                let cw_id = cw.id;
                let cw_name = cw.name.clone();
                let cw_variant = format!("{}", cw.spx_variant);
                let auth_label = match &cw.auth_method {
                    AuthMethod::Password => "PASSWORD".to_string(),
                    AuthMethod::Keychain => keychain::short_name().to_string(),
                    AuthMethod::Fido2 { .. } => "FIDO2".to_string(),
                    AuthMethod::Trezor { .. } => "TREZOR".to_string(),
                };
                let cw_is_v1 = cw.single_sig_convention == SingleSigConvention::V1;
                let cw_acct_count = cw.account_count;
                let cw_path = cw.path.clone();
                let is_active = cw_id == self.wallet_id;

                let full_w = ui.available_width();
                let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(full_w, ROW_H));
                if is_active {
                    // Persistent variant of the hover treatment: tint
                    // fill plus a 2px accent left tick.
                    ui.painter().rect_filled(rect, 0.0, self.colors.accent_tint);
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height())),
                        0.0,
                        self.colors.accent,
                    );
                } else if ui.rect_contains_pointer(rect) {
                    row_hover(ui.painter(), rect, &self.colors);
                }

                ui.allocate_ui_with_layout(
                    egui::vec2(full_w, ROW_H),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        // Keep content clear of the 2px tick.
                        ui.add_space(6.0);

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_NAME, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                // Pin to the column width (see header_cell).
                                ui.set_min_width(COL_NAME);
                                if self.rename_wallet_id == Some(cw_id) {
                                    let field =
                                        egui::TextEdit::singleline(&mut self.rename_wallet_buf)
                                            .desired_width(118.0)
                                            .font(egui::FontId::monospace(11.0));
                                    let response = ui.add(field);
                                    if response.lost_focus()
                                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                    {
                                        *rename_target =
                                            Some((cw_id, self.rename_wallet_buf.clone()));
                                    }
                                    let ok =
                                        ghost_button(&self.colors, "OK", egui::vec2(30.0, 18.0));
                                    if ui.add(ok).clicked() {
                                        *rename_target =
                                            Some((cw_id, self.rename_wallet_buf.clone()));
                                    }
                                    let cancel = egui::Button::new(
                                        egui::RichText::new("X")
                                            .font(label_font(9.0))
                                            .color(self.colors.text_muted),
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0, self.colors.border))
                                    .corner_radius(0.0)
                                    .min_size(egui::vec2(22.0, 18.0));
                                    if ui.add(cancel).clicked() {
                                        self.rename_wallet_id = None;
                                        self.rename_wallet_buf.clear();
                                    }
                                } else {
                                    let label = egui::Label::new(
                                        egui::RichText::new(&cw_name)
                                            .size(11.5)
                                            .color(self.colors.text),
                                    )
                                    .sense(egui::Sense::click());
                                    let resp = ui
                                        .add(label)
                                        .on_hover_text("Click to rename")
                                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                                    if resp.clicked() {
                                        self.rename_wallet_id = Some(cw_id);
                                        self.rename_wallet_buf = cw_name.clone();
                                    }
                                }
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_VAR, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_VAR);
                                badge(ui, &cw_variant, self.colors.accent3);
                                // Imported v1 web-wallet vaults use the v1
                                // single-sig address format; flag them so a
                                // wrong import choice is diagnosable.
                                if cw_is_v1 {
                                    ui.add_space(4.0);
                                    badge(ui, "V1", self.colors.warn);
                                }
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_AUTH, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_AUTH);
                                badge(ui, &auth_label, self.colors.text_muted);
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_ACCT, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_ACCT);
                                ui.label(
                                    egui::RichText::new(format!("{}", cw_acct_count))
                                        .size(11.5)
                                        .color(self.colors.text),
                                );
                            },
                        );

                        let path_w = (ui.available_width() - ACTIONS_W).max(60.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(path_w, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(path_w);
                                ui.add(egui::Label::new(
                                    egui::RichText::new(truncate_middle(&cw_path, 14, 16))
                                        .size(10.5)
                                        .color(self.colors.text_muted),
                                ))
                                .on_hover_text(&cw_path);
                            },
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(6.0);
                            self.delete_hold_button(ui, cw_id, delete_target);
                            ui.add_space(4.0);
                            if is_active {
                                // Solid accent marker in the SWITCH slot:
                                // unmistakably "this one is live", and the
                                // action column stays on one grid.
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(64.0, 20.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(rect, 0.0, self.colors.accent);
                                ui.painter().text(
                                    rect.center(),
                                    egui::Align2::CENTER_CENTER,
                                    "ACTIVE",
                                    label_font(9.0),
                                    self.colors.bg,
                                );
                            } else {
                                let sw =
                                    ghost_button(&self.colors, "SWITCH", egui::vec2(64.0, 20.0));
                                if ui.add(sw).clicked() {
                                    *switch_target = Some((cw_id, cw_name.clone()));
                                }
                            }
                        });
                    },
                );

                table_rule(ui, &self.colors);
            }
        });
    }

    /// Ghost-style DELETE in semantic red that must be held for
    /// `HOLD_SECS` — a flat progress fill sweeps across while held, so
    /// the confirmation gesture is visible at all times.
    fn delete_hold_button(
        &self,
        ui: &mut egui::Ui,
        wallet_id: u32,
        delete_target: &mut Option<u32>,
    ) {
        let c = self.colors.danger;
        let btn = egui::Button::new(
            egui::RichText::new("DELETE")
                .font(label_font(11.0))
                .color(c),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 90),
        ))
        .corner_radius(0.0)
        .min_size(egui::vec2(64.0, 20.0));

        let del_id = ui.id().with(("wallet-del-hold", wallet_id));
        let press_start: Option<f64> = ui.ctx().memory(|m| m.data.get_temp(del_id));
        let resp = ui.add(btn).on_hover_text("Hold to delete");

        // Once a hold fires, that physical press is spent: after the
        // deleted row disappears, the next row shifts under the still-
        // held pointer and would otherwise start charging immediately —
        // cascading into the wrong wallet. Latched until release.
        let consumed_id = egui::Id::new("wallet-del-press-consumed");
        let consumed: bool = ui
            .ctx()
            .memory(|m| m.data.get_temp(consumed_id).unwrap_or(false));
        let pointer_down = ui.input(|i| i.pointer.primary_down());
        if consumed && !pointer_down {
            ui.ctx().memory_mut(|m| m.data.remove::<bool>(consumed_id));
        }

        // Read the pointer directly instead of is_pointer_button_down_on():
        // egui drops that flag once a press outlives its max click
        // duration (~0.8s), which silently cancelled the 2s hold. The
        // press must start on the button AND stay over it — dragging
        // off cancels, like a regular button.
        let held = !consumed
            && pointer_down
            && ui.input(|i| {
                i.pointer
                    .press_origin()
                    .is_some_and(|p| resp.rect.contains(p))
                    && i.pointer
                        .latest_pos()
                        .is_some_and(|p| resp.rect.contains(p))
            });

        if held {
            let now = ui.input(|i| i.time);
            if press_start.is_none() {
                ui.ctx().memory_mut(|m| m.data.insert_temp(del_id, now));
            }
            let start = press_start.unwrap_or(now);
            let progress = ((now - start) / HOLD_SECS).clamp(0.0, 1.0) as f32;
            let r = resp.rect;
            ui.painter().rect_filled(
                egui::Rect::from_min_size(r.min, egui::vec2(r.width() * progress, r.height())),
                0.0,
                egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 60),
            );
            if progress >= 1.0 {
                *delete_target = Some(wallet_id);
                ui.ctx().memory_mut(|m| {
                    m.data.remove::<f64>(del_id);
                    m.data.insert_temp(consumed_id, true);
                });
            }
            ui.ctx().request_repaint();
        } else if press_start.is_some() {
            // Released early: disarm so the next press starts from zero.
            ui.ctx().memory_mut(|m| m.data.remove::<f64>(del_id));
        }
    }
}

/// Width of the notice shown while a seed export is in flight.
const SEED_EXPORT_NOTICE_W: f32 = 420.0;

impl App {
    /// Drawn while a seed export pinentry dialog is in flight.
    pub(crate) fn show_seed_export_blocking_overlay(&self, ctx: &egui::Context) {
        if self.seed_export_dialog_done_rx.is_none() {
            return;
        }

        // Using egui modal for the overlay.
        egui::Modal::new(egui::Id::new("seed_export_blocking_overlay"))
            .backdrop_color(egui::Color32::from_rgba_unmultiplied(0, 0, 0, 180))
            .frame(
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .inner_margin(egui::Margin::symmetric(20, 18)),
            )
            .show(ctx, |ui| {
                ui.set_width(SEED_EXPORT_NOTICE_W);
                ui.horizontal(|ui| {
                    let t = ui.input(|i| i.time) as f32;
                    let (dot, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    breathing_dot(ui.painter(), dot.center(), self.colors.warn, t, true);
                    ui.label(
                        egui::RichText::new("SEED PHRASE OPEN IN THE SECURE DIALOG")
                            .font(label_font(12.0))
                            .color(self.colors.warn),
                    );
                });
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Read it there. Close that dialog to return to the wallet.",
                    )
                    .size(12.0)
                    .color(self.colors.text_muted),
                );
            });
    }
}
