//! Accounts tab rendering — single-sig account registry.

use eframe::egui;
use qpv2_core::types::AuthMethod;
use qpv2_core::KeyVault;

use super::utils::{
    accent_button, badge, ckb_split, ghost_button, panel_frame, row_hover, section_header,
    truncate_middle,
};
use crate::types::{display_font, label_font, AppColors, Status};
use crate::App;

/// Tiny uppercase column header cell. Shared by the registry tables in
/// the Accounts / Multisig / Wallets tabs.
pub(crate) fn header_cell(
    ui: &mut egui::Ui,
    colors: &AppColors,
    w: f32,
    text: &str,
    right_align: bool,
) {
    let layout = if right_align {
        egui::Layout::right_to_left(egui::Align::Center)
    } else {
        egui::Layout::left_to_right(egui::Align::Center)
    };
    ui.allocate_ui_with_layout(egui::vec2(w, 14.0), layout, |ui| {
        // allocate_ui_with_layout advances the cursor by the *used*
        // width, not the desired one — pin the cell to its column
        // width or every trailing column drifts off the grid.
        ui.set_min_width(w);
        ui.label(
            egui::RichText::new(text)
                .font(label_font(9.0))
                .color(colors.text_muted),
        );
    });
}

/// Full-width 1px hairline separating table rows.
pub(crate) fn table_rule(ui: &mut egui::Ui, colors: &AppColors) {
    let (line, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().hline(
        line.x_range(),
        line.center().y,
        egui::Stroke::new(1.0, colors.border),
    );
}

const COL_IDX: f32 = 44.0;
const COL_ADDR: f32 = 210.0;
const COL_PUB: f32 = 210.0;
const COL_BAL: f32 = 150.0;
const ROW_H: f32 = 30.0;

/// Per-row snapshot taken before rendering so the row closures don't
/// hold a borrow of `self.accounts` while they mutate `self.status`.
struct AccountRow {
    index: usize,
    address: String,
    balance: Option<Option<u64>>,
    variant: String,
    pubkey_hex: String,
}

impl App {
    pub(crate) fn show_accounts_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 24.0);

                ui.label(
                    egui::RichText::new("ACCOUNTS")
                        .font(display_font(16.0))
                        .color(self.colors.text),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "Derive and manage single-sig accounts for the active wallet.",
                    )
                    .size(11.0)
                    .color(self.colors.text_muted),
                );
                ui.add_space(14.0);

                let rows: Vec<AccountRow> = self
                    .accounts
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.config.signers.len() == 1)
                    .map(|(i, a)| {
                        let address = match crate::utils::lock_args_to_address(
                            &a.lock_args,
                            self.qp_client.is_mainnet(),
                        ) {
                            Ok(addr) => addr.to_string(),
                            Err(_) => format!("0x{}", a.lock_args),
                        };
                        AccountRow {
                            index: i,
                            address,
                            balance: self.spendable_balances.get(&a.lock_args).copied(),
                            variant: format!("{}", a.config.signers[0].variant),
                            pubkey_hex: hex::encode(&a.config.signers[0].pubkey),
                        }
                    })
                    .collect();

                // Auth method is wallet-wide, so resolve it once and
                // repeat the badge on every row.
                let auth_label = KeyVault::read_wallet_info(self.wallet_id).ok().map(|info| {
                    match info.auth_method {
                        AuthMethod::Keychain => keychain::short_name().to_string(),
                        AuthMethod::Password => "PASSWORD".to_string(),
                        AuthMethod::Fido2 { .. } => "FIDO2".to_string(),
                        AuthMethod::Trezor { .. } => "TREZOR".to_string(),
                    }
                });

                panel_frame(&self.colors).show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    ui.horizontal(|ui| {
                        let btn_w = 130.0;
                        let header_w = (ui.available_width() - btn_w - 10.0).max(0.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(header_w, 24.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                section_header(
                                    ui,
                                    &self.colors,
                                    "01",
                                    &format!("Account Registry // {}", rows.len()),
                                );
                            },
                        );
                        let btn =
                            accent_button(&self.colors, "NEW ACCOUNT", egui::vec2(btn_w, 24.0));
                        if ui.add(btn).clicked() {
                            self.create_singlesig_account();
                        }
                    });
                    ui.add_space(10.0);

                    if rows.is_empty() {
                        ui.label(
                            egui::RichText::new("NO ACCOUNTS REGISTERED — CREATE ONE TO BEGIN.")
                                .font(label_font(9.5))
                                .color(self.colors.text_muted),
                        );
                    } else {
                        self.accounts_table(ui, &rows, auth_label.as_deref());
                    }
                });

                ui.add_space(20.0);
            });
        });
    }

    fn accounts_table(&mut self, ui: &mut egui::Ui, rows: &[AccountRow], auth_label: Option<&str>) {
        ui.scope(|ui| {
            // Rows must sit flush against their hairlines.
            ui.spacing_mut().item_spacing.y = 0.0;

            ui.horizontal(|ui| {
                ui.add_space(6.0);
                header_cell(ui, &self.colors, COL_IDX, "IDX", false);
                header_cell(ui, &self.colors, COL_ADDR, "ADDRESS", false);
                header_cell(ui, &self.colors, COL_PUB, "PUBKEY", false);
                header_cell(ui, &self.colors, COL_BAL, "BALANCE (CKB)", false);
                ui.add_space(14.0);
                header_cell(ui, &self.colors, 120.0, "TYPE", false);
            });
            ui.add_space(4.0);
            table_rule(ui, &self.colors);

            for row in rows {
                let full_w = ui.available_width();
                let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(full_w, ROW_H));
                if ui.rect_contains_pointer(rect) {
                    row_hover(ui.painter(), rect, &self.colors);
                }

                ui.allocate_ui_with_layout(
                    egui::vec2(full_w, ROW_H),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        // Keep content clear of the 2px hover tick.
                        ui.add_space(6.0);

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_IDX, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                // Pin to the column width (see header_cell).
                                ui.set_min_width(COL_IDX);
                                ui.label(
                                    egui::RichText::new(format!("{:02}", row.index))
                                        .font(label_font(9.5))
                                        .color(self.colors.text_muted),
                                );
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_ADDR, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_ADDR);
                                let label = egui::Label::new(
                                    egui::RichText::new(truncate_middle(&row.address, 12, 10))
                                        .size(11.0)
                                        .color(self.colors.text_muted),
                                )
                                .sense(egui::Sense::click());
                                let resp = ui
                                    .add(label)
                                    .on_hover_text(&row.address)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                if resp.clicked() {
                                    ui.ctx().copy_text(row.address.clone());
                                    self.status = Status::Info("Address copied!".to_string());
                                }
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_PUB, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_PUB);
                                let label = egui::Label::new(
                                    egui::RichText::new(truncate_middle(&row.pubkey_hex, 10, 8))
                                        .size(11.0)
                                        .color(self.colors.text_muted),
                                )
                                .sense(egui::Sense::click());
                                let resp = ui
                                    .add(label)
                                    .on_hover_text(&row.pubkey_hex)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                if resp.clicked() {
                                    ui.ctx().copy_text(row.pubkey_hex.clone());
                                    self.status = Status::Info("Public key copied!".to_string());
                                }
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(COL_BAL, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_BAL);
                                ui.spacing_mut().item_spacing.x = 0.0;
                                match row.balance {
                                    Some(Some(shannons)) => {
                                        let (int, frac) = ckb_split(shannons);
                                        ui.label(
                                            egui::RichText::new(int)
                                                .size(11.5)
                                                .color(self.colors.text),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!(".{}", frac))
                                                .size(11.5)
                                                .color(self.colors.text_muted),
                                        );
                                    }
                                    Some(None) => {
                                        ui.label(
                                            egui::RichText::new("SYNC")
                                                .font(label_font(9.0))
                                                .color(self.colors.text_muted),
                                        );
                                    }
                                    None => {
                                        ui.label(
                                            egui::RichText::new("--")
                                                .size(11.5)
                                                .color(self.colors.text_muted),
                                        );
                                    }
                                }
                            },
                        );

                        ui.add_space(14.0);
                        badge(ui, &row.variant, self.colors.accent3);
                        if let Some(auth) = auth_label {
                            ui.add_space(4.0);
                            badge(ui, auth, self.colors.text_muted);
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(6.0);
                            let copy_btn =
                                ghost_button(&self.colors, "COPY", egui::vec2(52.0, 20.0));
                            if ui.add(copy_btn).on_hover_text("Copy address").clicked() {
                                ui.ctx().copy_text(row.address.clone());
                                self.status = Status::Info("Address copied!".to_string());
                            }
                        });
                    },
                );

                table_rule(ui, &self.colors);
            }
        });
    }
}
