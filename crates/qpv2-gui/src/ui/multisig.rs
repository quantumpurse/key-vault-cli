//! Multisig tab rendering — M-of-N multisig account registry.

use eframe::egui;

use super::accounts::{header_cell, table_rule, truncate_middle};
use super::utils::{
    accent_button, badge, ckb_split, ghost_button, panel_frame, row_hover, section_header,
    SectionCounter,
};
use crate::types::{display_font, label_font, Status};
use crate::App;

const COL_IDX: f32 = 44.0;
const COL_CFG: f32 = 64.0;
/// Wide enough that the signer detail lines hanging under it
/// ("S0 SHA2128S <20…20 hex> // YOU", ~9.5pt mono) never run beneath
/// the BALANCE column.
const COL_ADDR: f32 = 360.0;
const COL_BAL: f32 = 180.0;
const ROW_H: f32 = 30.0;
/// Height of one signer detail line under the main row.
const SIGNER_H: f32 = 15.0;
/// How far the signer lines tuck up under the main row — its vertical
/// centering otherwise leaves what reads as a blank line.
const SIGNER_PULL_UP: f32 = 7.0;

/// One signer detail line rendered under the account's main row.
struct SignerLine {
    text: String,
    /// True when this signer's key lives in the local wallet.
    is_local: bool,
}

/// Per-row snapshot taken before rendering so the row closures don't
/// hold a borrow of `self.accounts` while they mutate `self.status`.
struct MultisigRow {
    index: usize,
    config: String,
    address: String,
    balance: Option<Option<u64>>,
    signers: Vec<SignerLine>,
}

impl App {
    pub(crate) fn show_multisig_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 24.0);

                ui.label(
                    egui::RichText::new("MULTISIG")
                        .font(display_font(16.0))
                        .color(self.colors.text),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("Create and manage M-of-N multi-signature accounts.")
                        .size(11.0)
                        .color(self.colors.text_muted),
                );
                ui.add_space(14.0);

                let rows: Vec<MultisigRow> = self
                    .accounts
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.config.signers.len() > 1)
                    .map(|(i, a)| {
                        let address = match crate::utils::lock_args_to_address(
                            &a.lock_args,
                            self.qp_client.is_mainnet(),
                        ) {
                            Ok(addr) => addr.to_string(),
                            Err(_) => format!("0x{}", a.lock_args),
                        };
                        // A signer is "local" when the account's initiating
                        // single-sig key in this wallet carries the same pubkey.
                        let local_pubkey = a
                            .initiating_signer_lock_args
                            .as_ref()
                            .and_then(|la| {
                                self.accounts
                                    .iter()
                                    .find(|x| x.lock_args == *la && x.config.is_single_sig())
                            })
                            .map(|x| &x.config.signers[0].pubkey);
                        let signers = a
                            .config
                            .signers
                            .iter()
                            .enumerate()
                            .map(|(si, s)| {
                                let pk_hex = hex::encode(&s.pubkey);
                                let is_local = local_pubkey == Some(&s.pubkey);
                                SignerLine {
                                    text: format!(
                                        "S{} {} {}",
                                        si,
                                        s.variant,
                                        truncate_middle(&pk_hex, 20, 20)
                                    ),
                                    is_local,
                                }
                            })
                            .collect();
                        MultisigRow {
                            index: i,
                            config: format!("{}/{}", a.config.threshold, a.config.signers.len()),
                            address,
                            balance: self.spendable_balances.get(&a.lock_args).copied(),
                            signers,
                        }
                    })
                    .collect();

                // One counter spans the registry and the co-signer flow
                // below so the screen never shows duplicate codes.
                let mut sec = SectionCounter::new();

                panel_frame(&self.colors).show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    ui.horizontal(|ui| {
                        let btn_w = 140.0;
                        let header_w = (ui.available_width() - btn_w - 10.0).max(0.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(header_w, 24.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                section_header(
                                    ui,
                                    &self.colors,
                                    &sec.next_code(),
                                    &format!("Multisig Registry // {}", rows.len()),
                                );
                            },
                        );
                        let btn =
                            accent_button(&self.colors, "NEW MULTISIG", egui::vec2(btn_w, 24.0));
                        if ui.add(btn).clicked() {
                            self.multisig_local_signer_idx = 0;
                            self.multisig_threshold = 2;
                            self.multisig_required_first_n = 0;
                            self.multisig_co_signers = vec![];
                            self.multisig_modal_open = true;
                        }
                    });
                    ui.add_space(10.0);

                    if rows.is_empty() {
                        ui.label(
                            egui::RichText::new(
                                "NO MULTISIG ACCOUNTS REGISTERED — CREATE ONE TO BEGIN.",
                            )
                            .font(label_font(9.5))
                            .color(self.colors.text_muted),
                        );
                    } else {
                        self.multisig_table(ui, &rows);
                    }
                });

                // Co-signer signing flow: paste / verify / sign panels.
                self.show_sign_request_ui(ui, &mut sec);

                ui.add_space(20.0);
            });
        });
    }

    fn multisig_table(&mut self, ui: &mut egui::Ui, rows: &[MultisigRow]) {
        ui.scope(|ui| {
            // Rows must sit flush against their hairlines.
            ui.spacing_mut().item_spacing.y = 0.0;

            ui.horizontal(|ui| {
                ui.add_space(6.0);
                header_cell(ui, &self.colors, COL_IDX, "IDX", false);
                header_cell(ui, &self.colors, COL_CFG, "CFG", false);
                header_cell(ui, &self.colors, COL_ADDR, "ADDRESS", false);
                header_cell(ui, &self.colors, COL_BAL, "BALANCE (CKB)", false);
            });
            ui.add_space(4.0);
            table_rule(ui, &self.colors);

            for row in rows {
                let full_w = ui.available_width();
                // The hover treatment spans the main line plus the
                // signer detail lines so the block reads as one row.
                let block_h = ROW_H - SIGNER_PULL_UP + row.signers.len() as f32 * SIGNER_H + 6.0;
                let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(full_w, block_h));
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
                            egui::vec2(COL_CFG, ROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_width(COL_CFG);
                                badge(ui, &row.config, self.colors.accent3);
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

                ui.add_space(-SIGNER_PULL_UP);
                for line in &row.signers {
                    ui.allocate_ui_with_layout(
                        egui::vec2(full_w, SIGNER_H),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            // Bulleted detail lines hang under the
                            // ADDRESS column, nudged right of it.
                            let s = ui.spacing().item_spacing.x;
                            ui.add_space(6.0 + COL_IDX + COL_CFG + 2.0 * s + 12.0);
                            let (text, color) = if line.is_local {
                                (format!("• {} // YOU", line.text), self.colors.accent)
                            } else {
                                (format!("• {}", line.text), self.colors.text_muted)
                            };
                            ui.label(egui::RichText::new(text).size(9.5).color(color));
                        },
                    );
                }
                ui.add_space(6.0);

                table_rule(ui, &self.colors);
            }
        });
    }
}
