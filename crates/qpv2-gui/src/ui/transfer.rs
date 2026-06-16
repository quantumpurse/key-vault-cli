//! Transfer tab — the "order entry ticket" of the Flight Deck UI.

use std::collections::HashSet;

use eframe::egui;

use crate::types::{
    display_font, label_font, AppColors, TransactionKind, TransactionStatus, TxKind,
};
use crate::ui::utils::{
    accent_button, badge, ghost_button, panel_frame, row_hover, section_header,
};
use crate::utils::{format_ckb, format_ckb_balance};
use crate::App;

/// Fixed left label column inside the order ticket so inputs align.
const FIELD_LABEL_W: f32 = 78.0;

/// Tiny uppercase field label occupying the fixed left column of a row.
fn field_label(ui: &mut egui::Ui, colors: &AppColors, text: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(FIELD_LABEL_W, 24.0), egui::Sense::hover());
    ui.painter().text(
        egui::pos2(rect.left(), rect.center().y),
        egui::Align2::LEFT_CENTER,
        text,
        label_font(9.5),
        colors.text_muted,
    );
}

/// Hairline rule separating field rows.
fn field_rule(ui: &mut egui::Ui, colors: &AppColors) {
    ui.add_space(8.0);
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().hline(
        rect.x_range(),
        rect.center().y,
        egui::Stroke::new(1.0, colors.border),
    );
    ui.add_space(8.0);
}

impl App {
    pub(crate) fn show_transfer_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 24.0);

                ui.label(
                    egui::RichText::new("TRANSFER")
                        .font(display_font(16.0))
                        .color(self.colors.text),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("Send CKB to any Nervos address.")
                        .size(11.0)
                        .color(self.colors.text_muted),
                );

                ui.add_space(16.0);

                let is_busy = !matches!(
                    self.tx_status,
                    TransactionStatus::Idle
                        | TransactionStatus::Success(_)
                        | TransactionStatus::Error(_)
                );

                self.draw_order_ticket(ui, is_busy);
                self.draw_tx_status_log(ui, false);

                // Multisig co-signer coordination — only mid-transaction,
                // and only for transfers (DAO operations coordinate on
                // the DAO screen).
                if matches!(
                    &self.tx_status,
                    TransactionStatus::AwaitingCoSigners {
                        kind: TransactionKind::Transfer,
                        ..
                    }
                ) {
                    self.show_cosigner_panel(ui);
                }

                self.draw_address_book(ui, is_busy);

                ui.add_space(20.0);
            });
        });
    }

    /// The order entry ticket: FROM / TO / AMOUNT / FEE RATE field rows
    /// separated by hairlines, then the single solid-accent execute button.
    fn draw_order_ticket(&mut self, ui: &mut egui::Ui, is_busy: bool) {
        panel_frame(&self.colors).show(ui, |ui| {
            section_header(ui, &self.colors, "01", "Order Entry");
            ui.add_space(10.0);

            // ── FROM: account selector ──
            ui.horizontal(|ui| {
                field_label(ui, &self.colors, "FROM");

                let from_text = if self.accounts.is_empty() {
                    "No accounts available".to_string()
                } else {
                    let idx = self.transfer_from_account.min(self.accounts.len() - 1);
                    let lock_args = &self.accounts[idx].lock_args;
                    let bal = self
                        .spendable_balances
                        .get(lock_args)
                        .and_then(|b| b.as_ref())
                        .copied();
                    let bal_str = match bal {
                        Some(b) => format_ckb_balance(b),
                        None => "--".to_string(),
                    };
                    format!("Account #{} ({})", idx, bal_str)
                };
                let selected_color = if self.accounts.is_empty() {
                    self.colors.text_muted
                } else {
                    self.colors.accent
                };

                let prev_from_account = self.transfer_from_account;
                egui::ComboBox::from_id_salt("transfer_from")
                    .selected_text(
                        egui::RichText::new(&from_text)
                            .size(12.0)
                            .color(selected_color),
                    )
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for (i, account) in self.accounts.iter().enumerate() {
                            let bal = self
                                .spendable_balances
                                .get(&account.lock_args)
                                .and_then(|b| b.as_ref())
                                .copied();
                            let label = match bal {
                                Some(b) => {
                                    format!("Account #{} ({})", i, format_ckb_balance(b))
                                }
                                None => format!("Account #{}", i),
                            };
                            let text = egui::RichText::new(label).size(12.0).color(
                                if self.transfer_from_account == i {
                                    self.colors.accent
                                } else {
                                    self.colors.text
                                },
                            );
                            ui.selectable_value(&mut self.transfer_from_account, i, text);
                        }
                    });
                // Clear send_all if the user switches accounts.
                if self.transfer_from_account != prev_from_account && self.transfer_all {
                    self.transfer_all = false;
                    self.transfer_amount.clear();
                }
            });

            field_rule(ui, &self.colors);

            // ── TO: recipient address + prefix-based network badge ──
            ui.horizontal(|ui| {
                field_label(ui, &self.colors, "TO");

                let trimmed = self.transfer_recipient.trim().to_string();
                let is_mainnet = self.qp_client.is_mainnet();
                let badge_info: Option<(&str, egui::Color32)> = if trimmed.is_empty() {
                    None
                } else if trimmed.starts_with("ckb") {
                    if is_mainnet {
                        Some(("MAIN", self.colors.accent))
                    } else {
                        Some(("NET MISMATCH", self.colors.danger))
                    }
                } else if trimmed.starts_with("ckt") {
                    if !is_mainnet {
                        Some(("TEST", self.colors.warn))
                    } else {
                        Some(("NET MISMATCH", self.colors.danger))
                    }
                } else {
                    Some(("BAD PREFIX", self.colors.danger))
                };

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some((label, color)) = badge_info {
                        badge(ui, label, color);
                        ui.add_space(6.0);
                    }
                    let recipient_edit = egui::TextEdit::singleline(&mut self.transfer_recipient)
                        .hint_text("Recipient address")
                        .desired_width(ui.available_width())
                        .font(egui::FontId::monospace(12.5))
                        .interactive(!is_busy);
                    ui.add(recipient_edit);
                });
            });

            field_rule(ui, &self.colors);

            // ── AMOUNT: free entry + MAX (send all) ──
            ui.horizontal(|ui| {
                field_label(ui, &self.colors, "AMOUNT");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Clear button when send_all is active.
                    if self.transfer_all
                        && !is_busy
                        && ui
                            .add(ghost_button(&self.colors, "CLEAR", egui::vec2(56.0, 22.0)))
                            .clicked()
                    {
                        self.transfer_all = false;
                        self.transfer_amount.clear();
                    }

                    let can_calculate_max =
                        !is_busy && !self.transfer_all && !self.accounts.is_empty();
                    if ui
                        .add_enabled(
                            can_calculate_max,
                            ghost_button(&self.colors, "MAX", egui::vec2(46.0, 22.0)),
                        )
                        .clicked()
                    {
                        // Fill the displayed amount from the cached
                        // spendable balance; send-all recomputes the
                        // exact amount from fresh cells at build time.
                        let idx = self.transfer_from_account.min(self.accounts.len() - 1);
                        if let Some(sh) = self
                            .spendable_balances
                            .get(&self.accounts[idx].lock_args)
                            .copied()
                            .flatten()
                        {
                            self.transfer_amount = format_ckb(sh);
                        }
                        self.transfer_all = true;
                    }
                    ui.add_space(6.0);

                    let amount_interactive = !is_busy && !self.transfer_all;
                    let amount_edit = egui::TextEdit::singleline(&mut self.transfer_amount)
                        .hint_text("0.00000000")
                        .desired_width(ui.available_width())
                        .font(egui::FontId::monospace(12.5))
                        .interactive(amount_interactive);
                    ui.add(amount_edit);
                });
            });
            if self.transfer_all {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    // Indent the note under the input column.
                    ui.add_space(FIELD_LABEL_W);
                    ui.label(
                        egui::RichText::new("SEND ALL — fee will be deducted at send time.")
                            .size(10.5)
                            .color(self.colors.text_muted),
                    );
                });
            }

            field_rule(ui, &self.colors);

            // ── FEE RATE ──
            ui.horizontal(|ui| {
                field_label(ui, &self.colors, "FEE RATE");
                let fee_edit = egui::TextEdit::singleline(&mut self.transfer_fee_rate)
                    .hint_text("1000")
                    .desired_width(120.0)
                    .font(egui::FontId::monospace(12.0))
                    .interactive(!is_busy);
                ui.add(fee_edit);
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("SHANNONS/KB")
                        .font(label_font(9.0))
                        .color(self.colors.text_muted),
                );
            });

            field_rule(ui, &self.colors);

            // ── Irreversibility caution ──
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("[WARN]")
                        .font(label_font(10.0))
                        .color(self.colors.warn),
                );
                ui.label(
                    egui::RichText::new(
                        "Transfers are final. Double-check the recipient address before sending.",
                    )
                    .size(11.0)
                    .color(self.colors.text_muted),
                );
            });

            ui.add_space(12.0);

            // ── Execute — the screen's single solid-accent action ──
            let has_accounts = !self.accounts.is_empty();
            let can_send = has_accounts
                && !is_busy
                && !self.transfer_recipient.is_empty()
                && !self.transfer_amount.is_empty();

            let size = egui::vec2(ui.available_width(), 40.0);
            // While a transaction is in flight the ticket is inert (the
            // wallet has a single tx slot); say whose transaction is
            // actually occupying it.
            let btn = if is_busy {
                let label = if self.active_tx_kind.is_some_and(|k| k.is_dao()) {
                    "BUSY — DAO TRANSACTION IN FLIGHT"
                } else {
                    "TRANSFER IN PROGRESS"
                };
                ghost_button(&self.colors, label, size)
            } else {
                accent_button(&self.colors, "EXECUTE TRANSFER", size)
            };
            if ui.add_enabled(can_send, btn).clicked() {
                self.transfer_async();
            }
        });
    }

    /// Recent external recipients harvested from outgoing history.
    /// Clicking a row loads the address into the ticket.
    fn draw_address_book(&mut self, ui: &mut egui::Ui, is_busy: bool) {
        let mut seen: HashSet<String> = HashSet::new();
        let entries: Vec<String> = self
            .tx_history
            .iter()
            .filter(|r| matches!(r.tx_kind, TxKind::Outgoing))
            .filter_map(|r| r.external_recipient_address.as_ref())
            .filter(|a| seen.insert((*a).clone()))
            .take(5)
            .cloned()
            .collect();

        ui.add_space(16.0);
        panel_frame(&self.colors).show(ui, |ui| {
            section_header(ui, &self.colors, "02", "Recent Recipients");
            ui.add_space(6.0);

            if entries.is_empty() {
                ui.label(
                    egui::RichText::new(
                        "No recent recipients yet. Sent addresses will appear here.",
                    )
                    .size(11.0)
                    .color(self.colors.text_muted),
                );
                return;
            }

            for (i, addr) in entries.iter().enumerate() {
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 28.0),
                    egui::Sense::click(),
                );
                let painter = ui.painter();
                let hovered = response.hovered() && !is_busy;

                if hovered {
                    row_hover(painter, rect, &self.colors);
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    painter.text(
                        egui::pos2(rect.right() - 8.0, rect.center().y),
                        egui::Align2::RIGHT_CENTER,
                        "USE →",
                        label_font(8.5),
                        self.colors.accent,
                    );
                }

                painter.text(
                    egui::pos2(rect.left() + 8.0, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    format!("{:02}", i + 1),
                    label_font(8.5),
                    self.colors.text_muted,
                );
                let short_addr = if addr.len() > 60 {
                    format!("{}…{}", &addr[..30], &addr[addr.len() - 30..])
                } else {
                    addr.clone()
                };
                painter.text(
                    egui::pos2(rect.left() + 34.0, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    short_addr,
                    egui::FontId::proportional(11.0),
                    if hovered {
                        self.colors.text
                    } else {
                        self.colors.text_muted
                    },
                );

                if response.clicked() && !is_busy {
                    self.transfer_recipient = addr.clone();
                }

                if i + 1 < entries.len() {
                    ui.painter().hline(
                        rect.x_range(),
                        rect.bottom() + 0.5,
                        egui::Stroke::new(1.0, self.colors.border),
                    );
                    ui.add_space(1.0);
                }
            }
        });
    }
}
