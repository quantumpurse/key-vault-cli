//! Nervos DAO module: position-summary readout, action row, and a
//! hairline positions table in the Flight Deck instrument style.

use eframe::egui;

use super::utils::{
    badge, ckb_split, extract_ar, format_duration_ms, ghost_button, panel_frame,
    pin_popup_above_modal, row_hover, section_header, truncate_middle,
};
use crate::types::{display_font, label_font, AppColors, DaoView, Status, TransactionStatus};
use crate::utils::{format_ckb, format_ckb_balance};
use crate::App;

/// Uniform height for positions-table rows so hairlines stay aligned.
const ROW_H: f32 = 30.0;

impl App {
    pub(crate) fn show_dao_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 24.0);

                ui.label(
                    egui::RichText::new("NERVOS DAO")
                        .font(display_font(16.0))
                        .color(self.colors.text),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("Deposit, withdraw, and manage DAO deposit positions.")
                        .size(11.0)
                        .color(self.colors.text_muted),
                );

                ui.add_space(16.0);

                // ── 01 // Position summary ──
                let total_deposited: u64 = self
                    .dao_deposited_cells
                    .iter()
                    .map(|(_, c)| c.capacity)
                    .sum();
                let total_prepared_principal: u64 = self
                    .dao_prepared_cells
                    .iter()
                    .map(|(_, c)| c.capacity)
                    .sum();
                // Prepared cells carry a locked-in payout; their interest
                // is exact (maximum_withdraw − principal).
                let prepared_earned: u64 = self
                    .dao_prepared_cells
                    .iter()
                    .map(|(_, c)| c.maximum_withdraw.saturating_sub(c.capacity))
                    .sum();
                // Deposited cells are still earning. Their interest is
                // estimated from AR growth to tip — the same per-row
                // figure the positions table shows. Omitting it made the
                // headline understate earnings by everything not yet
                // prepared for withdrawal.
                let deposited_earned: u64 = self
                    .dao_deposited_cells
                    .iter()
                    .filter_map(|(_, c)| self.estimated_deposit_interest(c))
                    .sum();
                let total_earned = prepared_earned + deposited_earned;
                let active_cells = self.dao_deposited_cells.len() + self.dao_prepared_cells.len();
                let total_locked = total_deposited + total_prepared_principal;

                panel_frame(&self.colors).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    section_header(ui, &self.colors, "01", "Position Summary");
                    ui.add_space(12.0);
                    self.draw_dao_stats(ui, total_locked, total_earned, active_cells);
                });

                ui.add_space(14.0);

                // ── Action row ──
                let is_busy = !matches!(self.tx_status, TransactionStatus::Idle)
                    && !matches!(self.tx_status, TransactionStatus::Success(_))
                    && !matches!(self.tx_status, TransactionStatus::Error(_));

                ui.horizontal(|ui| {
                    let size = egui::vec2(180.0, 32.0);
                    // All three render as equal ghosts: a solid button
                    // in a row of same-sized siblings reads as a
                    // selected segment, not an action.
                    if ui
                        .add(ghost_button(&self.colors, "DEPOSIT", size))
                        .clicked()
                        && !is_busy
                    {
                        self.dao_view = DaoView::Deposit;
                        self.tx_status = TransactionStatus::Idle;
                    }
                    ui.add_space(6.0);
                    // TODO: enable later when figure out their UX.
                    ui.add_enabled(
                        false,
                        ghost_button(&self.colors, "REQUEST WITHDRAWAL", size),
                    )
                    .on_disabled_hover_text(
                        "Use the REQUEST action on a deposited position in the table below.",
                    );
                    ui.add_space(6.0);
                    ui.add_enabled(false, ghost_button(&self.colors, "WITHDRAW", size))
                        .on_disabled_hover_text(
                            "Use the WITHDRAW action on a prepared position in the table below.",
                        );
                });

                // The in-flight transaction status, and — when a multisig
                // DAO operation pauses for co-signatures — the same
                // coordination panel the transfer screen uses. Without
                // this the flow is alive but invisible from this tab.
                self.draw_tx_status_log(ui, true);
                if matches!(
                    &self.tx_status,
                    TransactionStatus::AwaitingCoSigners { kind, .. } if kind.is_dao()
                ) {
                    self.show_cosigner_panel(ui);
                }

                ui.add_space(14.0);

                // ── 02 // Positions ──
                panel_frame(&self.colors).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    section_header(ui, &self.colors, "02", "Positions");
                    ui.add_space(10.0);
                    self.show_dao_positions_table(ui);
                });

                ui.add_space(20.0);
            }); // vertical
        }); // horizontal
    }

    /// Four-column instrument readout separated by vertical hairlines.
    fn draw_dao_stats(
        &self,
        ui: &mut egui::Ui,
        total_locked: u64,
        total_earned: u64,
        active_cells: usize,
    ) {
        let c = &self.colors;
        let pad = 14.0;
        let col_w = ((ui.available_width() - 3.0 * (1.0 + 2.0 * pad)) / 4.0).max(80.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;

            stat_cell(ui, c, col_w, "CKB LOCKED", |ui| {
                stat_ckb_value(ui, c, "", total_locked, c.text);
            });
            stat_divider(ui, c, pad);

            // Once deposited cells contribute, the total is an estimate
            // (their payout is taken at a future epoch), so it carries
            // the same "~" the per-row figures use.
            let earned_prefix = if self.dao_deposited_cells.is_empty() {
                "+"
            } else {
                "~+"
            };
            stat_cell(ui, c, col_w, "CKB EARNED", |ui| {
                stat_ckb_value(ui, c, earned_prefix, total_earned, c.accent2);
            });
            stat_divider(ui, c, pad);

            stat_cell(ui, c, col_w, "CURRENT APC", |ui| {
                ui.label(
                    egui::RichText::new(self.compute_dao_apc())
                        .font(display_font(18.0))
                        .color(c.text),
                );
            });
            stat_divider(ui, c, pad);

            stat_cell(ui, c, col_w, "ACTIVE DEPOSITS", |ui| {
                ui.label(
                    egui::RichText::new(format!("{}", active_cells))
                        .font(display_font(18.0))
                        .color(c.text),
                );
            });
        });
    }

    /// Estimated DAO interest for one deposited cell: the principal
    /// scaled by the accumulated-rate growth from the cell's deposit
    /// header to the current tip. `None` until both headers are cached.
    /// The realized payout lands at a future epoch boundary, so callers
    /// present this value as an estimate ("~").
    pub(crate) fn estimated_deposit_interest(&self, cell: &ckb_node::DepositedCell) -> Option<u64> {
        let dep_h = self.deposit_headers.get(&cell.block_number)?;
        let tip_h = self.node_status.tip_header.as_ref()?;
        let growth = extract_ar(tip_h) / extract_ar(dep_h);
        Some((cell.capacity as f64 * (growth - 1.0)) as u64)
    }

    /// Renders the DAO deposit form as a centered modal overlay.
    pub(crate) fn show_dao_deposit_modal(&mut self, ctx: &egui::Context) {
        if self.dao_view != DaoView::Deposit {
            return;
        }

        // A multisig deposit pauses for co-signatures; the coordination
        // panel lives on the DAO screen behind this modal, so close the
        // modal to reveal it.
        if matches!(self.tx_status, TransactionStatus::AwaitingCoSigners { .. }) {
            self.dao_view = DaoView::Overview;
            return;
        }

        // When DAO deposit transaction succeeds, close the modal and return.
        if matches!(self.tx_status, TransactionStatus::Success(_)) {
            self.dao_view = DaoView::Overview;
            return;
        }

        let is_busy = !matches!(
            self.tx_status,
            TransactionStatus::Idle | TransactionStatus::Success(_) | TransactionStatus::Error(_)
        );

        // Semi-transparent backdrop that consumes clicks.
        let screen_rect = ctx.input(|i| i.viewport_rect());
        let backdrop_clicked = egui::Area::new(egui::Id::new("dao_deposit_backdrop"))
            .fixed_pos(screen_rect.min)
            .order(egui::Order::Middle)
            .show(ctx, |ui| {
                let (rect, response) =
                    ui.allocate_exact_size(screen_rect.size(), egui::Sense::click());
                ui.painter().rect_filled(
                    rect,
                    0.0,
                    egui::Color32::from_rgba_unmultiplied(0, 0, 0, 180),
                );
                response.clicked()
            })
            .inner;

        let modal_width = 480.0;
        let modal_pos = egui::pos2(
            (screen_rect.width() - modal_width) / 2.0,
            screen_rect.height() * 0.12,
        );

        egui::Area::new(egui::Id::new("dao_deposit_area"))
            .fixed_pos(modal_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .inner_margin(egui::Margin::symmetric(24, 20))
                    .show(ui, |ui| {
                        ui.set_width(modal_width);

                        ui.label(
                            egui::RichText::new("DAO DEPOSIT")
                                .font(display_font(16.0))
                                .color(self.colors.text),
                        );
                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new(
                                "Lock CKB to earn compensation against inflation.",
                            )
                            .size(11.0)
                            .color(self.colors.text_muted),
                        );

                        ui.add_space(16.0);

                        // ── From Account ──
                        ui.label(
                            egui::RichText::new("FROM ACCOUNT")
                                .font(label_font(9.5))
                                .color(self.colors.text_muted),
                        );
                        ui.add_space(4.0);

                        let from_text = if self.accounts.is_empty() {
                            "No accounts available".to_string()
                        } else {
                            let idx =
                                self.dao_deposit_from_account.min(self.accounts.len() - 1);
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
                            let ms = if self.accounts[idx].config.signers.len() > 1 {
                                " multisig"
                            } else {
                                ""
                            };
                            format!("Account #{} ({}){}", idx, bal_str, ms)
                        };

                        let prev_picked_from_account = self.dao_deposit_from_account;
                        let from_combo = egui::ComboBox::from_id_salt("dao_deposit_from")
                            .selected_text(&from_text)
                            .width(ui.available_width())
                            .show_ui(ui, |ui| {
                                for (i, account) in self.accounts.iter().enumerate() {
                                    let bal = self
                                        .spendable_balances
                                        .get(&account.lock_args)
                                        .and_then(|b| b.as_ref())
                                        .copied();
                                    let ms = if account.config.signers.len() > 1 {
                                        " multisig"
                                    } else {
                                        ""
                                    };
                                    let label = match bal {
                                        Some(b) => {
                                            format!("Account #{} ({}){}", i, format_ckb_balance(b), ms)
                                        }
                                        None => format!("Account #{}{}", i, ms),
                                    };
                                    ui.selectable_value(
                                        &mut self.dao_deposit_from_account,
                                        i,
                                        label,
                                    );
                                }
                            });
                        pin_popup_above_modal(ui, &from_combo.response);
                        if self.dao_deposit_from_account != prev_picked_from_account
                            && self.dao_deposit_all
                        {
                            self.dao_deposit_all = false;
                            self.dao_deposit_amount.clear();
                        }

                        ui.add_space(14.0);

                        // ── Amount ──
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("AMOUNT (CKB)")
                                    .font(label_font(9.5))
                                    .color(self.colors.text_muted),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if self.dao_deposit_all
                                        && !is_busy
                                        && ui
                                            .add(ghost_button(
                                                &self.colors,
                                                "CLEAR",
                                                egui::vec2(52.0, 18.0),
                                            ))
                                            .clicked()
                                    {
                                        self.dao_deposit_all = false;
                                        self.dao_deposit_amount.clear();
                                    }

                                    let can_max = !is_busy
                                        && !self.dao_deposit_all
                                        && !self.accounts.is_empty();
                                    if ui
                                        .add_enabled(
                                            can_max,
                                            ghost_button(
                                                &self.colors,
                                                "MAX",
                                                egui::vec2(44.0, 18.0),
                                            ),
                                        )
                                        .clicked()
                                    {
                                        let idx = self
                                            .dao_deposit_from_account
                                            .min(self.accounts.len() - 1);
                                        if let Some(sh) = self
                                            .spendable_balances
                                            .get(&self.accounts[idx].lock_args)
                                            .copied()
                                            .flatten()
                                        {
                                            self.dao_deposit_amount = format_ckb(sh);
                                        }
                                        self.dao_deposit_all = true;
                                    }
                                },
                            );
                        });
                        ui.add_space(4.0);

                        let amount_interactive = !is_busy && !self.dao_deposit_all;
                        let amount_edit =
                            egui::TextEdit::singleline(&mut self.dao_deposit_amount)
                                .hint_text("Min: 114 CKB")
                                .desired_width(ui.available_width())
                                .font(egui::FontId::monospace(13.0))
                                .interactive(amount_interactive);
                        ui.add(amount_edit);

                        if self.dao_deposit_all {
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new("Fee will be deducted at deposit time.")
                                    .size(10.5)
                                    .color(self.colors.text_muted),
                            );
                        }

                        ui.add_space(14.0);

                        // ── Fee Rate (collapsible) ──
                        egui::CollapsingHeader::new(
                            egui::RichText::new("ADVANCED")
                                .font(label_font(9.5))
                                .color(self.colors.text_muted),
                        )
                        .default_open(false)
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new("FEE RATE (SHANNONS/KB)")
                                    .font(label_font(9.0))
                                    .color(self.colors.text_muted),
                            );
                            ui.add_space(4.0);
                            let fee_edit =
                                egui::TextEdit::singleline(&mut self.dao_deposit_fee_rate)
                                    .hint_text("1000")
                                    .desired_width(120.0)
                                    .font(egui::FontId::monospace(12.0))
                                    .interactive(!is_busy);
                            ui.add(fee_edit);
                        });

                        ui.add_space(12.0);

                        // ── Warning ──
                        egui::Frame::new()
                            .fill(self.colors.warn_tint)
                            .stroke(egui::Stroke::new(
                                1.0,
                                egui::Color32::from_rgba_unmultiplied(
                                    self.colors.warn.r(),
                                    self.colors.warn.g(),
                                    self.colors.warn.b(),
                                    90,
                                ),
                            ))
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(
                                        "Withdrawal can be requested any time, but funds unlock only at the end of each 180-epoch deposit cycle (~30 days).",
                                    )
                                    .size(11.0)
                                    .color(self.colors.warn),
                                );
                            });

                        ui.add_space(16.0);

                        // ── Confirm button ──
                        let can_deposit = !is_busy
                            && !self.accounts.is_empty()
                            && !self.dao_deposit_amount.is_empty();

                        let btn_text = match &self.tx_status {
                            TransactionStatus::Building => "BUILDING TRANSACTION...",
                            TransactionStatus::AwaitingSignature => "WAITING FOR TOUCH ID...",
                            TransactionStatus::Sending => "BROADCASTING...",
                            _ => "CONFIRM DEPOSIT",
                        };

                        // egui keeps explicit fills on disabled widgets,
                        // so the busy / not-ready states are dimmed here.
                        let (btn_fill, btn_fg) = if can_deposit {
                            (self.colors.accent, self.colors.bg)
                        } else if is_busy {
                            (self.colors.accent.linear_multiply(0.5), self.colors.bg)
                        } else {
                            (self.colors.surface2, self.colors.text_muted)
                        };
                        let deposit_btn = egui::Button::new(
                            egui::RichText::new(btn_text)
                                .font(label_font(11.0))
                                .color(btn_fg),
                        )
                        .fill(btn_fill)
                        .stroke(egui::Stroke::NONE)
                        .corner_radius(0.0)
                        .min_size(egui::vec2(ui.available_width(), 40.0));

                        if ui.add_enabled(can_deposit, deposit_btn).clicked() {
                            self.dao_deposit_async();
                        }

                        // ── Status messages ──
                        let mut copied_hash: Option<String> = None;
                        match &self.tx_status {
                            TransactionStatus::Success(tx_hash) => {
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("[ OK ]")
                                            .font(label_font(10.0))
                                            .color(self.colors.accent2),
                                    );
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "SENT 0x{}…{}",
                                            &tx_hash[..8],
                                            &tx_hash[tx_hash.len() - 8..]
                                        ))
                                        .size(11.0)
                                        .color(self.colors.text_muted),
                                    );
                                    if ui
                                        .add(ghost_button(
                                            &self.colors,
                                            "COPY",
                                            egui::vec2(48.0, 18.0),
                                        ))
                                        .clicked()
                                    {
                                        copied_hash = Some(format!("0x{}", tx_hash));
                                    }
                                });
                            }
                            TransactionStatus::Error(e) => {
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("[ERR ]")
                                            .font(label_font(10.0))
                                            .color(self.colors.danger),
                                    );
                                    ui.label(
                                        egui::RichText::new(e)
                                            .size(11.5)
                                            .color(self.colors.danger),
                                    );
                                });
                            }
                            _ => {}
                        }

                        if let Some(hash) = copied_hash {
                            ui.ctx().copy_text(hash);
                            self.status =
                                Status::Info("Transaction hash copied!".to_string());
                        }

                        ui.add_space(12.0);

                        // ── Cancel button ──
                        let avail = ui.available_width();
                        let cancel_clicked = ui
                            .add(ghost_button(
                                &self.colors,
                                "CANCEL",
                                egui::vec2(avail, 32.0),
                            ))
                            .clicked();

                        if cancel_clicked && !is_busy {
                            self.dao_view = DaoView::Overview;
                        }
                    });
            });

        if backdrop_clicked && !is_busy {
            self.dao_view = DaoView::Overview;
        }
    }

    /// Hairline table of deposited and prepared DAO cells.
    /// Transaction results are reported by `draw_tx_status_log` above
    /// the panel, not here.
    pub(crate) fn show_dao_positions_table(&mut self, ui: &mut egui::Ui) {
        let is_busy = !matches!(self.tx_status, TransactionStatus::Idle)
            && !matches!(self.tx_status, TransactionStatus::Success(_))
            && !matches!(self.tx_status, TransactionStatus::Error(_));

        if self.dao_deposited_cells.is_empty() && self.dao_prepared_cells.is_empty() {
            let text = if self.dao_cells_query_rx.is_some() {
                "Loading DAO cells..."
            } else {
                "No active DAO positions."
            };
            ui.label(
                egui::RichText::new(text)
                    .size(11.5)
                    .color(self.colors.text_muted),
            );
            return;
        }

        // Collect actions to perform after the table is rendered
        // (avoid borrow conflicts).
        let mut prepare_action: Option<(ckb_types::packed::OutPoint, String)> = None;
        let mut withdraw_action: Option<(ckb_types::packed::OutPoint, String)> = None;
        // The clicked outpoint, copied to the clipboard after the loop.
        let mut copied_outpoint: Option<String> = None;

        // Helper: find the account index for a given lock_args.
        let account_index =
            |lock_args: &str, accounts: &[qpv2_core::types::SphincsPlusAccount]| -> usize {
                accounts
                    .iter()
                    .position(|a| a.lock_args == lock_args)
                    .unwrap_or(0)
            };

        let full_w = ui.available_width();
        let gap = 10.0;
        let w_acct = 50.0;
        let w_amount = 150.0;
        let w_earned = 140.0;
        let w_age = 96.0;
        let w_state = 70.0;
        let w_action = 104.0;
        // The outpoint carries a full 32-byte tx hash, so it takes the
        // flex slot; the numeric columns are fixed since their values
        // never get that wide.
        let w_outpoint =
            (full_w - w_acct - w_amount - w_earned - w_age - w_state - w_action - 6.0 * gap)
                .max(200.0);
        let widths = [
            w_acct, w_outpoint, w_amount, w_earned, w_age, w_state, w_action,
        ];
        let titles = [
            "ACCOUNT", "OUTPOINT", "AMOUNT", "EARNED", "AGE", "STATE", "ACTION",
        ];

        // Header row.
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for (w, title) in widths.iter().zip(titles) {
                cell_ui(ui, *w, 16.0, |ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .font(label_font(9.0))
                            .color(self.colors.text_muted),
                    );
                });
            }
        });
        hairline(ui, full_w, self.colors.border);

        let mut row_index = 0usize;

        // Deposited cells: earning, awaiting a withdrawal request.
        for (lock_args, cell) in &self.dao_deposited_cells {
            if row_index > 0 {
                hairline(ui, full_w, self.colors.border);
            }
            row_index += 1;

            let row_rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(full_w, ROW_H));
            if ui.rect_contains_pointer(row_rect) {
                row_hover(ui.painter(), row_rect, &self.colors);
            }

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;

                let acct_idx = account_index(lock_args, &self.accounts);
                cell_ui(ui, widths[0], ROW_H, |ui| {
                    ui.label(
                        egui::RichText::new(format!("#{}", acct_idx))
                            .size(11.5)
                            .color(self.colors.text),
                    );
                });

                if let Some(op) = outpoint_cell(ui, &self.colors, widths[1], &cell.out_point) {
                    copied_outpoint = Some(op);
                }

                cell_ui(ui, widths[2], ROW_H, |ui| {
                    ckb_amount(ui, &self.colors, "", cell.capacity, self.colors.text);
                });

                // Estimated earned from cached deposit header + tip — the
                // same figure summed into the panel's CKB EARNED stat.
                let estimated = self.estimated_deposit_interest(cell);
                cell_ui(ui, widths[3], ROW_H, |ui| match estimated {
                    Some(earned) => {
                        ckb_amount(ui, &self.colors, "~+", earned, self.colors.accent2);
                    }
                    None => {
                        ui.label(
                            egui::RichText::new("--")
                                .size(11.5)
                                .color(self.colors.text_muted),
                        );
                    }
                });

                // Lock duration from deposit header timestamp to tip.
                let duration_str = self
                    .deposit_headers
                    .get(&cell.block_number)
                    .zip(self.node_status.tip_header.as_ref())
                    .map(|(dep_h, tip_h)| {
                        let ms = tip_h.timestamp().saturating_sub(dep_h.timestamp());
                        format_duration_ms(ms, false)
                    })
                    .unwrap_or_else(|| "--".to_string());
                cell_ui(ui, widths[4], ROW_H, |ui| {
                    ui.label(
                        egui::RichText::new(duration_str)
                            .size(11.0)
                            .color(self.colors.text_muted),
                    );
                });

                cell_ui(ui, widths[5], ROW_H, |ui| {
                    badge(ui, "DEPOSITED", self.colors.accent);
                });

                cell_ui(ui, widths[6], ROW_H, |ui| {
                    if ui
                        .add_enabled(
                            !is_busy,
                            ghost_button(&self.colors, "REQUEST", egui::vec2(96.0, 20.0)),
                        )
                        .clicked()
                    {
                        prepare_action = Some((cell.out_point.clone(), lock_args.clone()));
                    }
                });
            });
        }

        // Prepared cells: withdrawal requested, claimable after the
        // epoch boundary.
        for (lock_args, cell) in &self.dao_prepared_cells {
            if row_index > 0 {
                hairline(ui, full_w, self.colors.border);
            }
            row_index += 1;

            let row_rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(full_w, ROW_H));
            if ui.rect_contains_pointer(row_rect) {
                row_hover(ui.painter(), row_rect, &self.colors);
            }

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;

                let acct_idx = account_index(lock_args, &self.accounts);
                cell_ui(ui, widths[0], ROW_H, |ui| {
                    ui.label(
                        egui::RichText::new(format!("#{}", acct_idx))
                            .size(11.5)
                            .color(self.colors.text),
                    );
                });

                if let Some(op) = outpoint_cell(ui, &self.colors, widths[1], &cell.out_point) {
                    copied_outpoint = Some(op);
                }

                cell_ui(ui, widths[2], ROW_H, |ui| {
                    ckb_amount(ui, &self.colors, "", cell.capacity, self.colors.text);
                });

                let earned = cell.maximum_withdraw.saturating_sub(cell.capacity);
                cell_ui(ui, widths[3], ROW_H, |ui| {
                    ckb_amount(ui, &self.colors, "+", earned, self.colors.accent2);
                });

                // Lock duration from deposit to prepare.
                let ms = cell
                    .prepare_header
                    .timestamp()
                    .saturating_sub(cell.deposit_header.timestamp());
                cell_ui(ui, widths[4], ROW_H, |ui| {
                    ui.label(
                        egui::RichText::new(format_duration_ms(ms, false))
                            .size(11.0)
                            .color(self.colors.text_muted),
                    );
                });

                cell_ui(ui, widths[5], ROW_H, |ui| {
                    badge(ui, "PREPARED", self.colors.warn);
                });

                cell_ui(ui, widths[6], ROW_H, |ui| {
                    if ui
                        .add_enabled(
                            !is_busy,
                            ghost_button(&self.colors, "WITHDRAW", egui::vec2(96.0, 20.0)),
                        )
                        .clicked()
                    {
                        withdraw_action = Some((cell.out_point.clone(), lock_args.clone()));
                    }
                });
            });
        }

        // Handle deferred actions.
        if let Some((out_point, lock_args)) = prepare_action {
            self.dao_withdraw_request_async(out_point, lock_args);
        }
        if let Some((out_point, lock_args)) = withdraw_action {
            self.dao_withdraw_async(out_point, lock_args);
        }
        if let Some(op) = copied_outpoint {
            ui.ctx().copy_text(op);
            self.status = Status::Info("Outpoint copied!".to_string());
        }
    }
}

/// One readout column: tiny uppercase label above the value.
fn stat_cell(
    ui: &mut egui::Ui,
    colors: &AppColors,
    w: f32,
    label: &str,
    value: impl FnOnce(&mut egui::Ui),
) {
    ui.allocate_ui_with_layout(
        egui::vec2(w, 44.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.label(
                egui::RichText::new(label)
                    .font(label_font(9.0))
                    .color(colors.text_muted),
            );
            ui.add_space(5.0);
            value(ui);
        },
    );
}

/// Vertical hairline between readout columns.
fn stat_divider(ui: &mut egui::Ui, colors: &AppColors, pad: f32) {
    ui.add_space(pad);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(1.0, 44.0), egui::Sense::hover());
    ui.painter().vline(
        rect.center().x,
        rect.y_range(),
        egui::Stroke::new(1.0, colors.border),
    );
    ui.add_space(pad);
}

/// Big readout value: bright integer part, dim 8-digit fraction.
fn stat_ckb_value(
    ui: &mut egui::Ui,
    colors: &AppColors,
    prefix: &str,
    shannons: u64,
    int_color: egui::Color32,
) {
    let (int, frac) = ckb_split(shannons);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label(
            egui::RichText::new(format!("{}{}", prefix, int))
                .font(display_font(18.0))
                .color(int_color),
        );
        ui.label(
            egui::RichText::new(format!(".{}", frac))
                .size(10.0)
                .color(colors.text_muted),
        );
    });
}

/// Table amount: body-size integer part with a dim fraction.
fn ckb_amount(
    ui: &mut egui::Ui,
    colors: &AppColors,
    prefix: &str,
    shannons: u64,
    int_color: egui::Color32,
) {
    let (int, frac) = ckb_split(shannons);
    ui.spacing_mut().item_spacing.x = 0.0;
    ui.label(
        egui::RichText::new(format!("{}{}", prefix, int))
            .size(11.5)
            .color(int_color),
    );
    ui.label(
        egui::RichText::new(format!(".{}", frac))
            .size(11.5)
            .color(colors.text_muted),
    );
}

/// Outpoint cell: a shortened, copy-on-click `0x<tx_hash>:<index>`. The
/// hash never fits the column, so the full value is on the hover tooltip
/// and the clipboard. Returns the string to copy when the cell is clicked.
fn outpoint_cell(
    ui: &mut egui::Ui,
    colors: &AppColors,
    w: f32,
    out_point: &ckb_types::packed::OutPoint,
) -> Option<String> {
    use ckb_types::prelude::*;
    let tx_hash: ckb_types::H256 = out_point.tx_hash().unpack();
    let index: u32 = out_point.index().unpack();
    let text = format!("0x{}:{}", hex::encode(tx_hash.as_bytes()), index);

    let mut clicked = None;
    cell_ui(ui, w, ROW_H, |ui| {
        let resp = ui
            .add(
                egui::Label::new(
                    egui::RichText::new(truncate_middle(&text, 12, 10))
                        .font(egui::FontId::proportional(10.0))
                        .color(colors.text_muted),
                )
                .sense(egui::Sense::click()),
            )
            .on_hover_text(text.clone())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.clicked() {
            clicked = Some(text);
        }
    });
    clicked
}

/// Fixed-size table cell with vertically centered content.
fn cell_ui(ui: &mut egui::Ui, w: f32, h: f32, add: impl FnOnce(&mut egui::Ui)) {
    ui.allocate_ui_with_layout(
        egui::vec2(w, h),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            // allocate_ui_with_layout advances the cursor by the *used*
            // width, not the desired one — pin the cell to its column
            // width so header and row cells share one grid.
            ui.set_min_width(w);
            add(ui);
        },
    );
}

/// Full-width 1px horizontal rule.
fn hairline(ui: &mut egui::Ui, width: f32, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 1.0), egui::Sense::hover());
    ui.painter().hline(
        rect.x_range(),
        rect.center().y,
        egui::Stroke::new(1.0, color),
    );
}
