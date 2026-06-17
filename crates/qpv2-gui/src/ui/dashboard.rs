//! Dashboard tab: the flagship telemetry grid — balance readout,
//! quick actions, and the transaction tape.

use eframe::egui;

use super::utils::{
    breathing_dot, ckb_split, draw_trend_chart, ghost_button, lerp_color, panel_frame, row_hover,
    section_header, value_flash,
};
use crate::types::{display_font, label_font, AppColors, Status, Tab, TxKind, TxRecord};
use crate::utils::format_relative_time;
use crate::App;

/// Horizontal padding for the whole screen.
const PAD: f32 = 24.0;

/// Meta value below the total: integer part + 2 decimals keeps the
/// strip readable; the hero number above carries full precision.
fn meta_ckb(shannons: u64) -> String {
    let (int, frac) = ckb_split(shannons);
    format!("{}.{}", int, &frac[..2])
}

impl App {
    pub(crate) fn show_dashboard_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(PAD);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - PAD);

                // ── Screen header ──
                ui.label(
                    egui::RichText::new("DASHBOARD")
                        .font(display_font(16.0))
                        .color(self.colors.text),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("Portfolio overview and activity.")
                        .size(11.0)
                        .color(self.colors.text_muted),
                );
                ui.add_space(14.0);

                self.draw_balance_panel(ui);
                ui.add_space(12.0);
                self.draw_quick_actions(ui);
                ui.add_space(16.0);
                self.draw_transaction_tape(ui);

                ui.add_space(12.0);
                self.show_status(ui);
                ui.add_space(20.0);
            });
        });
    }

    /// The hero readout: full-precision total, then a five-column meta
    /// strip under a hairline rule.
    fn draw_balance_panel(&mut self, ui: &mut egui::Ui) {
        // Sum all balances + DAO earned interest.
        let base_balance: u64 = self
            .balances
            .values()
            .filter_map(|b| b.as_ref().copied())
            .sum();
        // DAO interest: prepared cells carry an exact, locked-in payout;
        // deposited cells are still earning, estimated from AR growth to
        // tip (the same per-position figure the DAO tab shows). Both are
        // folded into the total so the headline, the chart, and the
        // AVAILABLE + DAO LOCKED + DAO EARNED columns stay consistent.
        let prepared_interest: u64 = self
            .dao_prepared_cells
            .iter()
            .map(|(_, c)| c.maximum_withdraw.saturating_sub(c.capacity))
            .sum();
        let deposited_estimate: u64 = self
            .dao_deposited_cells
            .iter()
            .filter_map(|(_, c)| self.estimated_deposit_interest(c))
            .sum();
        let dao_earned = prepared_interest + deposited_estimate;
        let total_shannons = base_balance + dao_earned;

        // DAO Locked — sum of deposited + prepared cell capacities
        // across all accounts.
        let dao_locked: u64 = self
            .dao_deposited_cells
            .iter()
            .map(|(_, c)| c.capacity)
            .chain(self.dao_prepared_cells.iter().map(|(_, c)| c.capacity))
            .sum();
        // Spendable cells only — no type script, no data.
        let available: u64 = self
            .spendable_balances
            .values()
            .filter_map(|b| b.as_ref().copied())
            .sum();

        panel_frame(&self.colors).show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_header(ui, &self.colors, "01", "Total Balance");
            ui.add_space(12.0);

            // Display numerals on the left; the balance-history chart
            // claims all remaining width up to the panel's right edge.
            // The numerals column is measured from the actual strings
            // at the actual fonts so the hero readout can never wrap,
            // whatever the balance magnitude or window width.
            let flash = value_flash(ui, egui::Id::new("dash-total-flash"), total_shannons);
            let int_color = lerp_color(self.colors.text, self.colors.accent, flash);
            let (int, frac) = ckb_split(total_shannons);
            let int_w = ui
                .painter()
                .layout_no_wrap(int.clone(), display_font(34.0), int_color)
                .size()
                .x;
            let frac_w = ui
                .painter()
                .layout_no_wrap(format!(".{}", frac), display_font(20.0), int_color)
                .size()
                .x;
            let left_w = int_w + frac_w + 10.0 + 30.0; // gap + "CKB" tag
            let chart_w = (ui.available_width() - left_w - 14.0).max(140.0);
            ui.horizontal_top(|ui| {
                // The 14px gap below is the only spacing between the two
                // columns; without this, egui's default item_spacing.x
                // adds another 8px that chart_w doesn't account for, so
                // the chart overflows the panel's right edge and the
                // card's border eats into the screen's right margin.
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.vertical(|ui| {
                    ui.set_width(left_w);
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.label(
                            egui::RichText::new(int)
                                .font(display_font(34.0))
                                .color(int_color),
                        );
                        ui.label(
                            egui::RichText::new(format!(".{}", frac))
                                .font(display_font(20.0))
                                .color(self.colors.text_muted),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("CKB")
                                .font(label_font(10.0))
                                .color(self.colors.accent),
                        );
                    });
                });
                ui.add_space(14.0);
                ui.vertical(|ui| {
                    ui.set_width(chart_w);
                    // Memoized: replaying + sorting the whole tape every
                    // frame is wasted work. Key on the inputs, with time
                    // bucketed to 10s so the cache stays hot between
                    // repaints.
                    let now = crate::utils::unix_now_secs();
                    let key = (self.tx_history.len(), total_shannons, now / 10);
                    if self.balance_chart_cache.as_ref().map(|(k, _, _)| *k) != Some(key) {
                        let (h, d) = self.balance_history(total_shannons, now);
                        self.balance_chart_cache = Some((key, h, d));
                    }
                    let (_, history, _) = self.balance_chart_cache.as_ref().expect("set above");
                    draw_trend_chart(
                        ui,
                        &self.colors,
                        history,
                        96.0,
                        "NO SYNCED HISTORY YET",
                        "Your total balance over synced history.",
                    );
                });
            });

            ui.add_space(12.0);
            let (rule, _) =
                ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
            ui.painter().hline(
                rule.x_range(),
                rule.center().y,
                egui::Stroke::new(1.0, self.colors.border),
            );
            ui.add_space(10.0);

            // Semantic colors: spendable in the accent, locked capital
            // in caution yellow, yield in green; the plain count stays
            // neutral.
            // "~" once deposited cells contribute (their payout is at a
            // future epoch), matching the DAO tab's per-position figures.
            let earned_prefix = if self.dao_deposited_cells.is_empty() {
                "+"
            } else {
                "~+"
            };
            let metas = [
                ("AVAILABLE", meta_ckb(available), self.colors.accent),
                (
                    "ACCOUNTS",
                    format!("{}", self.accounts.len()),
                    self.colors.text,
                ),
                ("DAO LOCKED", meta_ckb(dao_locked), self.colors.warn),
                (
                    "DAO EARNED",
                    format!("{}{}", earned_prefix, meta_ckb(dao_earned)),
                    self.colors.accent2,
                ),
                ("APC", self.compute_dao_apc(), self.colors.accent2),
                (
                    "QR TVL",
                    self.qr_adoption_series
                        .last()
                        .map(|&(_, v)| meta_ckb(v))
                        .unwrap_or_else(|| "--".to_string()),
                    self.colors.accent,
                ),
            ];
            let gap = 25.0;
            let n = metas.len() as f32;
            let col_w = (ui.available_width() - (n - 1.0) * gap) / n;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for (i, (label, value, color)) in metas.iter().enumerate() {
                    if i > 0 {
                        ui.add_space(12.0);
                        let (div, _) =
                            ui.allocate_exact_size(egui::vec2(1.0, 30.0), egui::Sense::hover());
                        ui.painter().vline(
                            div.center().x,
                            div.y_range(),
                            egui::Stroke::new(1.0, self.colors.border),
                        );
                        ui.add_space(12.0);
                    }
                    ui.allocate_ui_with_layout(
                        egui::vec2(col_w, 30.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.label(
                                egui::RichText::new(*label)
                                    .font(label_font(9.0))
                                    .color(self.colors.text_muted),
                            );
                            ui.add_space(3.0);
                            ui.label(egui::RichText::new(value).size(13.0).color(*color));
                        },
                    );
                }
            });
        });
    }

    /// Reconstructs the wallet's full balance history by replaying the
    /// transaction tape backwards from the live total. Internal
    /// transfers and DAO operations are (fees aside) net-zero to the
    /// wallet total and produce no step.
    ///
    /// Returns `(line_points, tx_points)`: the line connects the
    /// balance after each transaction with straight segments (matching
    /// the TVL chart's look), from the first known transaction to the
    /// live total. `tx_points` holds one
    /// entry per balance-changing transaction for dot markers; event
    /// timestamps are fixed, so dots never drift between repaints.
    fn balance_history(&self, current_total: u64, now: u64) -> (Vec<(u64, u64)>, Vec<(u64, u64)>) {
        // Clamp event times below `now`: block headers may run ahead
        // of the local clock (consensus allows ~15s), and the series is
        // headed by the (now, total) anchor — a later event would make
        // the x axis double back.
        let mut events: Vec<(u64, i128)> = self
            .tx_history
            .iter()
            .filter(|r| r.timestamp > 0 && r.internal_counterparty_lock_args.is_none())
            .filter_map(|r| {
                let ts = r.timestamp.min(now.saturating_sub(1));
                match r.tx_kind {
                    TxKind::Incoming => Some((ts, r.amount as i128)),
                    TxKind::Outgoing => Some((ts, -(r.amount as i128))),
                    _ => None,
                }
            })
            .collect();
        if events.is_empty() {
            return (Vec::new(), Vec::new());
        }
        events.sort_by_key(|&(ts, _)| ts);

        // Coalesce same-timestamp events (txs sharing a block): one net
        // delta per instant, or the interleaved step edges would send
        // the x axis backwards and the area fill into bowtie quads.
        let mut merged: Vec<(u64, i128)> = Vec::with_capacity(events.len());
        for (ts, delta) in events {
            match merged.last_mut() {
                Some((last_ts, last_delta)) if *last_ts == ts => *last_delta += delta,
                _ => merged.push((ts, delta)),
            }
        }

        // Straight segments between transaction points (the TVL chart's
        // look) rather than square step edges: each point is the
        // balance right after its transaction, plus the live total as
        // the head.
        let mut points: Vec<(u64, u64)> = vec![(now, current_total)];
        let mut tx_points: Vec<(u64, u64)> = Vec::new();
        let mut bal = current_total as i128;
        for &(ts, delta) in merged.iter().rev() {
            let after = (ts, bal.max(0) as u64);
            points.push(after);
            tx_points.push(after);
            bal -= delta;
        }
        // Deliberately no pre-history anchor point: it is ~0 for any
        // wallet whose funding is inside the synced window, and a 0 in
        // the series pins the y-axis to zero — flattening the real
        // balance detail into the top few pixels. The line starts at
        // the first known transaction instead.
        points.reverse();
        tx_points.reverse();
        (points, tx_points)
    }

    /// One row of equal-width module shortcuts.
    fn draw_quick_actions(&mut self, ui: &mut egui::Ui) {
        let actions = [
            ("SEND", Tab::Transfer),
            ("RECEIVE", Tab::Accounts),
            ("DAO", Tab::DaoOperations),
            ("NODES", Tab::NodeManager),
            ("WALLETS", Tab::Wallets),
        ];
        let gap = 8.0;
        let btn_w = (ui.available_width() - 4.0 * gap) / 5.0;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for (label, target_tab) in actions {
                let btn = ghost_button(&self.colors, label, egui::vec2(btn_w, 32.0));
                if ui.add(btn).clicked() {
                    self.active_tab = target_tab;
                }
            }
        });
    }

    /// The transaction tape: a hairline table of resolved history.
    fn draw_transaction_tape(&mut self, ui: &mut egui::Ui) {
        let count_text = if self.tx_history.is_empty() && self.tx_history_rx.is_some() {
            "SYNCING".to_string()
        } else {
            format!("{}", self.tx_history.len())
        };

        panel_frame(&self.colors).show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_header(
                ui,
                &self.colors,
                "02",
                &format!("Transaction Tape // {}", count_text),
            );
            ui.add_space(10.0);

            if self.tx_history.is_empty() {
                ui.label(
                    egui::RichText::new("No transactions yet.")
                        .size(11.5)
                        .color(self.colors.text_muted),
                );
                return;
            }

            let records: Vec<TxRecord> = self.tx_history.clone();
            let accounts = &self.accounts;
            let t = ui.input(|i| i.time) as f32;
            let w = ui.available_width();

            // Fixed column offsets relative to the row's left edge;
            // AMOUNT is right-aligned against the STATUS column.
            let time_x = 6.0;
            let type_x = 84.0;
            let hash_x = 140.0;
            // AMOUNT starts past the longest hash + routing note so the
            // left-aligned columns never collide at the minimum width.
            let amount_x = 620.0;
            let status_x = w - 104.0;

            // Header row.
            let (hrect, _) = ui.allocate_exact_size(egui::vec2(w, 18.0), egui::Sense::hover());
            let painter = ui.painter();
            let hcols = [
                (time_x, "TIME"),
                (type_x, "TYPE"),
                (hash_x, "HASH"),
                (amount_x, "AMOUNT"),
                (status_x, "STATUS"),
            ];
            for (x, label) in hcols {
                painter.text(
                    egui::pos2(hrect.left() + x, hrect.center().y),
                    egui::Align2::LEFT_CENTER,
                    label,
                    label_font(9.0),
                    self.colors.text_muted,
                );
            }
            painter.hline(
                hrect.x_range(),
                hrect.bottom() - 0.5,
                egui::Stroke::new(1.0, self.colors.border),
            );

            let mut any_pending = false;
            // Copy is deferred past the loop: the rows borrow
            // `self.accounts`, so `self.status` can't be set inside it.
            let mut copied_hash: Option<String> = None;
            for record in &records {
                let owner_idx = accounts
                    .iter()
                    .position(|a| a.lock_args == record.owner_lock_args);
                let counterparty_idx = record
                    .internal_counterparty_lock_args
                    .as_ref()
                    .and_then(|args| accounts.iter().position(|a| a.lock_args == *args));
                any_pending |= record.is_pending;

                let (rect, response) =
                    ui.allocate_exact_size(egui::vec2(w, 28.0), egui::Sense::click());
                let response = response
                    .on_hover_text("Click to copy transaction hash")
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                if response.clicked() {
                    copied_hash = Some(record.tx_hash.clone());
                }
                let painter = ui.painter();
                if response.hovered() {
                    row_hover(painter, rect, &self.colors);
                }
                draw_tape_row(
                    painter,
                    rect,
                    &self.colors,
                    record,
                    owner_idx,
                    counterparty_idx,
                    (time_x, type_x, hash_x, amount_x, status_x),
                    t,
                );
                painter.hline(
                    rect.x_range(),
                    rect.bottom() - 0.5,
                    egui::Stroke::new(1.0, self.colors.border),
                );
            }

            if let Some(hash) = copied_hash {
                ui.ctx().copy_text(hash);
                self.status = Status::Info("Transaction hash copied!".to_string());
            }

            // Keep pending dots breathing without a per-frame repaint.
            if any_pending {
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(50));
            }
        });
    }
}

/// Paint one tape row: TIME | TYPE | HASH | AMOUNT | STATUS.
#[allow(clippy::too_many_arguments)]
fn draw_tape_row(
    painter: &egui::Painter,
    rect: egui::Rect,
    colors: &AppColors,
    record: &TxRecord,
    account_index: Option<usize>,
    counterparty_index: Option<usize>,
    (time_x, type_x, hash_x, amount_x, status_x): (f32, f32, f32, f32, f32),
    t: f32,
) {
    let cy = rect.center().y;
    let body = egui::FontId::proportional(11.5);

    // TIME.
    let time_str = if record.timestamp > 0 {
        format_relative_time(record.timestamp)
    } else {
        "...".to_string()
    };
    painter.text(
        egui::pos2(rect.left() + time_x, cy),
        egui::Align2::LEFT_CENTER,
        time_str,
        body.clone(),
        colors.text_muted,
    );

    // TYPE badge: short codes, semantic color.
    let (code, code_color) = match record.tx_kind {
        TxKind::Incoming => ("IN", colors.accent2),
        TxKind::Outgoing => ("OUT", colors.danger),
        TxKind::DaoDeposit => ("DEP", colors.accent),
        TxKind::DaoPrepare => ("WD", colors.accent),
        TxKind::DaoWithdraw => ("UNLK", colors.accent),
    };
    paint_badge(
        painter,
        egui::pos2(rect.left() + type_x, cy),
        code,
        code_color,
    );

    // HASH, in full — block explorers and co-signers need the whole
    // thing; the smaller font keeps it clear of the amount column at
    // the minimum window width. Internal transfers keep their
    // account-routing note ("#0 → #2") beside it.
    let hash_end = painter
        .text(
            egui::pos2(rect.left() + hash_x, cy),
            egui::Align2::LEFT_CENTER,
            &record.tx_hash,
            egui::FontId::proportional(10.0),
            colors.text_muted,
        )
        .right();
    if let Some(idx) = account_index {
        let route = if let Some(cp_idx) = counterparty_index {
            let arrow = match record.tx_kind {
                TxKind::Incoming => "\u{2190}",
                _ => "\u{2192}",
            };
            format!("#{} {} #{}", idx, arrow, cp_idx)
        } else {
            format!("#{}", idx)
        };
        painter.text(
            egui::pos2(hash_end + 10.0, cy),
            egui::Align2::LEFT_CENTER,
            route,
            label_font(8.5),
            colors.text_muted,
        );
    }

    // AMOUNT: signed integer part in semantic color, fraction dim.
    // Internal transfers are neutral — money moved between our own
    // accounts, not in or out.
    let is_internal = counterparty_index.is_some();
    let (prefix, amount_color) = if is_internal {
        ("", colors.text)
    } else {
        match record.tx_kind {
            TxKind::Incoming => ("+", colors.accent2),
            _ => ("\u{2212}", colors.danger),
        }
    };
    let (int, frac) = ckb_split(record.amount);
    let int_rect = painter.text(
        egui::pos2(rect.left() + amount_x, cy),
        egui::Align2::LEFT_CENTER,
        format!("{}{}.", prefix, int),
        body.clone(),
        amount_color,
    );
    painter.text(
        egui::pos2(int_rect.right(), cy),
        egui::Align2::LEFT_CENTER,
        frac,
        body,
        colors.text_muted,
    );

    // STATUS.
    if record.is_pending {
        breathing_dot(
            painter,
            egui::pos2(rect.left() + status_x + 3.0, cy),
            colors.accent,
            t,
            false,
        );
        painter.text(
            egui::pos2(rect.left() + status_x + 12.0, cy),
            egui::Align2::LEFT_CENTER,
            "PENDING",
            label_font(9.0),
            colors.accent,
        );
    } else {
        painter.text(
            egui::pos2(rect.left() + status_x, cy),
            egui::Align2::LEFT_CENTER,
            "CONFIRMED",
            label_font(9.0),
            colors.accent2.gamma_multiply(0.7),
        );
    }
}

/// Painter-space twin of `utils::badge` for rows laid out by hand.
fn paint_badge(painter: &egui::Painter, left_center: egui::Pos2, text: &str, color: egui::Color32) {
    let galley = painter.layout_no_wrap(text.to_string(), label_font(8.5), color);
    let rect = egui::Rect::from_min_size(
        egui::pos2(left_center.x, left_center.y - galley.size().y / 2.0 - 2.0),
        galley.size() + egui::vec2(10.0, 4.0),
    );
    let tint = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 24);
    painter.rect_filled(rect, 0.0, tint);
    painter.rect_stroke(
        rect,
        0.0,
        egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 90),
        ),
        egui::StrokeKind::Inside,
    );
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
}
