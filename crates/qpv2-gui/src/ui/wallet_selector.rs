//! Wallet selector popup — quick switch between wallets, anchored
//! below the telemetry strip's VAULT segment.

use eframe::egui;

use crate::types::{label_font, WalletModal};
use crate::ui::utils::row_hover;
use crate::App;

const POPUP_W: f32 = 250.0;
const ROW_H: f32 = 34.0;
const PAD: f32 = 12.0;

impl App {
    pub(crate) fn show_wallet_selector_popup(&mut self, ctx: &egui::Context) {
        if !self.wallet_selector_open {
            return;
        }

        let Some(selector_rect) = self.wallet_selector_rect else {
            return;
        };

        // The anchor segment sits near the window's top-right edge, so
        // the dropdown opens below it and right-aligned to its right
        // edge to stay on-screen at the minimum window width.
        let dropdown_pos = egui::pos2(
            selector_rect.right() - POPUP_W,
            selector_rect.bottom() + 8.0,
        );

        let area_response = egui::Area::new(egui::Id::new("wallet_selector_dropdown"))
            .fixed_pos(dropdown_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .show(ui, |ui| {
                        ui.set_width(POPUP_W);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        self.wallet_selector_contents(ui);
                    });
            });

        // Click outside to close.
        if ctx.input(|i| i.pointer.any_click()) {
            let pointer_pos = ctx.input(|i| i.pointer.hover_pos());
            if let Some(pos) = pointer_pos {
                let dropdown_rect = area_response.response.rect;
                if !dropdown_rect.contains(pos) && !selector_rect.contains(pos) {
                    self.wallet_selector_open = false;
                }
            }
        }
    }

    fn wallet_selector_contents(&mut self, ui: &mut egui::Ui) {
        let c_accent = self.colors.accent;
        let c_accent_tint = self.colors.accent_tint;
        let c_text = self.colors.text;
        let c_muted = self.colors.text_muted;
        let c_border = self.colors.border;

        // ── Title bar ──
        let (bar, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 26.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.text(
            bar.left_center() + egui::vec2(PAD, 0.0),
            egui::Align2::LEFT_CENTER,
            "VAULTS",
            label_font(9.0),
            c_accent,
        );
        painter.text(
            bar.left_center() + egui::vec2(PAD + 48.0, 0.0),
            egui::Align2::LEFT_CENTER,
            "// SELECT",
            label_font(9.0),
            c_muted,
        );
        painter.hline(
            bar.x_range(),
            bar.bottom() - 0.5,
            egui::Stroke::new(1.0, c_border),
        );

        // ── Wallet rows ──
        let mut switch_target: Option<(u32, String)> = None;
        for cw in &self.wallet_cache {
            let active = cw.id == self.wallet_id;
            let (rect, resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), ROW_H),
                egui::Sense::click(),
            );
            if resp.clicked() && !active {
                switch_target = Some((cw.id, cw.name.clone()));
            }

            let painter = ui.painter();
            if active {
                // Active vault: accent tick + tint, same idiom as the
                // module rail's active state.
                painter.rect_filled(rect, 0.0, c_accent_tint);
                painter.rect_filled(
                    egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height())),
                    0.0,
                    c_accent,
                );
            } else if resp.hovered() {
                row_hover(painter, rect, &self.colors);
            }
            if resp.hovered() && !active {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }

            let cy = rect.center().y;

            // Right cluster, painted right to left: the SPHINCS+ variant code
            // anchors the edge, with the ACTIVE badge (active row only) to its
            // left, then a uniform gap before the name.
            let mut rx = rect.right() - PAD;
            let variant = format!("{}", cw.spx_variant).to_uppercase();
            rx -= paint_badge(painter, egui::pos2(rx, cy), &variant, c_muted);
            if active {
                rx -= 6.0;
                rx -= paint_badge(painter, egui::pos2(rx, cy), "ACTIVE", c_accent);
            }
            rx -= 10.0;

            // Name, clipped so long names never run under the badges.
            let clip = egui::Rect::from_min_max(
                egui::pos2(rect.left() + 14.0, rect.top()),
                egui::pos2(rx, rect.bottom()),
            );
            painter.with_clip_rect(clip).text(
                egui::pos2(rect.left() + 14.0, cy),
                egui::Align2::LEFT_CENTER,
                &cw.name,
                egui::FontId::proportional(11.5),
                if active { c_accent } else { c_text },
            );

            painter.hline(
                rect.x_range(),
                rect.bottom() - 0.5,
                egui::Stroke::new(1.0, c_border),
            );
        }

        // ── Quick new-vault row (ghost action) ──
        let (rect, resp) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), ROW_H),
            egui::Sense::click(),
        );
        let painter = ui.painter();
        if resp.hovered() {
            row_hover(painter, rect, &self.colors);
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        painter.text(
            egui::pos2(rect.left() + 14.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            "+ NEW VAULT",
            label_font(9.5),
            c_accent,
        );

        if let Some((id, name)) = switch_target {
            self.switch_wallet(id, &name);
        }
        if resp.clicked() {
            // Hand off to the create modal with fresh name/variant
            // inputs, mirroring the Wallets tab's create action.
            self.wallet_modal = WalletModal::Create;
            self.new_wallet_name.clear();
            self.new_wallet_variant = qpv2_core::types::SpxVariant::Sha2128S;
            self.wallet_selector_open = false;
        }
    }
}

/// Paint a right-aligned uppercase badge ending at `right_center`;
/// returns the painted width so callers can stack further elements.
/// (Painter-space twin of `utils::badge`, which needs a `Ui` slot.)
fn paint_badge(
    painter: &egui::Painter,
    right_center: egui::Pos2,
    text: &str,
    color: egui::Color32,
) -> f32 {
    let galley = painter.layout_no_wrap(text.to_string(), label_font(8.5), color);
    let pad = egui::vec2(5.0, 2.0);
    let size = galley.size() + pad * 2.0;
    let rect = egui::Rect::from_min_size(
        egui::pos2(right_center.x - size.x, right_center.y - size.y / 2.0),
        size,
    );
    painter.rect_filled(
        rect,
        0.0,
        egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 24),
    );
    painter.rect_stroke(
        rect,
        0.0,
        egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 90),
        ),
        egui::StrokeKind::Inside,
    );
    painter.galley(rect.min + pad, galley, color);
    size.x
}
