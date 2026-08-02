//! Node selector popup: network + backend draft selection, anchored
//! below the telemetry strip's NODE segment. Drafts (`self.network`,
//! `self.node_type`) are seeded by the chrome when the popup opens and
//! committed only on APPLY, so closing the popup discards edits.

use ckb_node::{NetworkType, NodeConfig, NodeType};
use eframe::egui;

use crate::types::{label_font, Status};
use crate::ui::utils::{accent_button, breathing_dot, row_hover};
use crate::App;

const POPUP_W: f32 = 220.0;
const ROW_H: f32 = 34.0;
const PAD: f32 = 12.0;

impl App {
    pub(crate) fn show_node_selector_popup(&mut self, ctx: &egui::Context) {
        if !self.node_selector_open {
            return;
        }

        let Some(selector_rect) = self.node_selector_rect else {
            return;
        };

        let dropdown_pos = egui::pos2(selector_rect.left(), selector_rect.bottom() + 8.0);

        let area_response = egui::Area::new(egui::Id::new("node_selector_dropdown"))
            .fixed_pos(dropdown_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .show(ui, |ui| {
                        ui.set_width(POPUP_W);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        self.node_selector_contents(ui);
                    });
            });

        // The live backend's breathing dot animates while open.
        ctx.request_repaint_after(std::time::Duration::from_millis(50));

        // Click outside to close (discarding draft edits).
        if ctx.input(|i| i.pointer.any_click()) {
            let pointer_pos = ctx.input(|i| i.pointer.hover_pos());
            if let Some(pos) = pointer_pos {
                let dropdown_rect = area_response.response.rect;
                if !dropdown_rect.contains(pos) && !selector_rect.contains(pos) {
                    self.node_selector_open = false;
                }
            }
        }
    }

    fn node_selector_contents(&mut self, ui: &mut egui::Ui) {
        let t = ui.input(|i| i.time) as f32;
        let c_accent = self.colors.accent;
        let c_accent_tint = self.colors.accent_tint;
        let c_accent2 = self.colors.accent2;
        let c_warn = self.colors.warn;
        let c_danger = self.colors.danger;
        let c_text = self.colors.text;
        let c_muted = self.colors.text_muted;
        let c_border = self.colors.border;
        let c_border2 = self.colors.border2;
        let online = self.node_status.online;
        let live_type = self.qp_client.config().node_type;

        // ── Title bar ──
        let (bar, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 26.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.text(
            bar.left_center() + egui::vec2(PAD, 0.0),
            egui::Align2::LEFT_CENTER,
            "NODE LINK",
            label_font(9.0),
            c_accent,
        );
        painter.text(
            bar.left_center() + egui::vec2(PAD + 64.0, 0.0),
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

        // ── Network toggle: MAIN (accent) / TEST (warn) ──
        let (label_row, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 22.0), egui::Sense::hover());
        ui.painter().text(
            egui::pos2(label_row.left() + PAD, label_row.bottom() - 7.0),
            egui::Align2::LEFT_CENTER,
            "NETWORK",
            label_font(8.5),
            c_muted,
        );

        let (net_row, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::hover());
        let inner = net_row.shrink2(egui::vec2(PAD, 1.0));
        let gap = 6.0;
        let cell_w = (inner.width() - gap) / 2.0;
        let cells = [
            (NetworkType::Mainnet, "MAIN", c_accent),
            (NetworkType::Testnet, "TEST", c_warn),
        ];
        for (i, (net, label, color)) in cells.into_iter().enumerate() {
            let rect = egui::Rect::from_min_size(
                egui::pos2(inner.left() + i as f32 * (cell_w + gap), inner.top()),
                egui::vec2(cell_w, inner.height()),
            );
            let resp = ui.interact(rect, ui.id().with(("net-cell", i)), egui::Sense::click());
            if resp.clicked() {
                self.network = net;
            }
            let selected = self.network == net;
            let painter = ui.painter();
            if selected {
                painter.rect_filled(
                    rect,
                    0.0,
                    egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 22),
                );
                painter.rect_stroke(
                    rect,
                    0.0,
                    egui::Stroke::new(1.0, color),
                    egui::StrokeKind::Inside,
                );
            } else {
                painter.rect_stroke(
                    rect,
                    0.0,
                    egui::Stroke::new(1.0, if resp.hovered() { c_border2 } else { c_border }),
                    egui::StrokeKind::Inside,
                );
            }
            if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                label,
                label_font(9.5),
                if selected { color } else { c_muted },
            );
        }

        ui.add_space(8.0);

        // ── Backend rows ──
        let (label_row, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 18.0), egui::Sense::hover());
        ui.painter().text(
            egui::pos2(label_row.left() + PAD, label_row.bottom() - 7.0),
            egui::Align2::LEFT_CENTER,
            "BACKEND",
            label_font(8.5),
            c_muted,
        );

        let rows = [
            (NodeType::FullNode, "FULL NODE", "FULL"),
            (NodeType::LightClient, "LIGHT CLIENT", "LC"),
            (NodeType::PublicRpc, "REMOTE RPC", "RPC"),
        ];
        for (ntype, name, code) in rows {
            let (rect, resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), ROW_H),
                egui::Sense::click(),
            );
            if resp.clicked() {
                self.node_type = ntype;
            }
            let selected = self.node_type == ntype;
            let live = live_type == ntype;
            let painter = ui.painter();

            if selected {
                // Draft selection: accent tick + tint.
                painter.rect_filled(rect, 0.0, c_accent_tint);
                painter.rect_filled(
                    egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height())),
                    0.0,
                    c_accent,
                );
            } else if resp.hovered() {
                row_hover(painter, rect, &self.colors);
            }
            if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }

            let cy = rect.center().y;
            painter.text(
                egui::pos2(rect.left() + 14.0, cy),
                egui::Align2::LEFT_CENTER,
                name,
                egui::FontId::proportional(11.5),
                if selected { c_accent } else { c_text },
            );

            // Right cluster: live backend gets a breathing status dot
            // and the ACTIVE badge; the others show their code.
            let mut rx = rect.right() - PAD;
            if live {
                let dot_color = if online { c_accent2 } else { c_danger };
                rx -= paint_badge(painter, egui::pos2(rx, cy), "ACTIVE", dot_color) + 12.0;
                breathing_dot(painter, egui::pos2(rx, cy), dot_color, t, !online);
            } else {
                paint_badge(painter, egui::pos2(rx, cy), code, c_muted);
            }

            painter.hline(
                rect.x_range(),
                rect.bottom() - 0.5,
                egui::Stroke::new(1.0, c_border),
            );
        }

        if !online {
            let (row, _) = ui
                .allocate_exact_size(egui::vec2(ui.available_width(), 20.0), egui::Sense::hover());
            ui.painter().text(
                egui::pos2(row.left() + PAD, row.center().y),
                egui::Align2::LEFT_CENTER,
                "[ ! ] NO CONNECTION",
                label_font(8.5),
                c_danger,
            );
        }

        // ── Apply ──
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(PAD);
            let apply = accent_button(&self.colors, "Apply", egui::vec2(POPUP_W - 2.0 * PAD, 30.0));
            if ui.add(apply).clicked() {
                self.apply_node_selection();
                self.node_selector_open = false;
            }
        });
        ui.add_space(PAD);
    }

    /// Commit the drafted (network, backend) pair. Mirrors the node
    /// manager's commit path (private to that module): refresh the RPC
    /// URL preview, persist via `apply_node_config`, restart the local
    /// node process, and reload the per-network tx history cache when
    /// the network changed.
    fn apply_node_selection(&mut self) {
        let cfg = self.qp_client.config();
        let old_network = cfg.network;
        let backend_changed = cfg.node_type != self.node_type;
        let network_changed = old_network != self.network;
        if !backend_changed && !network_changed {
            return;
        }

        if backend_changed {
            self.on_node_type_changed();
        } else if self.node_type == NodeType::PublicRpc {
            // Network flip on the public backend: retarget the default
            // endpoint for the new network.
            self.settings_rpc_url =
                NodeConfig::default_rpc_url_for(self.node_type, self.network).to_string();
        }

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
}

/// Paint a right-aligned uppercase badge ending at `right_center`;
/// returns the painted width so callers can stack further elements.
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
