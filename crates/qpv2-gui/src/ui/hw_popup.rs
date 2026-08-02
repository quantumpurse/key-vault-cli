//! Trezor status dropdown, anchored below the telemetry strip's TREZOR
//! segment. Shows what the link probe last saw, explains it when the device
//! needs attention, and offers the only reconnect control in the app.
//!
//! Reconnecting lives here rather than on the segment itself because it opens a
//! real THP session — which can raise a PIN keyboard or a "Connect?" tap on the
//! device. That must be a deliberate choice, never a side effect of clicking
//! the status strip.

use eframe::egui;

use crate::types::label_font;
use crate::ui::utils::{breathing_dot, ghost_button};
use crate::App;
use trezor_connect::DeviceStatus;

const POPUP_W: f32 = 220.0;
const PAD: f32 = 12.0;

impl App {
    pub(crate) fn show_device_popup(&mut self, ctx: &egui::Context) {
        if !self.device_popup_open {
            return;
        }
        let Some(anchor) = self.device_popup_rect else {
            return;
        };

        let dropdown_pos = egui::pos2(anchor.left(), anchor.bottom() + 8.0);
        let area_response = egui::Area::new(egui::Id::new("device_status_dropdown"))
            .fixed_pos(dropdown_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .inner_margin(egui::Margin::same(PAD as i8))
                    .show(ui, |ui| {
                        ui.set_width(POPUP_W);
                        self.device_popup_contents(ui);
                    });
            });

        // The status dot breathes while open.
        ctx.request_repaint_after(std::time::Duration::from_millis(50));

        if ctx.input(|i| i.pointer.any_click()) {
            if let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) {
                let dropdown_rect = area_response.response.rect;
                if !dropdown_rect.contains(pos) && !anchor.contains(pos) {
                    self.device_popup_open = false;
                }
            }
        }
    }

    fn device_popup_contents(&mut self, ui: &mut egui::Ui) {
        let t = ui.input(|i| i.time) as f32;
        let connecting = self.trezor_reconnect_rx.is_some();
        // Same precedence as the segment: a live operation outranks the probe,
        // whose last result is stale by definition while a session is open.
        let status = if self.trezor_operation_in_flight() {
            DeviceStatus::Working
        } else {
            self.device_status
        };

        let (headline, detail, tint) = match status {
            DeviceStatus::Linked => (
                "LINKED",
                "Connected over USB and ready to sign.",
                self.colors.accent2,
            ),
            DeviceStatus::Emulator => (
                "EMULATOR",
                "Connected to the local firmware emulator.",
                self.colors.accent2,
            ),
            DeviceStatus::Busy => (
                "IN USE",
                "Another application holds the Trezor.",
                self.colors.warn,
            ),
            DeviceStatus::Absent => ("OFFLINE", "No Trezor device found.", self.colors.danger),
            DeviceStatus::Working => (
                if connecting { "CONNECTING" } else { "WORKING" },
                "Talking to your hardware wallet — check its screen.",
                self.colors.accent,
            ),
        };

        ui.horizontal(|ui| {
            let (dot, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
            breathing_dot(
                ui.painter(),
                dot.center(),
                tint,
                t,
                matches!(status, DeviceStatus::Busy | DeviceStatus::Absent),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(headline)
                    .font(label_font(11.0))
                    .color(tint),
            );
        });

        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(detail)
                .font(label_font(10.0))
                .color(self.colors.text_muted),
        );

        // Only offered when there is something to fix: from a healthy state a
        // connect would make the device demand a confirmation for nothing.
        if matches!(status, DeviceStatus::Busy | DeviceStatus::Absent) || connecting {
            ui.add_space(10.0);
            let label = if connecting {
                "Connecting"
            } else {
                "Reconnect"
            };
            let btn = ghost_button(&self.colors, label, egui::vec2(ui.available_width(), 30.0));
            if ui.add_enabled(!connecting, btn).clicked() {
                self.reconnect_trezor();
            }
        }
    }
}
