//! Modal for creating a multisig account, in the Flight Deck idiom:
//! sharp hairline-framed surface with indexed sections for the local
//! signer, the M/R signing policy, and the co-signer roster.

use eframe::egui;
use qpv2_core::types::SpxVariant;

use crate::types::label_font;
use crate::ui::utils::{accent_button, ghost_button, pin_popup_above_modal, section_header};
use crate::App;

const MODAL_W: f32 = 480.0;

impl App {
    pub(crate) fn show_multisig_modal(&mut self, ctx: &egui::Context) {
        if !self.multisig_modal_open {
            return;
        }

        // Semi-transparent backdrop that consumes clicks.
        let screen_rect = ctx.input(|i| i.viewport_rect());
        let backdrop_clicked = egui::Area::new(egui::Id::new("multisig_modal_backdrop"))
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

        let modal_pos = egui::pos2(
            (screen_rect.width() - MODAL_W) / 2.0,
            screen_rect.height() * 0.1,
        );

        egui::Area::new(egui::Id::new("multisig_modal_area"))
            .fixed_pos(modal_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .inner_margin(egui::Margin::symmetric(20, 18))
                    .show(ui, |ui| {
                        ui.set_width(MODAL_W);
                        self.multisig_modal_contents(ui);
                    });
            });

        if backdrop_clicked {
            self.multisig_modal_open = false;
        }
    }

    fn multisig_modal_contents(&mut self, ui: &mut egui::Ui) {
        let c_accent = self.colors.accent;
        let c_text = self.colors.text;
        let c_muted = self.colors.text_muted;
        let c_border = self.colors.border;
        let c_danger = self.colors.danger;

        // ── Title row + hairline ──
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("NEW MULTISIG")
                    .font(label_font(11.0))
                    .color(c_accent),
            );
            ui.label(
                egui::RichText::new("// CONFIGURE")
                    .font(label_font(11.0))
                    .color(c_muted),
            );
        });
        ui.add_space(8.0);
        let (rule, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
        ui.painter().hline(
            rule.x_range(),
            rule.center().y,
            egui::Stroke::new(1.0, c_border),
        );
        ui.add_space(14.0);

        // ── 01 / Local Signer ──
        section_header(ui, &self.colors, "01", "Local Signer");
        ui.add_space(6.0);

        let singlesig: Vec<_> = self
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| a.config.signers.len() == 1)
            .collect();

        let selected_text = if singlesig.is_empty() {
            "NO SINGLE-SIG ACCOUNTS".to_string()
        } else {
            let idx = self.multisig_local_signer_idx.min(singlesig.len() - 1);
            let (orig_i, _) = singlesig[idx];
            format!("ACCOUNT #{}", orig_i)
        };
        let selected_color = if singlesig.is_empty() {
            c_muted
        } else {
            c_accent
        };
        let signer_combo = egui::ComboBox::from_id_salt("ms_local_signer")
            .selected_text(
                egui::RichText::new(&selected_text)
                    .size(12.0)
                    .color(selected_color),
            )
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                for (pos, (orig_i, _)) in singlesig.iter().enumerate() {
                    let text = egui::RichText::new(format!("ACCOUNT #{}", orig_i))
                        .size(12.0)
                        .color(if self.multisig_local_signer_idx == pos {
                            c_accent
                        } else {
                            c_text
                        });
                    ui.selectable_value(&mut self.multisig_local_signer_idx, pos, text);
                }
            });
        pin_popup_above_modal(ui, &signer_combo.response);

        ui.add_space(14.0);

        // ── 02 / Signing Policy ──
        section_header(ui, &self.colors, "02", "Signing Policy");
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("THRESHOLD (M)")
                    .font(label_font(9.5))
                    .color(c_muted),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(egui::DragValue::new(&mut self.multisig_threshold).range(1..=255u8));
            });
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("REQUIRED FIRST N (R)")
                    .font(label_font(9.5))
                    .color(c_muted),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(
                    egui::DragValue::new(&mut self.multisig_required_first_n)
                        .range(0..=self.multisig_threshold),
                );
            });
        });

        ui.add_space(14.0);

        // ── 03 / Co-Signers ──
        section_header(ui, &self.colors, "03", "Co-Signers");
        ui.add_space(6.0);

        let mut remove_index: Option<usize> = None;
        for (i, (pubkey_hex, variant)) in self.multisig_co_signers.iter_mut().enumerate() {
            egui::Frame::new()
                .fill(self.colors.surface2)
                .stroke(egui::Stroke::new(1.0, c_border))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("SIGNER {:02}", i + 1))
                                .font(label_font(9.5))
                                .color(c_accent),
                        );
                        ui.add_space(6.0);
                        let variant_combo = egui::ComboBox::from_id_salt(("ms_variant", i))
                            .selected_text(
                                egui::RichText::new(format!("{}", variant))
                                    .size(11.5)
                                    .color(c_text),
                            )
                            .width(130.0)
                            .show_ui(ui, |ui| {
                                for v in ALL_VARIANTS {
                                    let text = egui::RichText::new(format!("{}", v))
                                        .size(11.5)
                                        .color(if variant == v { c_accent } else { c_text });
                                    ui.selectable_value(variant, *v, text);
                                }
                            });
                        pin_popup_above_modal(ui, &variant_combo.response);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let remove = egui::Button::new(
                                egui::RichText::new("\u{2715}").size(11.0).color(c_danger),
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::new(1.0, c_border))
                            .corner_radius(0.0);
                            if ui.add(remove).clicked() {
                                remove_index = Some(i);
                            }
                        });
                    });
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("PUBLIC KEY / HEX")
                            .font(label_font(9.0))
                            .color(c_muted),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::TextEdit::multiline(pubkey_hex)
                            .desired_width(ui.available_width())
                            .desired_rows(2)
                            .font(egui::FontId::monospace(11.5)),
                    );
                });
            ui.add_space(6.0);
        }

        if let Some(idx) = remove_index {
            self.multisig_co_signers.remove(idx);
        }

        if ui
            .add(ghost_button(
                &self.colors,
                "+ Add Co-Signer",
                egui::vec2(ui.available_width(), 28.0),
            ))
            .clicked()
        {
            self.multisig_co_signers
                .push((String::new(), SpxVariant::Sha2128S));
        }

        ui.add_space(14.0);
        let (rule, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
        ui.painter().hline(
            rule.x_range(),
            rule.center().y,
            egui::Stroke::new(1.0, c_border),
        );
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(accent_button(
                        &self.colors,
                        "Create",
                        egui::vec2(110.0, 30.0),
                    ))
                    .clicked()
                {
                    self.multisig_modal_open = false;
                    self.create_multisig_account();
                }
                ui.add_space(6.0);
                if ui
                    .add(ghost_button(&self.colors, "Cancel", egui::vec2(90.0, 30.0)))
                    .clicked()
                {
                    self.multisig_modal_open = false;
                }
            });
        });
    }
}

const ALL_VARIANTS: &[SpxVariant] = &[
    SpxVariant::Sha2128F,
    SpxVariant::Sha2128S,
    SpxVariant::Sha2192F,
    SpxVariant::Sha2192S,
    SpxVariant::Sha2256F,
    SpxVariant::Sha2256S,
    SpxVariant::Shake128F,
    SpxVariant::Shake128S,
    SpxVariant::Shake192F,
    SpxVariant::Shake192S,
    SpxVariant::Shake256F,
    SpxVariant::Shake256S,
];
