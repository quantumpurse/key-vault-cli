//! Centered modal for Create Wallet / Import Wallet flows, in the
//! Flight Deck idiom: sharp hairline-framed surface, indexed sections.
//! Seed phrase entry/reveal happens in the external pinentry prompt,
//! so the modal only collects name, parameter set, and auth method.

use eframe::egui;
use qpv2_core::types::{SingleSigConvention, SpxVariant};

use crate::types::{label_font, WalletModal};
use crate::ui::utils::{
    ghost_button, pin_popup_above_modal, section_header, v1_import_checkbox, SectionCounter,
};
use crate::App;

const MODAL_W: f32 = 440.0;

impl App {
    pub(crate) fn show_wallet_modal(&mut self, ctx: &egui::Context) {
        if self.wallet_modal == WalletModal::None {
            return;
        }

        let is_import = self.wallet_modal == WalletModal::Import;

        // Semi-transparent backdrop that consumes clicks.
        let screen_rect = ctx.input(|i| i.viewport_rect());
        let backdrop_clicked = egui::Area::new(egui::Id::new("wallet_modal_backdrop"))
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
            screen_rect.height() * 0.18,
        );

        egui::Area::new(egui::Id::new("wallet_modal_area"))
            .fixed_pos(modal_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(self.colors.surface)
                    .stroke(egui::Stroke::new(1.0, self.colors.border2))
                    .inner_margin(egui::Margin::symmetric(20, 18))
                    .show(ui, |ui| {
                        ui.set_width(MODAL_W);
                        self.wallet_modal_contents(ui, is_import);
                    });
            });

        if backdrop_clicked {
            self.wallet_modal = WalletModal::None;
            self.new_wallet_name.clear();
            self.import_from_v1 = false;
        }
    }

    fn wallet_modal_contents(&mut self, ui: &mut egui::Ui, is_import: bool) {
        let c_accent = self.colors.accent;
        let c_muted = self.colors.text_muted;
        let c_border = self.colors.border;

        // ── Title row + hairline ──
        let (code, subtitle) = if is_import {
            ("RESTORE VAULT", "// IMPORT SEED")
        } else {
            ("NEW VAULT", "// INITIALIZE")
        };
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(code)
                    .font(label_font(11.0))
                    .color(c_accent),
            );
            ui.label(
                egui::RichText::new(subtitle)
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

        // Sections are numbered in render order because Source only
        // appears on import; fixed codes would gap on the create flow.
        let mut sec = SectionCounter::new();

        // ── Name ──
        section_header(ui, &self.colors, &sec.next_code(), "Name");
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(self.colors.surface2)
            .stroke(egui::Stroke::new(1.0, c_border))
            .inner_margin(egui::Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_wallet_name)
                        .hint_text("auto-generated if empty")
                        .desired_width(ui.available_width())
                        .font(egui::FontId::monospace(12.5))
                        .frame(egui::Frame::NONE),
                );
            });

        ui.add_space(14.0);

        // ── Parameter Set ──
        section_header(ui, &self.colors, &sec.next_code(), "Parameter Set");
        ui.add_space(6.0);
        let variant_combo = egui::ComboBox::from_id_salt("wallet_modal_variant")
            .selected_text(
                egui::RichText::new(format!("SPHINCS+ {}", self.new_wallet_variant))
                    .size(12.0)
                    .color(c_accent),
            )
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                for variant in &[
                    SpxVariant::Sha2128S,
                    SpxVariant::Sha2128F,
                    SpxVariant::Shake128S,
                    SpxVariant::Shake128F,
                    SpxVariant::Sha2192S,
                    SpxVariant::Sha2192F,
                    SpxVariant::Shake192S,
                    SpxVariant::Shake192F,
                    SpxVariant::Sha2256S,
                    SpxVariant::Sha2256F,
                    SpxVariant::Shake256S,
                    SpxVariant::Shake256F,
                ] {
                    let selected = self.new_wallet_variant == *variant;
                    let text = egui::RichText::new(format!("{}", variant))
                        .size(12.0)
                        .color(if selected { c_accent } else { self.colors.text });
                    ui.selectable_value(&mut self.new_wallet_variant, *variant, text);
                }
            });
        pin_popup_above_modal(ui, &variant_combo.response);

        ui.add_space(14.0);

        // ── Source (import only) ──
        // v1 web-wallet mnemonics derive the same keys but need the v1
        // single-sig address convention for existing funds to stay visible.
        if is_import {
            section_header(ui, &self.colors, &sec.next_code(), "Source");
            ui.add_space(6.0);
            v1_import_checkbox(ui, &self.colors, &mut self.import_from_v1);
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("v1 used a different address format. Check this so the funds on your v1 addresses stay visible.")
                    .size(10.0)
                    .color(c_muted),
            );
            ui.add_space(14.0);
        }

        // ── Authentication ──
        section_header(ui, &self.colors, &sec.next_code(), "Authentication");
        ui.add_space(8.0);

        let verb = if is_import { "Import" } else { "Create" };
        let full_w = ui.available_width();
        let btn_size = egui::vec2(full_w, 34.0);

        let single_sig_convention = SingleSigConvention::new(self.import_from_v1);

        let kc_label = format!("{} // {}", verb, keychain::short_name());
        if ui
            .add(ghost_button(&self.colors, &kc_label, btn_size))
            .clicked()
        {
            let v = self.new_wallet_variant;
            if is_import {
                self.import_seed_phrase_with_keychain(v, single_sig_convention);
            } else {
                self.create_wallet_with_keychain(v);
            }
            self.wallet_modal = WalletModal::None;
            self.import_from_v1 = false;
        }

        ui.add_space(6.0);
        let fido_label = format!("{} // Security Key", verb);
        if ui
            .add(ghost_button(&self.colors, &fido_label, btn_size))
            .clicked()
        {
            let v = self.new_wallet_variant;
            if is_import {
                self.import_seed_phrase_with_fido2(v, single_sig_convention);
            } else {
                self.create_wallet_with_fido2(v);
            }
            self.wallet_modal = WalletModal::None;
            self.import_from_v1 = false;
        }

        ui.add_space(6.0);
        let pw_label = format!("{} // Password", verb);
        if ui
            .add(ghost_button(&self.colors, &pw_label, btn_size))
            .clicked()
        {
            let v = self.new_wallet_variant;
            if is_import {
                self.import_seed_phrase_with_password(v, single_sig_convention);
            } else {
                self.create_wallet_with_password(v);
            }
            self.wallet_modal = WalletModal::None;
            self.import_from_v1 = false;
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

        if ui
            .add(ghost_button(&self.colors, "Cancel", btn_size))
            .clicked()
        {
            self.wallet_modal = WalletModal::None;
            self.new_wallet_name.clear();
            self.import_from_v1 = false;
        }
    }
}
