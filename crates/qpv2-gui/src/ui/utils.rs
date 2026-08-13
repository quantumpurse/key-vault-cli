//! Shared UI helpers for the Flight Deck design language: hairline
//! panels, data rows, instrument backgrounds, and micro-animations.

use eframe::egui;
use std::time::Duration;

use crate::types::{label_font, AppColors, Status, TransactionStatus};
use crate::App;

impl App {
    pub(crate) fn compute_dao_apc(&self) -> String {
        let tip = match &self.node_status.tip_header {
            Some(h) => h,
            None => return "--".to_string(),
        };
        let prev = match &self.node_status.apc_baseline_header {
            Some(h) => h,
            None => return "--".to_string(),
        };
        match compute_apc(prev, tip) {
            Some(apc) => format!("{:.2}%", apc * 100.0),
            None => "--".to_string(),
        }
    }

    /// Instrument background for the unlocked screen: solid canvas plus
    /// a faint graph-paper grid and a very slow accent sweep band that
    /// crosses the screen — the "ambient" layer of the motion budget.
    pub(crate) fn draw_unlocked_bg(&self, ui: &mut egui::Ui) {
        draw_instrument_bg(ui, &self.colors, true);
    }

    /// Background for the Setup / Locked terminal screens: same grid,
    /// stronger sweep, plus HUD corner brackets framing the viewport.
    pub(crate) fn draw_gradient_bg(&self, ui: &mut egui::Ui, _animate: bool) {
        draw_instrument_bg(ui, &self.colors, true);
        let rect = ui.clip_rect().shrink(18.0);
        draw_frame_brackets(ui.painter(), rect, 26.0, self.colors.accent3);
    }

    /// Render the current status as a single mono log line:
    /// `[ OK ] message` / `[ERR ] message`, or a dim READY prompt.
    pub(crate) fn show_status(&self, ui: &mut egui::Ui) {
        let c = &self.colors;
        match &self.status {
            Status::None => {}
            // `horizontal_wrapped` so long messages wrap at the caller's
            // allocated width (e.g. the setup panel) instead of running past
            // it — plain `horizontal` lets labels extend unbounded.
            Status::Info(msg) => {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new("[ OK ]")
                            .font(label_font(10.0))
                            .color(c.accent2),
                    );
                    ui.label(egui::RichText::new(msg).size(12.0).color(c.text));
                });
            }
            Status::Error(msg) => {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new("[ERR ]")
                            .font(label_font(10.0))
                            .color(c.danger),
                    );
                    ui.label(egui::RichText::new(msg).size(12.0).color(c.danger));
                });
            }
        }
    }

    /// Clear a finished transaction status when navigating between tabs.
    pub(crate) fn reset_finished_tx_status(&mut self) {
        if matches!(
            self.tx_status,
            TransactionStatus::Success(_) | TransactionStatus::Error(_)
        ) {
            self.tx_status = TransactionStatus::Idle;
        }
    }

    /// TransactionStatus progression rendered as terminal log lines.
    /// `dao_screen` scopes the log to the calling screen's own flow —
    /// the status slot is shared, and a DAO transaction's progress must
    /// not read as a transfer's (or vice versa).
    pub(crate) fn draw_tx_status_log(&mut self, ui: &mut egui::Ui, dao_screen: bool) {
        let owns = self
            .active_tx_kind
            .is_some_and(|k| k.is_dao() == dao_screen);
        if matches!(self.tx_status, TransactionStatus::Idle) || !owns {
            return;
        }
        let c = &self.colors;
        ui.add_space(10.0);

        let mut copied_hash: Option<String> = None;
        match &self.tx_status {
            TransactionStatus::Idle => {}
            TransactionStatus::Building => log_line(
                ui,
                "[BUILD]",
                c.text_muted,
                "Building transaction...",
                c.text_muted,
                false,
            ),
            TransactionStatus::AwaitingSignature => log_line(
                ui,
                "[SIGN ]",
                c.accent,
                "Awaiting signature authorization...",
                c.text,
                true,
            ),
            TransactionStatus::AwaitingCoSigners {
                request,
                signatures,
                ..
            } => log_line(
                ui,
                "[SIGN ]",
                c.accent,
                &format!(
                    "Awaiting co-signers — {} of {} signatures collected.",
                    signatures.len(),
                    request.multisig_config.threshold
                ),
                c.text,
                true,
            ),
            TransactionStatus::Sending => log_line(
                ui,
                "[SEND ]",
                c.accent,
                "Broadcasting transaction...",
                c.text,
                true,
            ),
            TransactionStatus::Success(tx_hash) => {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("[ OK  ]")
                            .font(label_font(10.0))
                            .color(c.accent2),
                    );
                    ui.label(
                        egui::RichText::new("Transaction sent")
                            .size(11.5)
                            .color(c.accent2),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "0x{}…{}",
                            &tx_hash[..8],
                            &tx_hash[tx_hash.len() - 8..]
                        ))
                        .size(11.5)
                        .color(c.text_muted),
                    );
                    if ui
                        .add(ghost_button(c, "COPY", egui::vec2(50.0, 20.0)))
                        .clicked()
                    {
                        copied_hash = Some(format!("0x{}", tx_hash));
                    }
                });
            }
            TransactionStatus::Error(msg) => {
                log_line(ui, "[ ERR ]", c.danger, msg, c.danger, false)
            }
        }

        if let Some(hash) = copied_hash {
            ui.ctx().copy_text(hash);
            self.status = Status::Info("Transaction hash copied!".to_string());
        }
    }
}

/// Extract the DAO accumulated rate (AR) from a block header.
/// AR is stored as a u64 at bytes 8..16 of the `dao` field, scaled by 10^16.
pub(crate) fn extract_ar(header: &ckb_types::core::HeaderView) -> f64 {
    let dao_data = header.dao().raw_data();
    let ar = u64::from_le_bytes(dao_data[8..16].try_into().unwrap());
    ar as f64 / 1e16
}

/// Compute the annualized percentage compensation from two headers.
/// Returns `None` if the time span is too short (< 1 second).
pub(crate) fn compute_apc(
    deposit_header: &ckb_types::core::HeaderView,
    tip_header: &ckb_types::core::HeaderView,
) -> Option<f64> {
    let ar_deposit = extract_ar(deposit_header);
    let ar_tip = extract_ar(tip_header);
    if ar_deposit <= 0.0 {
        return None;
    }

    let deposit_ts = deposit_header.timestamp();
    let tip_ts = tip_header.timestamp();
    let elapsed_ms = tip_ts.saturating_sub(deposit_ts) as f64;

    const YEAR_MS: f64 = 365.25 * 24.0 * 3_600_000.0;
    // Reject if headers are identical or too close (< 1 second).
    if elapsed_ms < 1_000.0 {
        return None;
    }

    let growth = ar_tip / ar_deposit;
    let apc = growth.powf(YEAR_MS / elapsed_ms) - 1.0;
    Some(apc)
}

pub(crate) fn format_duration_ms(ms: u64, verbose: bool) -> String {
    let secs = ms / 1000;
    let mins = secs / 60;
    let hours = mins / 60;
    let days = hours / 24;

    if verbose {
        format!("{}d {}h {}m {}s", days, hours % 24, mins % 60, secs % 60)
    } else if days > 0 {
        format!("{}d {}h", days, hours % 24)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins % 60)
    } else {
        format!("{}m", mins)
    }
}

/// Split a shannon amount into a thousands-separated integer part and
/// an 8-digit fractional part ("12,480", "32000000"). Callers render
/// the fraction dimmer so full precision is visible without shouting.
pub(crate) fn ckb_split(shannons: u64) -> (String, String) {
    let int = shannons / crate::types::CKB_DECIMAL_PLACES;
    let frac = shannons % crate::types::CKB_DECIMAL_PLACES;
    (group_thousands(int), format!("{:08}", frac))
}

/// Format an integer with comma thousands separators.
pub(crate) fn group_thousands(mut n: u64) -> String {
    let mut parts = Vec::new();
    loop {
        let chunk = n % 1000;
        n /= 1000;
        if n == 0 {
            parts.push(format!("{}", chunk));
            break;
        }
        parts.push(format!("{:03}", chunk));
    }
    parts.reverse();
    parts.join(",")
}

/// Solid canvas + faint graph-paper grid + slow ambient accent sweep.
pub(crate) fn draw_instrument_bg(ui: &mut egui::Ui, colors: &AppColors, sweep: bool) {
    let rect = ui.clip_rect();
    let painter = ui.painter();

    painter.rect_filled(rect, 0.0, colors.bg);

    // Graph-paper grid: 1px hairlines every 48px, barely above the bg.
    let grid = egui::Color32::from_rgba_unmultiplied(100, 125, 135, 9);
    let spacing = 48.0;
    let mut gx = rect.left() + spacing;
    while gx < rect.right() {
        painter.vline(gx, rect.y_range(), egui::Stroke::new(1.0, grid));
        gx += spacing;
    }
    let mut gy = rect.top() + spacing;
    while gy < rect.bottom() {
        painter.hline(rect.x_range(), gy, egui::Stroke::new(1.0, grid));
        gy += spacing;
    }

    // Ambient sweep: a soft vertical band of accent drifting across the
    // canvas once every ~16 seconds. Trailing gradient, sharp leading
    // edge — like a radar refresh.
    if sweep {
        let t = ui.input(|i| i.time) as f32;
        let period = 16.0;
        let phase = (t % period) / period;
        let band_w = rect.width() * 0.22;
        let head_x = rect.left() + phase * (rect.width() + band_w);

        let mut mesh = egui::Mesh::default();
        let a = colors.accent;
        let head = egui::Color32::from_rgba_unmultiplied(a.r(), a.g(), a.b(), 7);
        let tail = egui::Color32::TRANSPARENT;
        let x0 = head_x - band_w;
        let x1 = head_x;
        mesh.colored_vertex(egui::pos2(x0, rect.top()), tail);
        mesh.colored_vertex(egui::pos2(x1, rect.top()), head);
        mesh.colored_vertex(egui::pos2(x1, rect.bottom()), head);
        mesh.colored_vertex(egui::pos2(x0, rect.bottom()), tail);
        mesh.add_triangle(0, 1, 2);
        mesh.add_triangle(0, 2, 3);
        painter.add(egui::Shape::mesh(mesh));

        // ~20fps is plenty for a slow ambient drift and far cheaper
        // than a per-frame repaint.
        ui.ctx().request_repaint_after(Duration::from_millis(50));
    }
}

/// HUD-style corner brackets framing `rect`.
pub(crate) fn draw_frame_brackets(
    painter: &egui::Painter,
    rect: egui::Rect,
    arm: f32,
    color: egui::Color32,
) {
    let s = egui::Stroke::new(1.0, color);
    let r = rect;
    // Top-left.
    painter.line_segment([r.left_top(), r.left_top() + egui::vec2(arm, 0.0)], s);
    painter.line_segment([r.left_top(), r.left_top() + egui::vec2(0.0, arm)], s);
    // Top-right.
    painter.line_segment([r.right_top(), r.right_top() + egui::vec2(-arm, 0.0)], s);
    painter.line_segment([r.right_top(), r.right_top() + egui::vec2(0.0, arm)], s);
    // Bottom-left.
    painter.line_segment([r.left_bottom(), r.left_bottom() + egui::vec2(arm, 0.0)], s);
    painter.line_segment(
        [r.left_bottom(), r.left_bottom() + egui::vec2(0.0, -arm)],
        s,
    );
    // Bottom-right.
    painter.line_segment(
        [r.right_bottom(), r.right_bottom() + egui::vec2(-arm, 0.0)],
        s,
    );
    painter.line_segment(
        [r.right_bottom(), r.right_bottom() + egui::vec2(0.0, -arm)],
        s,
    );
}

/// The standard panel frame: surface fill, 1px hairline, sharp
/// corners, 14px padding. Every content block sits in one of these.
pub(crate) fn panel_frame(colors: &AppColors) -> egui::Frame {
    egui::Frame::new()
        .fill(colors.surface)
        .stroke(egui::Stroke::new(1.0, colors.border))
        .inner_margin(14.0)
}

/// Pin a [`egui::ComboBox`]'s option list above the modal panel it was
/// opened from.
///
/// Fixing https://github.com/quantumpurse/quantum-purse-v2/issues/7
///
/// Reopening a modal lifts its panel above the layer the popup left
/// behind in an earlier session, and a click whose press and release land
/// in the same pass — a trackpad tap — leaves it there, so the list opens
/// behind the opaque panel. The sublayer re-pins it above the panel every
/// pass. Both layers must sit at `Order::Foreground`, which is where egui
/// puts ComboBox popups.
pub(crate) fn pin_popup_above_modal(ui: &egui::Ui, combo: &egui::Response) {
    ui.ctx().set_sublayer(
        ui.layer_id(),
        egui::LayerId::new(
            egui::Order::Foreground,
            egui::Popup::default_response_id(combo),
        ),
    );
}

/// Sequential section codes ("01", "02", ...) handed out in render
/// order, so a conditionally skipped section never leaves a gap in a
/// screen's numbering.
#[derive(Default)]
pub(crate) struct SectionCounter(u8);

impl SectionCounter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The next two-digit section code.
    pub(crate) fn next_code(&mut self) -> String {
        self.0 += 1;
        format!("{:02}", self.0)
    }
}

/// Section header: `CODE // TITLE` in tiny uppercase label type with a
/// hairline rule filling the remaining width.
pub(crate) fn section_header(ui: &mut egui::Ui, colors: &AppColors, code: &str, title: &str) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(code)
                .font(label_font(10.0))
                .color(colors.accent),
        );
        ui.label(
            egui::RichText::new(title.to_uppercase())
                .font(label_font(10.0))
                .color(colors.text_muted),
        );
        let remaining = ui.available_width();
        if remaining > 8.0 {
            let (rule, _) =
                ui.allocate_exact_size(egui::vec2(remaining, 10.0), egui::Sense::hover());
            ui.painter().hline(
                egui::Rangef::new(rule.left() + 6.0, rule.right()),
                rule.center().y,
                egui::Stroke::new(1.0, colors.border),
            );
        }
    });
}

/// Label-left / value-right row inside a panel. Label renders in tiny
/// uppercase, value in body mono.
pub(crate) fn data_row(ui: &mut egui::Ui, colors: &AppColors, label: &str, value: &str) {
    data_row_colored(ui, colors, label, value, colors.text);
}

pub(crate) fn data_row_colored(
    ui: &mut egui::Ui,
    colors: &AppColors,
    label: &str,
    value: &str,
    value_color: egui::Color32,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(label.to_uppercase())
                .font(label_font(9.5))
                .color(colors.text_muted),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).size(12.5).color(value_color));
        });
    });
}

/// Checkbox marking a mnemonic import as coming from the Quantum Purse
/// v1 web wallet, which used a different single-sig address format.
/// Shared by the setup screen and the import modal so the two entry
/// points can never drift apart.
pub(crate) fn v1_import_checkbox(ui: &mut egui::Ui, colors: &AppColors, checked: &mut bool) {
    let w = colors.warn;
    let (fill, stroke, label) = if *checked {
        (
            colors.warn_tint,
            egui::Color32::from_rgba_unmultiplied(w.r(), w.g(), w.b(), 90),
            colors.warn,
        )
    } else {
        (egui::Color32::TRANSPARENT, colors.border, colors.text)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke))
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if *checked {
                // Tint the checkmark to match; egui draws it with the
                // interact-state fg_stroke.
                let v = ui.visuals_mut();
                v.widgets.inactive.fg_stroke.color = w;
                v.widgets.hovered.fg_stroke.color = w;
                v.widgets.active.fg_stroke.color = w;
            }
            ui.checkbox(
                checked,
                egui::RichText::new("User comes from the Quantum Purse v1 web wallet.")
                    .size(12.0)
                    .color(label),
            );
        });
}

/// Tiny uppercase badge in a tinted, hairline-stroked box.
pub(crate) fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    let tint = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 24);
    egui::Frame::new()
        .fill(tint)
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 90),
        ))
        .inner_margin(egui::Margin::symmetric(5, 2))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text.to_uppercase())
                    .font(label_font(8.5))
                    .color(color),
            );
        });
}

/// Primary action button: solid accent fill, near-black uppercase
/// label, sharp corners.
pub(crate) fn accent_button(
    colors: &AppColors,
    text: &str,
    size: egui::Vec2,
) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text.to_uppercase())
            .font(label_font(11.0))
            .color(colors.bg),
    )
    .fill(colors.accent)
    .stroke(egui::Stroke::NONE)
    .corner_radius(0.0)
    .min_size(size)
}

/// Secondary action button: transparent fill, hairline border, accent
/// uppercase label.
pub(crate) fn ghost_button(
    colors: &AppColors,
    text: &str,
    size: egui::Vec2,
) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text.to_uppercase())
            .font(label_font(11.0))
            .color(colors.accent),
    )
    .fill(egui::Color32::TRANSPARENT)
    .stroke(egui::Stroke::new(1.0, colors.border2))
    .corner_radius(0.0)
    .min_size(size)
}

/// Breathing status dot: alpha oscillates slowly around full strength.
/// Pass `urgent` to double the breathing rate (e.g. offline/red).
pub(crate) fn breathing_dot(
    painter: &egui::Painter,
    center: egui::Pos2,
    color: egui::Color32,
    t: f32,
    urgent: bool,
) {
    let rate = if urgent { 4.0 } else { 1.6 };
    let breath = 0.55 + 0.45 * (t * rate).sin();
    let alpha = (255.0 * (0.35 + 0.65 * breath)) as u8;
    let c = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha);
    painter.circle_filled(center, 3.0, c);
    // Faint halo.
    let halo = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha / 5);
    painter.circle_filled(center, 5.5, halo);
}

/// Blinking block cursor (1.2Hz square wave), the terminal idiom used
/// beside active titles and prompts.
pub(crate) fn blinking_cursor(
    painter: &egui::Painter,
    left_center: egui::Pos2,
    height: f32,
    color: egui::Color32,
    t: f32,
) {
    if (t * 1.2).fract() < 0.55 {
        let rect = egui::Rect::from_min_size(
            egui::pos2(left_center.x, left_center.y - height / 2.0),
            egui::vec2(height * 0.55, height),
        );
        painter.rect_filled(rect, 0.0, color);
    }
}

/// Bloomberg-style change flash: remembers `value` under `id` and
/// returns a 0..=1 intensity for ~0.9s after it changes. Callers paint
/// an accent overlay scaled by the returned intensity.
pub(crate) fn value_flash(ui: &egui::Ui, id: egui::Id, value: u64) -> f32 {
    #[derive(Clone, Copy)]
    struct Seen {
        value: u64,
        at: f64,
    }
    let now = ui.input(|i| i.time);
    let seen = ui.ctx().memory_mut(|m| {
        let entry = m.data.get_temp::<Seen>(id);
        match entry {
            None => {
                // First observation: register without flashing.
                m.data.insert_temp(
                    id,
                    Seen {
                        value,
                        at: f64::MIN,
                    },
                );
                Seen {
                    value,
                    at: f64::MIN,
                }
            }
            Some(s) if s.value != value => {
                let s = Seen { value, at: now };
                m.data.insert_temp(id, s);
                s
            }
            Some(s) => s,
        }
    });
    let elapsed = (now - seen.at) as f32;
    let intensity = (1.0 - elapsed / 0.9).clamp(0.0, 1.0);
    if intensity > 0.0 {
        ui.ctx().request_repaint();
    }
    intensity
}

/// Paint a left-edge accent tick + tint over `rect` when a row is
/// hovered — the standard row hover treatment.
pub(crate) fn row_hover(painter: &egui::Painter, rect: egui::Rect, colors: &AppColors) {
    painter.rect_filled(rect, 0.0, colors.accent_tint);
    painter.rect_filled(
        egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height())),
        0.0,
        colors.accent,
    );
}

/// Linearly interpolates between two RGBA colours at fraction `t`
/// (clamped to `[0, 1]`). Used by the node-manager sync-bar gradient.
pub(crate) fn lerp_color(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 * (1.0 - t) + y as f32 * t).round() as u8;
    egui::Color32::from_rgba_unmultiplied(
        mix(a.r(), b.r()),
        mix(a.g(), b.g()),
        mix(a.b(), b.b()),
        mix(a.a(), b.a()),
    )
}

/// One terminal log line: `[TAG ] message`, with an optional breathing
/// dot for in-flight states.
fn log_line(
    ui: &mut egui::Ui,
    tag: &str,
    tag_color: egui::Color32,
    msg: &str,
    msg_color: egui::Color32,
    live: bool,
) {
    // Top-aligned so the tag hugs the first line when a long message
    // (e.g. a node rejection) wraps onto several lines.
    ui.horizontal_top(|ui| {
        ui.label(
            egui::RichText::new(tag)
                .font(label_font(10.0))
                .color(tag_color),
        );
        if live {
            let t = ui.input(|i| i.time) as f32;
            let (r, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
            breathing_dot(ui.painter(), r.center(), tag_color, t, false);
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(50));
        }
        // Wrap instead of running off-screen: the user must be able to
        // read the entire error.
        ui.add(egui::Label::new(egui::RichText::new(msg).size(11.5).color(msg_color)).wrap());
    });
}

/// A compact trend chart: a single gradient area line coloured by its
/// net trend — green when the series rises over its window, red when
/// it falls, cyan when flat — so the chart itself answers "which way is
/// this going?" before a number is read. A headline callout states the
/// change (signed CKB delta, percent, and the window's start date) and a
/// clean endpoint dot marks the latest value. No axes, gridlines, or
/// per-point markers; the trend and the one callout sentence carry the
/// whole story. Shared by the dashboard's balance history and the
/// Networks screen's QR-adoption (TVL) chart.
pub(crate) fn draw_trend_chart(
    ui: &mut egui::Ui,
    colors: &AppColors,
    series: &[(u64, u64)],
    height: f32,
    placeholder: &str,
    hover: &str,
) {
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    resp.on_hover_text(hover);

    if series.len() < 2 {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            placeholder,
            label_font(8.5),
            colors.text_muted,
        );
        return;
    }

    let t = ui.input(|i| i.time) as f32;
    let painter = ui.painter();

    // The callout claims a header band; the trace takes the rest. The
    // right inset reserves room for the endpoint dot's halo so it never
    // clips the panel edge.
    let callout_h = 18.0;
    let plot = egui::Rect::from_min_max(
        egui::pos2(rect.left() + 1.0, rect.top() + callout_h + 2.0),
        egui::pos2(rect.right() - 8.0, rect.bottom() - 3.0),
    );

    // ── Geometry. Fractions clamp so a point beyond the series' own range
    // (e.g. a block timestamp ahead of the clock) pins to the plot edge. ──
    let (t0, _) = series[0];
    let (t1, _) = series[series.len() - 1];
    let t_span = (t1.saturating_sub(t0)).max(1) as f32;
    let v_min = series.iter().map(|&(_, v)| v).min().unwrap_or(0);
    let v_max = series.iter().map(|&(_, v)| v).max().unwrap_or(1);
    let pad = ((v_max - v_min) / 10).max(v_max / 100).max(1);
    let lo = v_min.saturating_sub(pad) as f64;
    let hi = (v_max + pad) as f64;
    let to_pos = |&(t, v): &(u64, u64)| {
        let fx = ((t.saturating_sub(t0)) as f32 / t_span).clamp(0.0, 1.0);
        let fy = (((v as f64 - lo) / (hi - lo)) as f32).clamp(0.0, 1.0);
        egui::pos2(
            plot.left() + fx * plot.width(),
            plot.bottom() - fy * plot.height(),
        )
    };
    let points: Vec<egui::Pos2> = series.iter().map(to_pos).collect();
    let last_point = *points.last().expect("series.len() >= 2 checked above");

    // ── Net trend over the window picks the card's colour and sign. ──
    let first_v = series[0].1;
    let curr_v = series[series.len() - 1].1;
    let (dir, sign, up) = match curr_v.cmp(&first_v) {
        std::cmp::Ordering::Greater => (colors.accent2, "+", true),
        std::cmp::Ordering::Less => (colors.danger, "\u{2212}", false),
        std::cmp::Ordering::Equal => (colors.accent, "", true),
    };
    let delta = curr_v.abs_diff(first_v);
    let tint = |alpha: u8| egui::Color32::from_rgba_unmultiplied(dir.r(), dir.g(), dir.b(), alpha);

    // ── Area fill: a vertical gradient in the trend colour, brighter at
    // the trace and fading to nothing at the baseline. ──
    let fill_top = tint(44);
    let fill_bot = egui::Color32::TRANSPARENT;
    let mut mesh = egui::Mesh::default();
    for pair in points.windows(2) {
        let i = mesh.vertices.len() as u32;
        mesh.colored_vertex(pair[0], fill_top);
        mesh.colored_vertex(pair[1], fill_top);
        mesh.colored_vertex(egui::pos2(pair[1].x, plot.bottom()), fill_bot);
        mesh.colored_vertex(egui::pos2(pair[0].x, plot.bottom()), fill_bot);
        mesh.add_triangle(i, i + 1, i + 2);
        mesh.add_triangle(i, i + 2, i + 3);
    }
    painter.add(egui::Shape::mesh(mesh));
    // Baseline hairline grounds the fill.
    painter.hline(
        plot.x_range(),
        plot.bottom(),
        egui::Stroke::new(1.0, colors.border),
    );

    // ── Trace: a soft bloom beneath a crisp stroke. ──
    painter.add(egui::Shape::line(
        points.clone(),
        egui::Stroke::new(4.0, tint(22)),
    ));
    painter.add(egui::Shape::line(points, egui::Stroke::new(1.0, dir)));

    // ── Endpoint: a clean dot with a gently breathing halo at "now". ──
    let breath = 0.6 + 0.4 * (t * 1.4).sin();
    painter.circle_filled(last_point, 6.5, tint((70.0 * breath / 3.0) as u8));
    painter.circle_filled(last_point, 3.0, dir);
    ui.ctx().request_repaint_after(Duration::from_millis(50));

    // ── Callout: a painted ▲/▼ (font-independent), the signed CKB delta
    // and percent in the trend colour, then "SINCE <date>" — one
    // self-contained sentence telling the whole change story. ──
    let start_label = chrono::DateTime::from_timestamp(t0 as i64, 0)
        .map(|d| d.format("%b %d").to_string().to_uppercase())
        .unwrap_or_default();
    let ccy = rect.top() + callout_h / 2.0;
    let mut x = rect.left() + 1.0;
    if curr_v != first_v {
        let tri = if up {
            vec![
                egui::pos2(x + 4.0, ccy - 4.0),
                egui::pos2(x, ccy + 3.0),
                egui::pos2(x + 8.0, ccy + 3.0),
            ]
        } else {
            vec![
                egui::pos2(x + 4.0, ccy + 4.0),
                egui::pos2(x, ccy - 3.0),
                egui::pos2(x + 8.0, ccy - 3.0),
            ]
        };
        painter.add(egui::Shape::convex_polygon(tri, dir, egui::Stroke::NONE));
        x += 13.0;
    }
    let (d_int, d_frac) = ckb_split(delta);
    let r = painter.text(
        egui::pos2(x, ccy),
        egui::Align2::LEFT_CENTER,
        format!("{}{}.{} CKB", sign, d_int, &d_frac[..1]),
        label_font(10.5),
        dir,
    );
    x = r.right() + 10.0;
    // Percent, when the baseline is non-zero and the figure stays sane.
    if first_v > 0 {
        let pct = delta as f64 / first_v as f64 * 100.0;
        if pct < 1000.0 {
            let r = painter.text(
                egui::pos2(x, ccy),
                egui::Align2::LEFT_CENTER,
                format!("{}{:.1}%", sign, pct),
                label_font(10.5),
                dir.gamma_multiply(0.85),
            );
            x = r.right() + 10.0;
        }
    }
    // "SINCE <date>" only when it fits — at the minimum chart width the
    // delta and percent take priority over the date.
    let since = format!("SINCE {}", start_label);
    let since_w = painter
        .layout_no_wrap(since.clone(), label_font(8.5), colors.text_muted)
        .size()
        .x;
    if x + since_w <= rect.right() {
        painter.text(
            egui::pos2(x, ccy),
            egui::Align2::LEFT_CENTER,
            since,
            label_font(8.5),
            colors.text_muted,
        );
    }
}
