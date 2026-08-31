//! Co-signer coordination UI for multisig transactions.
//!
//! Rendered when `TransactionStatus::AwaitingCoSigners` is active.
//! Also provides a "Sign a Request" flow for the receiving co-signer.

use eframe::egui;

use crate::types::{label_font, AppColors, TransactionStatus};
use crate::ui::utils::{ghost_button, panel_frame, section_header, SectionCounter};
use crate::App;

/// Section header with a step pointer: the active step's title renders
/// bright with a pulsing green triangle pointing at it — green for
/// "proceed here", and for contrast against the cyan step codes.
/// Completed steps get a static green checkmark instead. Deliberately
/// NOT the blinking block cursor — that idiom is taken by the module
/// rail and the READY prompt.
fn step_header(
    ui: &mut egui::Ui,
    colors: &AppColors,
    code: &str,
    title: &str,
    active: bool,
    completed: bool,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(code)
                .font(label_font(10.0))
                .color(colors.accent),
        );
        ui.label(
            egui::RichText::new(title.to_uppercase())
                .font(label_font(10.0))
                .color(if active {
                    colors.text
                } else {
                    colors.text_muted
                }),
        );
        if active {
            let t = ui.input(|i| i.time) as f32;
            let breath = 0.45 + 0.55 * (t * 1.6).sin().abs();
            let a = colors.accent2;
            let color =
                egui::Color32::from_rgba_unmultiplied(a.r(), a.g(), a.b(), (255.0 * breath) as u8);
            let (r, _) = ui.allocate_exact_size(egui::vec2(14.0, 12.0), egui::Sense::hover());
            let cy = r.center().y;
            ui.painter().add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(r.left() + 2.0, cy),
                    egui::pos2(r.left() + 11.0, cy - 4.5),
                    egui::pos2(r.left() + 11.0, cy + 4.5),
                ],
                color,
                egui::Stroke::NONE,
            ));
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(50));
        } else if completed {
            // Static green checkmark: this step is behind you.
            let (r, _) = ui.allocate_exact_size(egui::vec2(14.0, 12.0), egui::Sense::hover());
            let cy = r.center().y;
            let stroke = egui::Stroke::new(1.6, colors.accent2);
            ui.painter().line_segment(
                [
                    egui::pos2(r.left() + 2.0, cy + 0.5),
                    egui::pos2(r.left() + 5.5, cy + 4.0),
                ],
                stroke,
            );
            ui.painter().line_segment(
                [
                    egui::pos2(r.left() + 5.5, cy + 4.0),
                    egui::pos2(r.left() + 12.0, cy - 4.0),
                ],
                stroke,
            );
        }
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

/// Wraps one step's controls: when the step isn't the live one, the
/// whole zone is disabled and sunk to low opacity — reads as a
/// powered-down panel section rather than egui's default grey tint.
fn step_zone(ui: &mut egui::Ui, open: bool, add: impl FnOnce(&mut egui::Ui)) {
    ui.add_enabled_ui(open, |ui| {
        if !open {
            ui.set_opacity(0.35);
        }
        add(ui);
    });
}

/// Hairline-framed container for JSON paste/copy text areas.
fn json_frame(colors: &AppColors) -> egui::Frame {
    egui::Frame::new()
        .fill(colors.surface2)
        .stroke(egui::Stroke::new(1.0, colors.border))
        .inner_margin(8.0)
}

/// Tiny uppercase label above a wrapped mono value — used for long
/// addresses that don't fit a label/value row.
fn detail_field(ui: &mut egui::Ui, colors: &AppColors, label: &str, value: &str) {
    ui.label(
        egui::RichText::new(label)
            .font(label_font(9.0))
            .color(colors.text_muted),
    );
    ui.label(egui::RichText::new(value).size(11.0).color(colors.text));
    ui.add_space(6.0);
}

impl App {
    /// Render the co-signer coordination panel (initiator side).
    /// Shows the signing request, collected signatures, import field, and submit button.
    pub(crate) fn show_cosigner_panel(&mut self, ui: &mut egui::Ui) {
        let (kind, request, sig_count, threshold, step1_done) = match &self.tx_status {
            TransactionStatus::AwaitingCoSigners {
                kind,
                request,
                signatures,
                step1_done,
                ..
            } => (
                *kind,
                // `request` is `&Box<SigningRequest>`; clone the inner value
                // so the local stays a plain `SigningRequest`.
                request.as_ref().clone(),
                signatures.len(),
                request.multisig_config.threshold as usize,
                *step1_done,
            ),
            _ => return,
        };

        // Once the threshold is met there's nothing left to point at —
        // the submit row takes over.
        let step2_done = sig_count >= threshold;

        let step1_open = !step1_done && !step2_done;
        let step2_open = step1_done && !step2_done;

        ui.add_space(16.0);
        panel_frame(&self.colors).show(ui, |ui| {
            // What is being co-signed — without this, a paused DAO
            // deposit and a withdrawal look identical mid-flight.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("OPERATION")
                        .font(label_font(9.5))
                        .color(self.colors.text_muted),
                );
                ui.label(
                    egui::RichText::new(kind.label())
                        .font(label_font(11.0))
                        .color(self.colors.accent),
                );
            });
            ui.add_space(10.0);

            // ── Export side: hand the request to each co-signer ──
            step_header(
                ui,
                &self.colors,
                "01",
                "Signing Request",
                step1_open,
                step1_done || step2_done,
            );
            ui.add_space(8.0);

            // Label + count side by side (not the data_row label/value
            // split — the count belongs visually to its label).
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("SIGNATURES")
                        .font(label_font(9.5))
                        .color(self.colors.text_muted),
                );
                ui.label(
                    egui::RichText::new(format!("{} / {}", sig_count, threshold))
                        .size(12.5)
                        .color(if sig_count >= threshold {
                            self.colors.accent2
                        } else {
                            self.colors.text
                        }),
                );
            });
            ui.add_space(8.0);

            let mut copy_clicked = false;
            step_zone(ui, step1_open, |ui| {
                copy_clicked = ui
                    .add(ghost_button(
                        &self.colors,
                        "Copy Signing Request",
                        egui::vec2(190.0, 26.0),
                    ))
                    .clicked();
            });
            if copy_clicked {
                if let Ok(json) = serde_json::to_string_pretty(&request) {
                    ui.ctx().copy_text(json);
                    if let TransactionStatus::AwaitingCoSigners { step1_done, .. } =
                        &mut self.tx_status
                    {
                        *step1_done = true;
                    }
                    self.status = crate::types::Status::Info("Signing request copied!".to_string());
                }
            }

            ui.add_space(14.0);

            // ── Import side: collect each co-signer's response ──
            step_header(ui, &self.colors, "02", "Response", step2_open, step2_done);
            ui.add_space(8.0);

            // The hint must track the flow: after the last import the
            // buffer is cleared, and a bare "paste here" would read as
            // "you still owe a response".
            let hint = if step2_done {
                "All required signatures imported."
            } else if step2_open {
                "Paste signing response JSON here..."
            } else {
                "Copy the signing request first."
            };
            let mut import_clicked = false;
            step_zone(ui, step2_open, |ui| {
                if let TransactionStatus::AwaitingCoSigners {
                    ref mut import_response_json,
                    ..
                } = self.tx_status
                {
                    json_frame(&self.colors).show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(import_response_json)
                                .hint_text(hint)
                                .desired_width(ui.available_width())
                                .desired_rows(3)
                                .frame(egui::Frame::NONE)
                                .font(egui::FontId::monospace(11.0)),
                        );
                    });
                }

                ui.add_space(6.0);
                import_clicked = ui
                    .add(ghost_button(
                        &self.colors,
                        "Import Response",
                        egui::vec2(160.0, 26.0),
                    ))
                    .clicked();
            });
            if import_clicked {
                self.import_cosigner_response();
            }

            ui.add_space(12.0);

            // Re-read current signature count (may have changed after import).
            let (current_sig_count, current_threshold) = match &self.tx_status {
                TransactionStatus::AwaitingCoSigners {
                    request,
                    signatures,
                    ..
                } => (signatures.len(), request.multisig_config.threshold as usize),
                _ => return,
            };

            // ── Final step: broadcast once the threshold is met ──
            let can_submit = current_sig_count >= current_threshold;
            step_header(ui, &self.colors, "03", "Submit", can_submit, false);
            ui.add_space(8.0);

            // Submit stays a ghost: the transfer ticket's EXECUTE
            // button is the screen's single solid-accent action.
            let submit_label = if can_submit {
                "Submit Transaction".to_string()
            } else {
                format!(
                    "Awaiting Signatures ({}/{})",
                    current_sig_count, current_threshold
                )
            };
            let submit_btn = ghost_button(
                &self.colors,
                &submit_label,
                egui::vec2(ui.available_width(), 36.0),
            );
            if ui.add_enabled(can_submit, submit_btn).clicked() {
                self.submit_multisig_transaction();
            }

            ui.add_space(6.0);
            if ui
                .add(ghost_button(&self.colors, "Cancel", egui::vec2(80.0, 24.0)))
                .clicked()
            {
                self.tx_status = TransactionStatus::Idle;
            }
        });
    }

    /// Parse and validate the import buffer as a `SigningResponse`, then add
    /// the signature to the collected set.
    fn import_cosigner_response(&mut self) {
        tracing::info!("Import cosigner response triggered.");

        let (request_msg, n_signers, signatures, import_response_json) = match &mut self.tx_status {
            TransactionStatus::AwaitingCoSigners {
                request,
                signatures,
                import_response_json,
                ..
            } => (
                request.signing_message.clone(),
                request.multisig_config.signers.len(),
                signatures,
                import_response_json,
            ),
            _ => {
                tracing::error!("import_cosigner_response: not in AwaitingCoSigners state.");
                return;
            }
        };

        let buf = import_response_json.trim().to_string();
        tracing::info!("Import buffer length: {} chars.", buf.len());
        if buf.is_empty() {
            self.status = crate::types::Status::Error("Paste a response first.".to_string());
            return;
        }

        let response: qpv2_core::types::SigningResponse = match serde_json::from_str(&buf) {
            Ok(r) => r,
            Err(e) => {
                self.status = crate::types::Status::Error(format!("Invalid response JSON: {}", e));
                return;
            }
        };

        if response.signing_message != request_msg {
            self.status =
                crate::types::Status::Error("Response signing message does not match.".to_string());
            return;
        }

        if response.signer_index >= n_signers {
            self.status = crate::types::Status::Error(format!(
                "Signer index {} out of range (N={}).",
                response.signer_index, n_signers
            ));
            return;
        }

        if signatures
            .iter()
            .any(|(idx, _)| *idx == response.signer_index)
        {
            self.status = crate::types::Status::Error(format!(
                "Signer {} already provided a signature.",
                response.signer_index
            ));
            return;
        }

        let sig_bytes = match hex::decode(&response.signature) {
            Ok(b) => b,
            Err(e) => {
                self.status = crate::types::Status::Error(format!("Invalid signature hex: {}", e));
                return;
            }
        };

        signatures.push((response.signer_index, sig_bytes));
        import_response_json.clear();
        self.status = crate::types::Status::Info(format!(
            "Signature from signer {} imported.",
            response.signer_index
        ));
    }

    /// Co-signer signing flow: paste a signing request, verify details,
    /// sign with a local key, and copy the response.
    ///
    /// Renders exactly one panel — the response replaces the request
    /// form — so it draws one code from the screen's shared counter.
    pub(crate) fn show_sign_request_ui(&mut self, ui: &mut egui::Ui, sec: &mut SectionCounter) {
        ui.add_space(16.0);
        let code = sec.next_code();

        // ── Completed response: copy-back panel ──
        if let Some(response_copy) = self.cosign_response_json.clone() {
            panel_frame(&self.colors).show(ui, |ui| {
                section_header(ui, &self.colors, &code, "Response");
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("[ OK  ]")
                            .font(label_font(10.0))
                            .color(self.colors.accent2),
                    );
                    ui.label(
                        egui::RichText::new("Signed. Copy the response and send it back.")
                            .size(11.5)
                            .color(self.colors.accent2),
                    );
                });
                ui.add_space(6.0);

                let mut display = response_copy.clone();
                json_frame(&self.colors).show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut display)
                            .desired_width(ui.available_width())
                            .desired_rows(4)
                            .frame(egui::Frame::NONE)
                            .font(egui::FontId::monospace(11.0)),
                    );
                });
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    if ui
                        .add(ghost_button(
                            &self.colors,
                            "Copy Response",
                            egui::vec2(140.0, 26.0),
                        ))
                        .clicked()
                    {
                        ui.ctx().copy_text(response_copy.clone());
                        self.status = crate::types::Status::Info("Response copied!".to_string());
                    }
                    if ui
                        .add(ghost_button(&self.colors, "Done", egui::vec2(80.0, 26.0)))
                        .clicked()
                    {
                        self.cosign_response_json = None;
                        self.cosign_request_json.clear();
                    }
                });
            });
            return;
        }

        // ── Paste + verify + sign panel ──
        panel_frame(&self.colors).show(ui, |ui| {
            section_header(ui, &self.colors, &code, "Signing Request");
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Paste a signing request from another party to co-sign.")
                    .size(11.0)
                    .color(self.colors.text_muted),
            );
            ui.add_space(8.0);

            json_frame(&self.colors).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.cosign_request_json)
                        .hint_text("Paste signing request JSON here...")
                        .desired_width(ui.available_width())
                        .desired_rows(4)
                        .frame(egui::Frame::NONE)
                        .font(egui::FontId::monospace(11.0)),
                );
            });
            ui.add_space(8.0);

            // ── Preview + sign ──
            if self.cosign_request_json.trim().is_empty() {
                return;
            }
            match serde_json::from_str::<qpv2_core::types::SigningRequest>(
                self.cosign_request_json.trim(),
            ) {
                Ok(request) => {
                    egui::Frame::new()
                        .stroke(egui::Stroke::new(1.0, self.colors.border))
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                egui::RichText::new("TRANSACTION DETAILS")
                                    .font(label_font(9.5))
                                    .color(self.colors.text_muted),
                            );
                            ui.add_space(8.0);

                            detail_field(ui, &self.colors, "TYPE", &request.metadata.tx_type);
                            detail_field(ui, &self.colors, "FROM", &request.metadata.from_address);
                            if let Some(ref to) = request.metadata.to_address {
                                detail_field(ui, &self.colors, "TO", to);
                            }
                            if let Some(ref amount) = request.metadata.amount_ckb {
                                detail_field(
                                    ui,
                                    &self.colors,
                                    "AMOUNT",
                                    &format!("{} CKB", amount),
                                );
                            }
                            detail_field(
                                ui,
                                &self.colors,
                                "THRESHOLD",
                                &format!(
                                    "{}-of-{}",
                                    request.multisig_config.threshold,
                                    request.multisig_config.signers.len()
                                ),
                            );
                        });

                    ui.add_space(10.0);

                    let sign_btn = ghost_button(
                        &self.colors,
                        "Approve & Sign",
                        egui::vec2(ui.available_width(), 36.0),
                    );
                    if ui.add(sign_btn).clicked() {
                        self.cosign_sign_request(request);
                    }
                }
                Err(e) => {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("[ ERR ]")
                                .font(label_font(10.0))
                                .color(self.colors.danger),
                        );
                        ui.label(
                            egui::RichText::new(format!("Invalid JSON: {}", e))
                                .size(11.0)
                                .color(self.colors.danger),
                        );
                    });
                }
            }
        });
    }

    /// Authenticate, find the matching local key, sign, and produce the response JSON.
    fn cosign_sign_request(&mut self, request: qpv2_core::types::SigningRequest) {
        use qpv2_core::KeyVault;

        let variant = match KeyVault::get_spx_variant(self.wallet_id) {
            Ok(v) => v,
            Err(e) => {
                self.status = crate::types::Status::Error(format!("Failed to read variant: {}", e));
                return;
            }
        };

        let singlesig_accounts = match KeyVault::get_singlesig_accounts(self.wallet_id) {
            Ok(a) => a,
            Err(e) => {
                self.status =
                    crate::types::Status::Error(format!("Failed to load accounts: {}", e));
                return;
            }
        };

        let mut matched_signer_index = None;
        let mut matched_lock_args = None;

        for account in &singlesig_accounts {
            let account_pubkey = &account.config.signers[0].pubkey;
            for (i, signer) in request.multisig_config.signers.iter().enumerate() {
                if signer.pubkey == *account_pubkey && signer.variant == variant {
                    matched_signer_index = Some(i);
                    matched_lock_args = Some(account.lock_args.clone());
                    break;
                }
            }
            if matched_signer_index.is_some() {
                break;
            }
        }

        let signer_index = match matched_signer_index {
            Some(i) => i,
            None => {
                self.status = crate::types::Status::Error(
                    "No local account matches a signer in this request.".to_string(),
                );
                return;
            }
        };
        let singlesig_lock_args = matched_lock_args.unwrap();

        let message_bytes = match hex::decode(&request.signing_message) {
            Ok(b) => b,
            Err(e) => {
                self.status =
                    crate::types::Status::Error(format!("Invalid signing message hex: {}", e));
                return;
            }
        };

        // Authenticate
        let auth = match &self.auth_method {
            Some(qpv2_core::types::AuthMethod::Password) => {
                match qpv2_core::pinentry::prompt_password(
                    "Enter your wallet password to co-sign a multisig transaction.",
                    "Password:",
                ) {
                    Ok(pw) => qpv2_core::types::AuthKey::Password(pw),
                    Err(e) => {
                        self.status = crate::types::Status::Error(format!("Auth failed: {}", e));
                        return;
                    }
                }
            }
            Some(qpv2_core::types::AuthMethod::Keychain) => {
                match keychain::retrieve_key(self.wallet_id) {
                    Ok(key) => qpv2_core::types::AuthKey::CryptoKey(key),
                    Err(e) => {
                        self.status = crate::types::Status::Error(format!("Auth failed: {}", e));
                        return;
                    }
                }
            }
            Some(qpv2_core::types::AuthMethod::Fido2 { ref credential_id }) => {
                let cred_bytes = match hex::decode(credential_id) {
                    Ok(b) => b,
                    Err(e) => {
                        self.status =
                            crate::types::Status::Error(format!("Invalid credential: {}", e));
                        return;
                    }
                };
                match qpv2_core::pinentry::prompt_password(
                    "Enter your wallet password to co-sign a multisig transaction.",
                    "Password:",
                ) {
                    Ok(pin) => match keychain::fido2::authenticate(&cred_bytes, &pin) {
                        Ok(hmac) => match qpv2_core::utilities::derive_vault_enc_key(&hmac) {
                            Ok(key) => qpv2_core::types::AuthKey::CryptoKey(key),
                            Err(e) => {
                                self.status = crate::types::Status::Error(format!(
                                    "Key derivation failed: {}",
                                    e
                                ));
                                return;
                            }
                        },
                        Err(e) => {
                            self.status =
                                crate::types::Status::Error(format!("FIDO2 auth failed: {}", e));
                            return;
                        }
                    },
                    Err(e) => {
                        self.status =
                            crate::types::Status::Error(format!("PIN prompt failed: {}", e));
                        return;
                    }
                }
            }
            Some(qpv2_core::types::AuthMethod::Trezor { .. }) => {
                // Multisig co-signing on a Trezor is not supported: the firmware
                // only signs a transaction locked by its own single-sig lock.
                self.status = crate::types::Status::Error(
                    "Co-signing a multisig transaction on a Trezor is not supported yet."
                        .to_string(),
                );
                return;
            }
            None => {
                self.status =
                    crate::types::Status::Error("No authentication method set.".to_string());
                return;
            }
        };

        let vault = KeyVault::new(variant, self.wallet_id);
        let (signature, _pubkey) = match vault.raw_sign(auth, singlesig_lock_args, message_bytes) {
            Ok(s) => s,
            Err(e) => {
                self.status = crate::types::Status::Error(format!("Signing failed: {}", e));
                return;
            }
        };

        let response = qpv2_core::types::SigningResponse {
            version: request.version,
            signer_index,
            signature: hex::encode(&signature),
            signing_message: request.signing_message.clone(),
        };

        match serde_json::to_string_pretty(&response) {
            Ok(json) => {
                self.cosign_response_json = Some(json);
                self.status =
                    crate::types::Status::Info("Signed! Copy the response below.".to_string());
            }
            Err(e) => {
                self.status =
                    crate::types::Status::Error(format!("Failed to serialize response: {}", e));
            }
        }
    }
}
