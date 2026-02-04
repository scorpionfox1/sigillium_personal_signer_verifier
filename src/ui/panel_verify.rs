// src/ui/panel_verify.rs

use super::Route;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    error::AppError,
    types::{AppState, KeyId, SignVerifyMode},
};

use super::{message::PanelMsgState, widgets};

pub struct VerifyPanel {
    pubkey_hex: String,
    signature_b64: String,
    message: String,
    msg: PanelMsgState,
}

impl VerifyPanel {
    pub fn new() -> Self {
        Self {
            pubkey_hex: String::new(),
            signature_b64: String::new(),
            message: String::new(),
            msg: PanelMsgState::default(),
        }
    }

    pub fn apply_prefill(&mut self, message: String, signature_b64: String) {
        self.message = message;
        self.signature_b64 = signature_b64;
        self.msg.clear();
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.pubkey_hex.clear();
        self.signature_b64.clear();
        self.message.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.heading("Verify");
                ui.separator();

                let metas = state.keys.lock().map(|g| g.clone()).unwrap_or_default();
                if let Err(e) =
                    widgets::active_key_selector(ui, state, ctx, route, "verify_active_key", &metas)
                {
                    if let AppError::KeyfileQuarantined { .. } = e {
                        *route = Route::KeyfileSelect;
                        return;
                    }
                    self.msg.from_app_error(&e);
                }

                let current_active_id: Option<KeyId> =
                    lock_session(state).ok().and_then(|g| g.active_key_id);

                ui.add_space(12.0);

                let mut mode = state
                    .sign_verify_mode
                    .lock()
                    .map(|g| *g)
                    .unwrap_or(SignVerifyMode::Text);
                let prev_mode = mode;

                ui.horizontal(|ui| {
                    ui.label("Sign mode");
                    ui.selectable_value(&mut mode, SignVerifyMode::Text, "Text");
                    ui.selectable_value(&mut mode, SignVerifyMode::Json, "JSON");
                });

                if mode != prev_mode {
                    if let Ok(mut g) = state.sign_verify_mode.lock() {
                        *g = mode;
                    }
                    self.message.clear();
                    self.msg.clear();
                }

                ui.add_space(12.0);

                let active_pubkey_hex: Option<String> = current_active_id.and_then(|id| {
                    metas
                        .iter()
                        .find(|m| m.id == id)
                        .map(|m| hex::encode(m.public_key))
                });

                if let Some(pk) = active_pubkey_hex.as_deref() {
                    widgets::copy_label_with_button(ui, "Public key (hex)", pk, "Copy public key");
                } else {
                    ui.label("Public key (hex)");
                }

                if let Some(pk) = active_pubkey_hex.as_deref() {
                    let mut s = pk.to_string();
                    ui.add(egui::TextEdit::singleline(&mut s).interactive(false));
                } else {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pubkey_hex)
                            .hint_text("Paste hex public key…"),
                    );
                }

                ui.add_space(10.0);

                widgets::copy_label_with_button(
                    ui,
                    "Signature (base64)",
                    &self.signature_b64,
                    "Copy signature",
                );

                ui.add(
                    egui::TextEdit::multiline(&mut self.signature_b64)
                        .desired_rows(6)
                        .hint_text("Paste base64 signature…"),
                );

                ui.add_space(10.0);

                ui.label(match mode {
                    SignVerifyMode::Text => "String Message",
                    SignVerifyMode::Json => "JSON Message",
                });
                ui.add(
                    egui::TextEdit::multiline(&mut self.message)
                        .desired_rows(12)
                        .hint_text(match mode {
                            SignVerifyMode::Text => {
                                "Paste the exact string message that was signed…"
                            }
                            SignVerifyMode::Json => "Paste the exact JSON message that was signed…",
                        }),
                );

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    if ui.button("Verify").clicked() {
                        self.clear_messages();

                        let pk_hex = if let Some(pk) = active_pubkey_hex.as_deref() {
                            pk.trim()
                        } else {
                            self.pubkey_hex.trim()
                        };

                        if pk_hex.is_empty() {
                            self.msg.set_error("Public key required");
                            return;
                        }

                        let pk_bytes = match hex::decode(pk_hex) {
                            Ok(b) => b,
                            Err(_) => {
                                self.msg.set_error("Public key must be valid hex");
                                return;
                            }
                        };
                        if pk_bytes.len() != 32 {
                            self.msg.set_error(format!(
                                "Public key must be 32 bytes (got {})",
                                pk_bytes.len()
                            ));
                            return;
                        }

                        let sig_b64 = self.signature_b64.trim();
                        if sig_b64.is_empty() {
                            self.msg.set_error("Signature required");
                            return;
                        }

                        let sig_bytes = match STANDARD.decode(sig_b64.as_bytes()) {
                            Ok(b) => b,
                            Err(_) => {
                                self.msg.set_error("Signature must be valid base64");
                                return;
                            }
                        };
                        if sig_bytes.len() != 64 {
                            self.msg.set_error(format!(
                                "Signature must be 64 bytes (got {})",
                                sig_bytes.len()
                            ));
                            return;
                        }

                        let message = self.message.trim();
                        if message.is_empty() {
                            self.msg.set_error("Empty message not allowed");
                            return;
                        }

                        let mode = state
                            .sign_verify_mode
                            .lock()
                            .map(|g| *g)
                            .unwrap_or(SignVerifyMode::Text);

                        match command::verify_message(pk_hex, message, sig_b64, mode, None) {
                            Ok(true) => self.msg.set_info("Valid signature."),
                            Ok(false) => self.msg.set_info("Invalid signature."),
                            Err(e) => {
                                if let AppError::KeyfileQuarantined { .. } = e {
                                    *route = Route::KeyfileSelect;
                                    return;
                                }
                                self.msg.from_app_error(&e)
                            }
                        }
                    }

                    if ui.button("Clear fields").clicked() {
                        self.pubkey_hex.clear();
                        self.signature_b64.clear();
                        self.message.clear();
                        self.msg.clear();
                    }
                });

                self.msg.show(ui);
            });
    }
}
