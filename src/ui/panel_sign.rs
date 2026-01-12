// src/ui/panel_sign.rs

use eframe::egui;
use sigillum_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    types::{AppState, SignVerifyMode},
};

use super::Route;
use super::{message::PanelMsgState, widgets};

pub struct SignPanel {
    message: String,
    schema: String,
    signature_b64: String,
    msg: PanelMsgState,
}

impl SignPanel {
    pub fn new() -> Self {
        Self {
            message: String::new(),
            schema: String::new(),
            signature_b64: String::new(),
            msg: PanelMsgState::default(),
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.message.clear();
        self.schema.clear();
        self.signature_b64.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.heading("Sign");
                ui.separator();

                // Active key selector
                let metas = state.keys.lock().map(|g| g.clone()).unwrap_or_default();
                if let Err(e) =
                    widgets::active_key_selector(ui, state, ctx, route, "sign_active_key", &metas)
                {
                    self.msg.from_app_error(&e, ctx.debug_ui);
                }
                ui.add_space(10.0);

                let current_active_id = lock_session(state).ok().and_then(|g| g.active_key_id);

                let active_pubkey_hex = current_active_id
                    .and_then(|id| {
                        metas
                            .iter()
                            .find(|m| m.id == id)
                            .map(|m| hex::encode(m.public_key))
                    })
                    .unwrap_or_default();

                let active_assoc_id = lock_session(state)
                    .ok()
                    .and_then(|g| g.active_associated_key_id.clone())
                    .unwrap_or_default();

                let mut mode = state
                    .sign_verify_mode
                    .lock()
                    .map(|m| *m)
                    .unwrap_or(SignVerifyMode::Text);

                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    if ui
                        .selectable_label(mode == SignVerifyMode::Text, "Text")
                        .clicked()
                    {
                        mode = SignVerifyMode::Text;
                    }
                    if ui
                        .selectable_label(mode == SignVerifyMode::Json, "JSON")
                        .clicked()
                    {
                        mode = SignVerifyMode::Json;
                    }
                });

                if let Ok(mut g) = state.sign_verify_mode.lock() {
                    *g = mode;
                }

                ui.add_space(8.0);

                ui.label("Message");
                ui.add(
                    egui::TextEdit::multiline(&mut self.message)
                        .desired_rows(7)
                        .hint_text("Message to sign…"),
                );

                if mode == SignVerifyMode::Json {
                    ui.add_space(8.0);
                    ui.label("Schema (optional, draft 2020-12)");
                    ui.add(
                egui::TextEdit::multiline(&mut self.schema)
                    .desired_rows(5)
                    .hint_text(
                        "{ \"$schema\": \"https://json-schema.org/draft/2020-12/schema\", ... }",
                    ),
            );
                }

                ui.add_space(10.0);

                let has_active = current_active_id.is_some();
                let can_sign = has_active && !self.message.trim().is_empty();

                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(can_sign, egui::Button::new("Sign"))
                        .clicked()
                    {
                        self.clear_messages();

                        let schema_opt = if mode == SignVerifyMode::Json {
                            let s = self.schema.trim();
                            if s.is_empty() {
                                None
                            } else {
                                Some(s)
                            }
                        } else {
                            None
                        };

                        match command::sign_payload(self.message.trim(), mode, schema_opt, state) {
                            Ok(sig_b64) => {
                                self.signature_b64 = sig_b64;
                                self.msg.set_success("Signed.");
                            }
                            Err(e) => {
                                self.msg.from_app_error(&e, ctx.debug_ui);
                                self.signature_b64.clear();
                            }
                        }
                    }

                    if ui.button("Clear fields").clicked() {
                        self.reset_inputs();
                        self.clear_messages();
                    }

                    if !has_active {
                        ui.weak("Select an active key in Key Registry to sign.");
                    }
                });

                self.msg.show(ui, false);

                ui.separator();

                ui.columns(2, |cols| {
                    cols[0].horizontal(|ui| {
                        ui.label("Signature (base64)");
                        let ok = !self.signature_b64.trim().is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy signature") {
                            ui.ctx().copy_text(self.signature_b64.clone());
                        }
                    });

                    cols[0].add(
                        egui::TextEdit::multiline(&mut self.signature_b64)
                            .desired_rows(7)
                            .interactive(false)
                            .hint_text("Signature will appear here…"),
                    );

                    cols[1].label("Active key");

                    cols[1].horizontal(|ui| {
                        ui.label("Public key (hex)");
                        let ok = !active_pubkey_hex.is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy public key") {
                            ui.ctx().copy_text(active_pubkey_hex.clone());
                        }
                    });
                    let mut pk = active_pubkey_hex.clone();
                    cols[1].add(
                        egui::TextEdit::singleline(&mut pk)
                            .interactive(false)
                            .hint_text("No active key"),
                    );

                    cols[1].add_space(6.0);

                    cols[1].horizontal(|ui| {
                        ui.label("Associated ID");
                        let ok = !active_assoc_id.is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy associated ID") {
                            ui.ctx().copy_text(active_assoc_id.clone());
                        }
                    });
                    let mut aid = active_assoc_id.clone();
                    cols[1].add(
                        egui::TextEdit::singleline(&mut aid)
                            .interactive(false)
                            .hint_text("—"),
                    );
                });
            });
    }
}
