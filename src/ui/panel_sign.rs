// src/ui/panel_sign.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    error::AppError,
    types::{AppState, SignOutputMode, SignVerifyMode},
};

use super::Route;
use super::{message::PanelMsgState, widgets};

pub struct SignPanel {
    message: String,
    schema: String,
    record_config: String,
    output_text: String,
    msg: PanelMsgState,
}

impl SignPanel {
    pub fn new() -> Self {
        Self {
            message: String::new(),
            schema: String::new(),
            record_config: String::new(),
            output_text: String::new(),
            msg: PanelMsgState::default(),
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.message.clear();
        self.schema.clear();
        self.record_config.clear();
        self.output_text.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        ui.heading("Sign");
        ui.separator();

        // Active key selector outside scroll area
        let metas = state.keys.lock().map(|g| g.clone()).unwrap_or_default();
        if let Err(e) =
            widgets::active_key_selector(ui, state, ctx, route, "sign_active_key", &metas)
        {
            if let AppError::KeyfileQuarantined { .. } = e {
                *route = Route::KeyfileSelect;
                return;
            }
            self.msg.from_app_error(&e, ctx.debug_ui);
        }
        ui.add_space(10.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {

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

                // ---- Sign mode (Text / JSON)
                let mut sign_mode = state
                    .sign_verify_mode
                    .lock()
                    .map(|m| *m)
                    .unwrap_or(SignVerifyMode::Text);

                ui.horizontal(|ui| {
                    ui.label("Sign mode:");
                    if ui
                        .selectable_label(sign_mode == SignVerifyMode::Text, "Text")
                        .clicked()
                    {
                        sign_mode = SignVerifyMode::Text;
                    }
                    if ui
                        .selectable_label(sign_mode == SignVerifyMode::Json, "JSON")
                        .clicked()
                    {
                        sign_mode = SignVerifyMode::Json;
                    }
                });

                if let Ok(mut g) = state.sign_verify_mode.lock() {
                    *g = sign_mode;
                }

                ui.add_space(6.0);

                // ---- Output mode (Signature / Record)
                let mut output_mode = state
                    .sign_output_mode
                    .lock()
                    .map(|m| *m)
                    .unwrap_or(SignOutputMode::Signature);

                ui.horizontal(|ui| {
                    ui.label("Output mode:");
                    if ui
                        .selectable_label(output_mode == SignOutputMode::Signature, "Signature")
                        .clicked()
                    {
                        output_mode = SignOutputMode::Signature;
                    }
                    if ui
                        .selectable_label(output_mode == SignOutputMode::Record, "Record")
                        .clicked()
                    {
                        output_mode = SignOutputMode::Record;
                    }
                });

                if let Ok(mut g) = state.sign_output_mode.lock() {
                    *g = output_mode;
                }

                ui.add_space(10.0);

                // ---- Message (left) + Schema/Config (right)
                ui.columns(2, |cols| {
                    // LEFT: message
                    cols[0].horizontal(|ui| {
                        ui.label("Message");
                        let ok = !self.message.trim().is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy message") {
                            ui.ctx().copy_text(self.message.clone());
                        }
                    });

                    cols[0].add(
                        egui::TextEdit::multiline(&mut self.message)
                            .desired_rows(12)
                            .hint_text("Message to sign…"),
                    );

                    // RIGHT: schema + record config (stacked)
                    cols[1].vertical(|ui| {
                        if sign_mode == SignVerifyMode::Json {
                            ui.label("Schema (optional, draft 2020-12)");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.schema)
                                    .desired_rows(6)
                                    .hint_text(
                                        "{ \"$schema\": \"https://json-schema.org/draft/2020-12/schema\", }",
                                    ),
                            );
                            ui.add_space(10.0);
                        }

                        if output_mode == SignOutputMode::Record {
                            ui.label("Signature record config (optional)");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.record_config)
                                    .desired_rows(6)
                                    .hint_text(
r#"{ 
  "payload_name": "payload",
  "signature_name": "signature",
  "pub_key_name": "pub_key",
  "assoc_key_id_name": "assoc_key_id"
}"#,
                                    ),
                            );
                        }
                    });
                });

                ui.add_space(2.0);

                let has_active = current_active_id.is_some();
                let can_sign = has_active && !self.message.trim().is_empty();

                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(can_sign, egui::Button::new("Sign"))
                        .clicked()
                    {
                        self.clear_messages();

                        let schema_opt = if sign_mode == SignVerifyMode::Json {
                            let s = self.schema.trim();
                            if s.is_empty() {
                                None
                            } else {
                                Some(s)
                            }
                        } else {
                            None
                        };

                        let config_opt = if output_mode == SignOutputMode::Record {
                            let s = self.record_config.trim();
                            if s.is_empty() {
                                None
                            } else {
                                Some(s)
                            }
                        } else {
                            None
                        };

                        match command::sign_payload(
                            self.message.trim(),
                            sign_mode,
                            schema_opt,
                            state,
                            config_opt,
                        ) {
                            Ok(out) => {
                                self.output_text = out;
                                self.msg.set_success("Signed.");
                            }
                            Err(e) => {
                                if let AppError::KeyfileQuarantined { .. } = e {
                                    *route = Route::KeyfileSelect;
                                    self.output_text.clear();
                                    return;
                                }
                                self.msg.from_app_error(&e, ctx.debug_ui);
                                self.output_text.clear();
                            }
                        }
                    }

                    if ui
                        .add_enabled(!self.message.trim().is_empty(), egui::Button::new("Replace message tags"))
                        .clicked()
                    {
                        self.clear_messages();

                        let before = self.message.clone();
                        let after = command::sign_verify::replace_tags(before.as_str(), active_assoc_id.as_str());

                        if after == before {
                            self.msg.set_info("No tags found.");
                        } else {
                            self.message = after;
                            self.msg.set_success("Tags replaced.");
                        }
                    }

                    if ui.button("Clear fields").clicked() {
                        self.reset_inputs();
                        self.clear_messages();
                    }
                });

                self.msg.show(ui, false);

                ui.add_space(8.0);
                ui.separator();


                let left_label = if output_mode == SignOutputMode::Signature {
                    "Signature (base64)"
                } else {
                    "Signature record (canonical JSON)"
                };

                ui.columns(2, |cols| {
                    cols[0].horizontal(|ui| {
                        ui.label(left_label);
                        let ok = !self.output_text.trim().is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy output") {
                            ui.ctx().copy_text(self.output_text.clone());
                        }
                    });

                    cols[0].add(
                        egui::TextEdit::multiline(&mut self.output_text)
                            .desired_rows(10)
                            .interactive(false)
                            .hint_text("Output will appear here…"),
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
