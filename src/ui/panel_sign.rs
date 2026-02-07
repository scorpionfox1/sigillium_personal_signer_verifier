// src/ui/panel_sign.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    notices::AppNotice,
    types::{AppState, SignOutputMode, SignVerifyMode},
};

use serde_json::Value as JsonValue;

use super::{message::PanelMsgState, widgets};
use super::{Route, RoutePrefill};

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

    pub fn apply_prefill(&mut self, message: String) {
        self.message = message;
        self.schema.clear();
        self.output_text.clear();
        self.msg.clear();
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

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        ctx: &AppCtx,
        route: &mut Route,
        route_prefill: &mut Option<RoutePrefill>,
    ) {
        widgets::panel_title(ui, "Sign");
        ui.separator();

        // Active key selector outside scroll area
        let metas = state.keys.lock().map(|g| g.clone()).unwrap_or_default();
        let mut active_key_error: Option<AppNotice> = None;
        ui.horizontal(|ui| {
            ui.label("Key:");
            if let Err(e) =
                widgets::active_key_selector(ui, state, ctx, route, "sign_active_key", &metas)
            {
                active_key_error = Some(e);
            }
        });
        if let Some(e) = active_key_error {
            if let AppNotice::KeyfileQuarantined { .. } = e {
                *route = Route::KeyfileSelect;
                return;
            }
            self.msg.from_app_error(&e);
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
                    ui.selectable_value(
                        &mut output_mode,
                        SignOutputMode::Signature,
                        "Signature",
                    );
                    ui.selectable_value(&mut output_mode, SignOutputMode::Record, "Record");
                });

                if let Ok(mut g) = state.sign_output_mode.lock() {
                    *g = output_mode;
                }

                ui.add_space(6.0);

                // ---- Resolve tags mode (True / False)
                let mut resolve_tags_mode = state
                    .sign_resolve_tag_mode
                    .lock()
                    .map(|m| *m)
                    .unwrap_or(true);

                ui.horizontal(|ui| {
                    ui.label("Resolve tags mode:");
                    ui.selectable_value(&mut resolve_tags_mode, true, "True");
                    ui.selectable_value(&mut resolve_tags_mode, false, "False");
                });

                if let Ok(mut g) = state.sign_resolve_tag_mode.lock() {
                    *g = resolve_tags_mode;
                }

                ui.add_space(10.0);
                ui.separator();

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
  "message_name": "message",
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
                        .add_enabled(can_sign, egui::Button::new(egui::RichText::new("Sign").strong()))
                        .clicked()
                    {
                        self.clear_messages();

                        if resolve_tags_mode {
                            let before = self.message.clone();
                            let after = command::sign_verify::replace_tags(before.as_str(), active_assoc_id.as_str());
                            if after != before {
                                self.message = after;
                            }
                        }

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

                        match command::sign_message(
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
                                if let AppNotice::KeyfileQuarantined { .. } = e {
                                    *route = Route::KeyfileSelect;
                                    self.output_text.clear();
                                    return;
                                }
                                self.msg.from_app_error(&e);
                                self.output_text.clear();
                            }
                        }
                    }

                    if ui.button("Clear fields").clicked() {
                        self.reset_inputs();
                        self.clear_messages();
                    }

                                        let can_jump_verify = !self.output_text.trim().is_empty() && !self.message.trim().is_empty();
                    if ui
                        .add_enabled(can_jump_verify, egui::Button::new("Verify signature"))
                        .clicked()
                    {
                        // NOTE:
                        // This relies on UI-local signature-record parsing.
                        // If this behavior expands, move parsing out of the UI layer.
                        let sig_b64 = if output_mode == SignOutputMode::Signature {
                            self.output_text.trim().to_string()
                        } else {
                            let sig_field = self.signature_field_name_from_record_config();
                            match Self::extract_signature_b64_from_record(self.output_text.trim(), sig_field.as_str()) {
                                Ok(s) => s,
                                Err(e) => {
                                    self.msg.set_error(&e);
                                    return;
                                }
                            }
                        };

                        let mode = state
                            .sign_verify_mode
                            .lock()
                            .map(|g| *g)
                            .unwrap_or(SignVerifyMode::Text);

                        *route_prefill = Some(RoutePrefill::ToVerify {
                            mode,
                            message: self.message.trim().to_string(),
                            signature_b64: sig_b64,
                        });
                        *route = Route::Verify;
                    }

                });

                self.msg.show(ui);

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
                        let hover = "Copy output";
                        let copied = if output_mode == SignOutputMode::Record {
                            widgets::copy_json_icon_button(
                                ui,
                                ok,
                                "Copy output",
                                self.output_text.trim(),
                            )
                        } else {
                            widgets::copy_icon_button(ui, ok, hover)
                        };
                        if copied {
                            if output_mode == SignOutputMode::Signature {
                                ui.ctx().copy_text(self.output_text.clone());
                            }

                            let err = AppNotice::StringCopied;

                            let um = err.user_msg();
                            self.msg.set_success(um.short);
                        }
                    });

                    cols[0].add(
                        egui::TextEdit::multiline(&mut self.output_text)
                            .desired_rows(10)
                            .interactive(false)
                            .hint_text("Output will appear here…"),
                    );

                    let w = cols[1].available_width().min(480.0);

                    // Associated ID
                    cols[1].horizontal(|ui| {
                        ui.label("Associated ID");
                        let ok = !active_assoc_id.is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy associated ID") {
                            ui.ctx().copy_text(active_assoc_id.clone());
                        }
                    });
                    let mut aid = active_assoc_id.clone();
                    cols[1].scope(|ui| {
                        ui.set_max_width(w);
                        ui.add(
                            egui::TextEdit::singleline(&mut aid)
                                .desired_width(w)
                                .interactive(false)
                                .hint_text("—"),
                        );
                    });

                    cols[1].add_space(6.0);

                    // Public key
                    cols[1].horizontal(|ui| {
                        ui.label("Public key (hex)");
                        let ok = !active_pubkey_hex.is_empty();
                        if widgets::copy_icon_button(ui, ok, "Copy public key") {
                            ui.ctx().copy_text(active_pubkey_hex.clone());
                        }
                    });
                    let mut pk = active_pubkey_hex.clone();
                    cols[1].scope(|ui| {
                        ui.set_max_width(w);
                        ui.add(
                            egui::TextEdit::singleline(&mut pk)
                                .desired_width(w)
                                .interactive(false),
                        );
                    });

                });
            });
    }

    // NOTE:
    // This helper exists ONLY to support the Sign → Verify UI flow
    // when the sign output mode is `record`.
    //
    // If signature-record parsing is ever needed outside of this UI
    // (CLI, import, tests, or core verification paths), move this logic
    // out of the UI layer.
    fn signature_field_name_from_record_config(&self) -> String {
        let raw = self.record_config.trim();
        if raw.is_empty() {
            return "signature".to_string();
        }

        let Ok(v) = serde_json::from_str::<JsonValue>(raw) else {
            return "signature".to_string();
        };

        v.get("signature_name")
            .and_then(|x| x.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("signature")
            .to_string()
    }

    // NOTE:
    // UI-only helper. See comment above.
    fn extract_signature_b64_from_record(
        record_json: &str,
        signature_field: &str,
    ) -> Result<String, String> {
        let Ok(v) = serde_json::from_str::<JsonValue>(record_json) else {
            return Err("Signature record is not valid JSON".to_string());
        };

        let Some(obj) = v.as_object() else {
            return Err("Signature record JSON must be an object".to_string());
        };

        let Some(sig_val) = obj.get(signature_field) else {
            return Err(format!(
                "Signature record missing field '{signature_field}'"
            ));
        };

        let Some(sig) = sig_val.as_str() else {
            return Err(format!(
                "Signature record field '{signature_field}' must be a string"
            ));
        };

        let sig = sig.trim();
        if sig.is_empty() {
            return Err(format!(
                "Signature record field '{signature_field}' is empty"
            ));
        }

        Ok(sig.to_string())
    }
}
