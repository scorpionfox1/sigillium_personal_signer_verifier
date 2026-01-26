// src/ui/panel_document_wizard.rs

use crate::ui::message::PanelMsgState;
use eframe::egui;
use serde_json::Value as JsonValue;
use sigillium_personal_signer_verifier_lib::context::AppCtx;
use sigillium_personal_signer_verifier_lib::types::AppState;
use std::collections::BTreeMap;

use sigillium_personal_signer_verifier_lib::command::document_wizard as dw;
use sigillium_personal_signer_verifier_lib::template::doc_wizard::{InputSpec, InputType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WizardPanelMode {
    EditDocs,
    ReviewBuild,
}

pub struct DocumentWizardPanel {
    msg: PanelMsgState,

    template_text: String,
    wizard: Option<dw::WizardState>,

    mode: WizardPanelMode,

    // raw text buffers for inputs that are edited as text
    input_buf: BTreeMap<String, String>,

    // raw JSON buffers for json-type inputs
    json_buf: BTreeMap<String, String>,

    bundle_out: String,
}

impl DocumentWizardPanel {
    pub fn new() -> Self {
        Self {
            msg: PanelMsgState::default(),
            template_text: String::new(),
            wizard: None,
            mode: WizardPanelMode::EditDocs,
            input_buf: BTreeMap::new(),
            json_buf: BTreeMap::new(),
            bundle_out: String::new(),
        }
    }

    pub fn reset_inputs(&mut self) {
        self.template_text.clear();
        self.wizard = None;
        self.mode = WizardPanelMode::EditDocs;
        self.input_buf.clear();
        self.json_buf.clear();
        self.bundle_out.clear();
        self.msg.clear();
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, _state: &AppState, _ctx: &AppCtx) {
        let debug_ui = cfg!(debug_assertions);

        ui.heading("Document Wizard");
        ui.add_space(6.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                self.msg.show(ui, debug_ui);

                if self.wizard.is_none() {
                    ui.label("Load a template to begin.");
                    ui.add_space(6.0);
                }

                ui.label("Template (JSON5):");

                ui.horizontal(|ui| {
                    let open_btn = ui.small_button("Browse");
                    if open_btn.clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("JSON5", &["json5"])
                            .add_filter("JSON", &["json"])
                            .pick_file()
                        {
                            match std::fs::read_to_string(&path) {
                                Ok(s) => {
                                    self.template_text = s;
                                    self.bundle_out.clear();
                                    self.input_buf.clear();
                                    self.json_buf.clear();
                                    self.mode = WizardPanelMode::EditDocs;

                                    match dw::load_wizard_from_str(&self.template_text) {
                                        Ok(w) => {
                                            self.wizard = Some(w);
                                            self.msg.clear();
                                        }
                                        Err(e) => {
                                            self.wizard = None;
                                            self.msg.set_warn(&format!("Load failed: {e}"));
                                        }
                                    }
                                }
                                Err(e) => self.msg.set_warn(&format!("Read failed: {e}")),
                            }
                        }
                    }

                    if ui.button("Load Template").clicked() {
                        self.bundle_out.clear();
                        self.input_buf.clear();
                        self.json_buf.clear();
                        self.mode = WizardPanelMode::EditDocs;

                        match dw::load_wizard_from_str(&self.template_text) {
                            Ok(w) => {
                                self.wizard = Some(w);
                                self.msg.clear();
                            }
                            Err(e) => {
                                self.wizard = None;
                                self.msg.set_warn(&format!("Load failed: {e}"));
                            }
                        }
                    }

                    if ui.button("Clear").clicked() {
                        self.reset_inputs();
                    }
                });

                ui.add(
                    egui::TextEdit::multiline(&mut self.template_text)
                        .desired_rows(10)
                        .lock_focus(true),
                );

                let Some(_) = self.wizard.as_ref() else {
                    return;
                };

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(6.0);

                // Borrow-splitting: do not call any &mut self methods while holding &mut self.wizard.
                let mode = self.mode;

                let msg = &mut self.msg;
                let input_buf = &mut self.input_buf;
                let json_buf = &mut self.json_buf;
                let bundle_out = &mut self.bundle_out;
                let mode_ref = &mut self.mode;

                let Some(wiz) = self.wizard.as_mut() else {
                    return;
                };

                match mode {
                    WizardPanelMode::EditDocs => {
                        Self::ui_edit_docs_impl(
                            ui, msg, input_buf, json_buf, bundle_out, mode_ref, wiz,
                        );
                    }
                    WizardPanelMode::ReviewBuild => {
                        Self::ui_review_build_impl(ui, msg, bundle_out, mode_ref, wiz);
                    }
                }
            });
    }

    fn ui_edit_docs_impl(
        ui: &mut egui::Ui,
        msg: &mut PanelMsgState,
        input_buf: &mut BTreeMap<String, String>,
        json_buf: &mut BTreeMap<String, String>,
        bundle_out: &mut String,
        mode: &mut WizardPanelMode,
        wiz: &mut dw::WizardState,
    ) {
        let doc_count = wiz.docs.len();
        let doc_index = wiz.doc_index;

        let doc_label: String = wiz
            .docs
            .get(doc_index)
            .map(|d| d.doc_identity.label.clone())
            .unwrap_or_else(|| "(unknown)".to_string());

        ui.horizontal(|ui| {
            ui.label(format!(
                "Document: {}/{} — {}",
                doc_index + 1,
                doc_count,
                doc_label
            ));

            let back_enabled = doc_index > 0;
            if ui
                .add_enabled(back_enabled, egui::Button::new("Back"))
                .clicked()
            {
                bundle_out.clear();
                match dw::back_doc(wiz) {
                    Ok(()) => msg.clear(),
                    Err(e) => msg.set_warn(&format!("{e}")),
                }
            }

            let is_last = doc_index + 1 >= doc_count;
            let next_label = if is_last { "Review" } else { "Next" };

            if ui.button(next_label).clicked() {
                bundle_out.clear();

                if is_last {
                    msg.clear();
                    *mode = WizardPanelMode::ReviewBuild;
                } else {
                    match dw::advance_doc(wiz) {
                        Ok(()) => msg.clear(),
                        Err(e) => msg.set_warn(&format!("{e}")),
                    }
                }
            }
        });

        ui.add_space(6.0);

        // Current doc template diagnostics + hash line.
        if let Ok(d) = dw::current_doc(wiz) {
            if !d.template_errors.is_empty() {
                ui.label("Template errors:");
                for e in d.template_errors.iter() {
                    ui.label(format!("- {e}"));
                }
                ui.add_space(6.0);
            }

            if !d.template_warnings.is_empty() {
                ui.label("Template warnings:");
                for w in d.template_warnings.iter() {
                    ui.label(format!("- {w}"));
                }
                ui.add_space(6.0);
            }

            ui.label(format!(
                "Hash: expected {} | computed {}",
                d.expected_hash_hex, d.computed_hash_hex
            ));
        }

        ui.separator();

        ui.heading("Inputs");
        ui.add_space(6.0);

        let specs = collect_current_doc_specs(wiz);
        if specs.is_empty() {
            ui.label("(No inputs declared for this document.)");
        } else {
            for (key, spec) in specs {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        if spec.required {
                            ui.label(format!("{} *", spec.label));
                        } else {
                            ui.label(&spec.label);
                        }
                        ui.label(format!("({})", key));
                    });

                    match spec.input_type {
                        InputType::String | InputType::Date => {
                            let buf = input_buf
                                .entry(key.clone())
                                .or_insert_with(|| current_value_string(wiz, &key));

                            let resp = ui.add(egui::TextEdit::singleline(buf));
                            if resp.changed() {
                                let _ = dw::set_input_value_current_doc(
                                    wiz,
                                    &key,
                                    JsonValue::String(buf.clone()),
                                );
                            }
                        }

                        InputType::Enum => {
                            let choices = spec.choices.clone().unwrap_or_default();
                            let cur = current_value_string(wiz, &key);

                            egui::ComboBox::from_id_salt(format!("enum_{key}"))
                                .selected_text(if cur.is_empty() {
                                    "(select)".to_string()
                                } else {
                                    cur.clone()
                                })
                                .show_ui(ui, |ui| {
                                    for c in choices.iter() {
                                        if ui.selectable_label(cur == *c, c).clicked() {
                                            let _ = dw::set_input_value_current_doc(
                                                wiz,
                                                &key,
                                                JsonValue::String(c.clone()),
                                            );
                                        }
                                    }
                                });
                        }

                        InputType::Number => {
                            let buf = input_buf
                                .entry(key.clone())
                                .or_insert_with(|| current_value_string(wiz, &key));

                            let resp = ui.add(egui::TextEdit::singleline(buf));
                            if resp.changed() {
                                let s = buf.trim();
                                if s.is_empty() {
                                    // allow clearing
                                } else if let Ok(x) = s.parse::<f64>() {
                                    if let Some(n) = serde_json::Number::from_f64(x) {
                                        let _ =
                                            dw::set_input_value_current_doc(wiz, &key, n.into());
                                    }
                                }
                            }
                        }

                        InputType::Int => {
                            let buf = input_buf
                                .entry(key.clone())
                                .or_insert_with(|| current_value_string(wiz, &key));

                            let resp = ui.add(egui::TextEdit::singleline(buf));
                            if resp.changed() {
                                let s = buf.trim();
                                if s.is_empty() {
                                    // allow clearing
                                } else if let Ok(x) = s.parse::<i64>() {
                                    let _ = dw::set_input_value_current_doc(
                                        wiz,
                                        &key,
                                        JsonValue::Number(x.into()),
                                    );
                                }
                            }
                        }

                        InputType::Bool => {
                            let cur = current_value_bool(wiz, &key);
                            let mut v = cur;

                            if ui.checkbox(&mut v, "true/false").changed() {
                                let _ = dw::set_input_value_current_doc(wiz, &key, v.into());
                            }
                        }

                        InputType::Json => {
                            let buf = json_buf
                                .entry(key.clone())
                                .or_insert_with(|| current_value_json_pretty(wiz, &key));

                            ui.add(egui::TextEdit::multiline(buf).desired_rows(6).code_editor());

                            ui.horizontal(|ui| {
                                if ui.button("Apply JSON").clicked() {
                                    match dw::set_input_json_from_str_current_doc(wiz, &key, buf) {
                                        Ok(()) => msg.clear(),
                                        Err(e) => msg.set_warn(&format!("{e}")),
                                    }
                                }

                                if ui.button("Clear JSON").clicked() {
                                    buf.clear();
                                }
                            });
                        }
                    }
                });

                ui.add_space(6.0);
            }
        }

        ui.separator();

        if ui.button("Validate Current Doc").clicked() {
            match dw::validate_current_doc_inputs(wiz) {
                Ok(()) => msg.set_warn("OK"),
                Err(e) => msg.set_warn(&format!("{e}")),
            }
        }
    }

    fn ui_review_build_impl(
        ui: &mut egui::Ui,
        msg: &mut PanelMsgState,
        bundle_out: &mut String,
        mode: &mut WizardPanelMode,
        wiz: &mut dw::WizardState,
    ) {
        ui.heading("Review & Build");
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            if ui.button("Back to Docs").clicked() {
                *mode = WizardPanelMode::EditDocs;
                msg.clear();
            }

            if ui.button("Build Bundle JSON").clicked() {
                match dw::build_bundle_json(wiz) {
                    Ok(v) => match serde_json::to_string_pretty(&v) {
                        Ok(s) => {
                            *bundle_out = s;
                            msg.clear();
                        }
                        Err(e) => msg.set_warn(&format!("Serialize failed: {e}")),
                    },
                    Err(e) => msg.set_warn(&format!("{e}")),
                }
            }
        });

        ui.add_space(6.0);

        for (i, d) in wiz.docs.iter().enumerate() {
            let title = format!(
                "Doc {}/{} — {}",
                i + 1,
                wiz.docs.len(),
                d.doc_identity.label
            );
            egui::CollapsingHeader::new(title)
                .default_open(i == wiz.doc_index)
                .show(ui, |ui| {
                    if !d.template_errors.is_empty() {
                        ui.label("Template errors:");
                        for e in d.template_errors.iter() {
                            ui.label(format!("- {e}"));
                        }
                        ui.add_space(6.0);
                    }

                    if !d.template_warnings.is_empty() {
                        ui.label("Template warnings:");
                        for w in d.template_warnings.iter() {
                            ui.label(format!("- {w}"));
                        }
                        ui.add_space(6.0);
                    }

                    ui.label(format!(
                        "Hash: expected {} | computed {}",
                        d.expected_hash_hex, d.computed_hash_hex
                    ));
                });

            ui.add_space(4.0);
        }

        ui.separator();
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("Bundle JSON (sign this):");

            let copy_btn = ui.small_button("⧉").on_hover_text("Copy bundle JSON");
            if copy_btn.clicked() {
                ui.ctx().copy_text(bundle_out.clone());
            }
        });

        ui.add(
            egui::TextEdit::multiline(bundle_out)
                .desired_rows(10)
                .code_editor()
                .lock_focus(true),
        );
    }
}

fn collect_current_doc_specs(wiz: &dw::WizardState) -> Vec<(String, InputSpec)> {
    let Ok(d) = dw::current_doc(wiz) else {
        return Vec::new();
    };

    let mut map: BTreeMap<String, InputSpec> = BTreeMap::new();

    for s in d.sections.iter() {
        if let Some(specs) = &s.inputs_spec {
            for spec in specs.iter() {
                map.entry(spec.key.clone()).or_insert_with(|| spec.clone());
            }
        }
    }

    map.into_iter().collect()
}

fn current_value_string(wiz: &dw::WizardState, key: &str) -> String {
    let Ok(d) = dw::current_doc(wiz) else {
        return String::new();
    };
    match d.doc_inputs.get(key) {
        Some(JsonValue::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

fn current_value_bool(wiz: &dw::WizardState, key: &str) -> bool {
    let Ok(d) = dw::current_doc(wiz) else {
        return false;
    };
    d.doc_inputs
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn current_value_json_pretty(wiz: &dw::WizardState, key: &str) -> String {
    let Ok(d) = dw::current_doc(wiz) else {
        return String::new();
    };
    let Some(v) = d.doc_inputs.get(key) else {
        return String::new();
    };
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}
