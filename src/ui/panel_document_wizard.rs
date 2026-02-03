// src/ui/panel_document_wizard.rs

use crate::ui::message::PanelMsgState;
use crate::ui::widgets::ui_notice;
use eframe::egui;
use serde_json::Value as JsonValue;
use sigillium_personal_signer_verifier_lib::context::AppCtx;
use sigillium_personal_signer_verifier_lib::types::{AppState, SignOutputMode, SignVerifyMode};
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{Route, RoutePrefill};

use sigillium_personal_signer_verifier_lib::command::document_wizard::{
    self as dw, validate_current_section_inputs,
};
use sigillium_personal_signer_verifier_lib::template::doc_wizard::{InputSpec, InputType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WizardPanelMode {
    EditDocs,
    ReviewBuild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WizardStepPhase {
    About,
    Text,
    Translation,
    Inputs,
}

pub struct DocumentWizardPanel {
    msg: PanelMsgState,

    template_path: Option<PathBuf>,
    wizard: Option<dw::WizardState>,

    mode: WizardPanelMode,

    // UI-owned navigation state.
    section_index: usize,
    phase: WizardStepPhase,

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
            template_path: None,
            wizard: None,
            mode: WizardPanelMode::EditDocs,
            section_index: 0,
            phase: WizardStepPhase::Text,
            input_buf: BTreeMap::new(),
            json_buf: BTreeMap::new(),
            bundle_out: String::new(),
        }
    }

    pub fn reset_inputs(&mut self) {
        self.template_path = None;
        self.wizard = None;
        self.mode = WizardPanelMode::EditDocs;
        self.section_index = 0;
        self.phase = WizardStepPhase::Text;
        self.input_buf.clear();
        self.json_buf.clear();
        self.bundle_out.clear();
        self.msg.clear();
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        _state: &AppState,
        _ctx: &AppCtx,
        route: &mut Route,
        route_prefill: &mut Option<RoutePrefill>,
    ) {
        ui.heading("Document Wizard");
        ui.add_space(6.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                self.ui_template_picker(ui);

                ui.add_space(6.0);
                self.msg.show(ui);
                ui.add_space(6.0);

                let Some(wiz) = self.wizard.as_mut() else {
                    ui.add_space(6.0);
                    ui.label("Load a template to begin.");
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

                let section_index = &mut self.section_index;
                let phase = &mut self.phase;

                match mode {
                    WizardPanelMode::EditDocs => {
                        Self::ui_edit_docs_impl(
                            ui,
                            msg,
                            input_buf,
                            json_buf,
                            bundle_out,
                            mode_ref,
                            section_index,
                            phase,
                            wiz,
                        );
                    }
                    WizardPanelMode::ReviewBuild => {
                        Self::ui_review_build_impl(
                            ui,
                            msg,
                            bundle_out,
                            mode_ref,
                            wiz,
                            route,
                            route_prefill,
                        );
                    }
                }
            });
    }

    fn ui_template_picker(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Template:");

            let path_label = self
                .template_path
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "(none)".to_string());

            ui.label(path_label);

            if ui.small_button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("JSON5", &["json5"])
                    .add_filter("JSON", &["json"])
                    .pick_file()
                {
                    match std::fs::read_to_string(&path) {
                        Ok(s) => {
                            self.template_path = Some(path);
                            self.bundle_out.clear();
                            self.input_buf.clear();
                            self.json_buf.clear();
                            self.mode = WizardPanelMode::EditDocs;
                            self.section_index = 0;
                            self.phase = WizardStepPhase::Text;

                            match dw::load_wizard_from_str(&s) {
                                Ok(w) => {
                                    self.wizard = Some(w);
                                    self.msg.clear();
                                    if let Some(wiz) = self.wizard.as_ref() {
                                        self.phase = if doc_has_about(wiz) {
                                            WizardStepPhase::About
                                        } else {
                                            WizardStepPhase::Text
                                        };
                                    }
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

            if ui.small_button("Clear").clicked() {
                self.reset_inputs();
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
        section_index: &mut usize,
        phase: &mut WizardStepPhase,
        wiz: &mut dw::WizardState,
    ) {
        bundle_out.clear();

        let doc_count = wiz.docs.len();
        let doc_index = wiz.doc_index;

        let section_count = wiz
            .docs
            .get(doc_index)
            .map(|d| d.sections.len())
            .unwrap_or(0);

        if *section_index >= section_count {
            *section_index = 0;
            *phase = WizardStepPhase::Text;
        }

        let doc_label: String = wiz
            .docs
            .get(doc_index)
            .map(|d| d.doc_identity.label.clone())
            .unwrap_or_else(|| "(unknown)".to_string());

        // Progress header + nav.
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Doc {}/{} — {}",
                    doc_index + 1,
                    doc_count,
                    doc_label
                ));

                if section_count > 0 {
                    ui.label(format!(
                        "| Section {}/{}",
                        *section_index + 1,
                        section_count
                    ));
                }

                ui.label(format!("| {}", phase_label(*phase)));
            });

            let can_back = match *phase {
                WizardStepPhase::About => wiz.doc_index > 0,
                WizardStepPhase::Text => {
                    wiz.doc_index > 0 || *section_index > 0 || doc_has_about(wiz)
                }
                WizardStepPhase::Translation | WizardStepPhase::Inputs => true,
            };

            let at_last = is_last_step(wiz, *section_index, *phase);
            let can_next = if at_last {
                all_docs_have_no_template_errors(wiz)
            } else {
                true
            };

            ui.add_space(6.0);

            ui.horizontal(|ui| {
                let button_height = 32.0;

                let back_btn = egui::Button::new(egui::RichText::new("← Back").size(16.0))
                    .min_size(egui::vec2(100.0, button_height));

                if ui.add_enabled(can_back, back_btn).clicked() {
                    if let Err(e) = step_back(wiz, section_index, phase) {
                        msg.set_warn(&format!("{e}"));
                    } else {
                        msg.clear();
                    }
                }

                ui.add_space(8.0);

                let next_btn = egui::Button::new(egui::RichText::new("Next →").size(16.0))
                    .min_size(egui::vec2(120.0, button_height));

                if ui.add_enabled(can_next, next_btn).clicked() {
                    if at_last {
                        *mode = WizardPanelMode::ReviewBuild;
                        msg.clear();
                    } else if let Err(e) = step_next(wiz, section_index, phase) {
                        msg.set_warn(&format!("{e}"));
                    } else {
                        msg.clear();
                    }
                }
            });
        });

        ui.add_space(8.0);

        // Current doc diagnostics: failures (hard) and warnings.
        if let Ok(d) = dw::current_doc(wiz) {
            if !d.template_errors.is_empty() {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Template problems (must fix)").strong());
                    for e in d.template_errors.iter() {
                        ui.label(format!("- {e}"));
                    }
                });
                ui.add_space(8.0);
            }

            if !d.template_warnings.is_empty() {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Template warnings").strong());
                    for w in d.template_warnings.iter() {
                        ui.label(format!("- {w}"));
                    }
                });
                ui.add_space(8.0);
            }
        }

        // Centerpiece: section text / translation / inputs.
        match *phase {
            WizardStepPhase::About => {
                ui_notice(
                    ui,
                    "This section contains context information about the document you are about to read. It is provided to help orient you, but understand it is not signed ONLY the actual document text is hashed and signed.
                    
i.e. only the document text itself is canonical.",
                );

                let Some(about) = current_doc_about(wiz) else {
                    // If about is absent/empty, fall through behavior: show section text.
                    // (This should normally be unreachable if navigation is wired correctly.)
                    *phase = WizardStepPhase::Text;
                    return;
                };

                let mut text = about.to_string();
                ui_doc_text_window(ui, &mut text);
            }

            WizardStepPhase::Text => {
                let Some(section) = current_section(wiz, *section_index) else {
                    ui.label("(No section.)");
                    return;
                };
                ui_section_text(ui, section);
            }
            WizardStepPhase::Translation => {
                let Some(section) = current_section(wiz, *section_index) else {
                    ui.label("(No section.)");
                    return;
                };
                ui_section_translation(ui, section);
            }
            WizardStepPhase::Inputs => {
                let specs = current_section(wiz, *section_index)
                    .and_then(|s| s.inputs_spec.clone())
                    .unwrap_or_default();

                ui_section_inputs(ui, msg, input_buf, json_buf, wiz, &specs);
            }
        }
    }

    fn ui_review_build_impl(
        ui: &mut egui::Ui,
        msg: &mut PanelMsgState,
        bundle_out: &mut String,
        mode: &mut WizardPanelMode,
        wiz: &mut dw::WizardState,
        route: &mut Route,
        route_prefill: &mut Option<RoutePrefill>,
    ) {
        ui.heading("Review & Build");
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            if ui.button("Back").clicked() {
                *mode = WizardPanelMode::EditDocs;
                msg.clear();
            }

            let can_build = all_docs_have_no_template_errors(wiz);
            if ui
                .add_enabled(can_build, egui::Button::new("Build JSON Bundle"))
                .clicked()
            {
                match dw::build_json_bundle(wiz) {
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

            let can_sign_bundle = !bundle_out.trim().is_empty();
            if ui
                .add_enabled(can_sign_bundle, egui::Button::new("Sign Doc Bundle"))
                .clicked()
            {
                *route_prefill = Some(RoutePrefill::ToSign {
                    mode: SignVerifyMode::Json,
                    output_mode: SignOutputMode::Record,
                    message: bundle_out.trim().to_string(),
                });
                *route = Route::Sign;
            }
        });

        ui.add_space(6.0);

        if !all_docs_have_no_template_errors(wiz) {
            ui.group(|ui| {
                ui.label(egui::RichText::new("Cannot build: template has hard failures.").strong());
                ui.label("Go back and review the template problems.");
            });
            ui.add_space(6.0);
        }

        for (i, d) in wiz.docs.iter().enumerate() {
            let title = format!(
                "Doc {}/{} — {}",
                i + 1,
                wiz.docs.len(),
                d.doc_identity.label
            );
            egui::CollapsingHeader::new(title)
                .default_open(false)
                .show(ui, |ui| {
                    if !d.template_errors.is_empty() {
                        ui.label("Template problems (must fix):");
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

        ui.separator();
        ui.add_space(6.0);

        if ui.button("Copy Raw Document Text to Clipboard").clicked() {
            match wiz.docs.get(wiz.doc_index) {
                Some(d) => {
                    let raw = sigillium_personal_signer_verifier_lib::template::doc_wizard_verify::canonical_doc_text_from_sections(
                d.sections.iter().map(|s| s.text.as_str()),
            );
                    ui.ctx().copy_text(raw);
                    msg.set_success("Copied raw document text to clipboard.");
                }
                None => {
                    msg.set_warn("No current document is selected.");
                }
            }
        }
    }
}

fn phase_label(p: WizardStepPhase) -> &'static str {
    match p {
        WizardStepPhase::About => "About",
        WizardStepPhase::Text => "Text",
        WizardStepPhase::Translation => "Translation",
        WizardStepPhase::Inputs => "Inputs",
    }
}

fn all_docs_have_no_template_errors(wiz: &dw::WizardState) -> bool {
    wiz.docs.iter().all(|d| d.template_errors.is_empty())
}

fn current_section<'a>(
    wiz: &'a dw::WizardState,
    section_index: usize,
) -> Option<&'a sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate> {
    wiz.docs
        .get(wiz.doc_index)
        .and_then(|d| d.sections.get(section_index))
}

fn section_has_translation(
    s: &sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate,
) -> bool {
    s.translation
        .as_ref()
        .map(|t| !t.text.trim().is_empty())
        .unwrap_or(false)
}

fn section_has_inputs(
    s: &sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate,
) -> bool {
    s.inputs_spec
        .as_ref()
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}
fn step_next(
    wiz: &mut dw::WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), dw::WizardError> {
    // About step: just move into the normal section flow (or skip doc if no sections).
    if matches!(*phase, WizardStepPhase::About) {
        let has_sections = wiz
            .docs
            .get(wiz.doc_index)
            .map(|d| !d.sections.is_empty())
            .unwrap_or(false);

        if has_sections {
            *phase = WizardStepPhase::Text;
        } else {
            // edge case: doc has about but no sections
            advance_to_next_section_or_doc(wiz, section_index, phase)?;
        }
        return Ok(());
    }

    // From here on, we can safely immutably borrow doc/section.
    let Some(doc) = wiz.docs.get(wiz.doc_index) else {
        return Ok(());
    };

    let Some(sec) = doc.sections.get(*section_index) else {
        return Ok(());
    };

    match *phase {
        WizardStepPhase::Text => {
            if section_has_translation(sec) {
                *phase = WizardStepPhase::Translation;
            } else if section_has_inputs(sec) {
                *phase = WizardStepPhase::Inputs;
            } else {
                // no translation + no inputs: advance section/doc
                advance_to_next_section_or_doc(wiz, section_index, phase)?;
            }
        }
        WizardStepPhase::Translation => {
            if section_has_inputs(sec) {
                *phase = WizardStepPhase::Inputs;
            } else {
                advance_to_next_section_or_doc(wiz, section_index, phase)?;
            }
        }
        WizardStepPhase::Inputs => {
            advance_to_next_section_or_doc(wiz, section_index, phase)?;
        }

        // Should be unreachable because About returns above, but keeps match exhaustive and future-proof.
        WizardStepPhase::About => {}
    }

    Ok(())
}

fn advance_to_next_section_or_doc(
    wiz: &mut dw::WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), dw::WizardError> {
    let doc_section_count = wiz
        .docs
        .get(wiz.doc_index)
        .map(|d| d.sections.len())
        .unwrap_or(0);

    if doc_section_count > 0 && *section_index + 1 < doc_section_count {
        *section_index += 1;
        *phase = WizardStepPhase::Text;
        return Ok(());
    }

    // next doc
    if wiz.doc_index + 1 < wiz.docs.len() {
        dw::advance_doc(wiz)?;
        *section_index = 0;
        *phase = if doc_has_about(wiz) {
            WizardStepPhase::About
        } else {
            WizardStepPhase::Text
        };
    }

    Ok(())
}

fn step_back(
    wiz: &mut dw::WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), dw::WizardError> {
    // About step: back to previous doc end (or no-op if already at first doc).
    if matches!(*phase, WizardStepPhase::About) {
        back_to_prev_section_or_doc(wiz, section_index, phase)?;
        return Ok(());
    }

    // If we're at the first section text and this doc has About, go back to About.
    if matches!(*phase, WizardStepPhase::Text) && *section_index == 0 && doc_has_about(wiz) {
        *phase = WizardStepPhase::About;
        return Ok(());
    }

    // From here on, only Translation/Inputs need to look at the current section.
    let Some(doc) = wiz.docs.get(wiz.doc_index) else {
        return Ok(());
    };
    let Some(sec) = doc.sections.get(*section_index) else {
        return Ok(());
    };

    match *phase {
        WizardStepPhase::Inputs => {
            if section_has_translation(sec) {
                *phase = WizardStepPhase::Translation;
            } else {
                *phase = WizardStepPhase::Text;
            }
        }
        WizardStepPhase::Translation => {
            *phase = WizardStepPhase::Text;
        }
        WizardStepPhase::Text => {
            back_to_prev_section_or_doc(wiz, section_index, phase)?;
        }

        // Unreachable due to early return above, but keeps the match exhaustive.
        WizardStepPhase::About => {}
    }

    Ok(())
}

fn back_to_prev_section_or_doc(
    wiz: &mut dw::WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), dw::WizardError> {
    if *section_index > 0 {
        *section_index -= 1;
        set_phase_to_last_step_in_section(wiz, *section_index, phase);
        return Ok(());
    }

    if wiz.doc_index > 0 {
        dw::back_doc(wiz)?;
        let sc = wiz
            .docs
            .get(wiz.doc_index)
            .map(|d| d.sections.len())
            .unwrap_or(0);
        *section_index = sc.saturating_sub(1);
        set_phase_to_last_step_in_section(wiz, *section_index, phase);
    }

    Ok(())
}

fn set_phase_to_last_step_in_section(
    wiz: &dw::WizardState,
    section_index: usize,
    phase: &mut WizardStepPhase,
) {
    let Some(sec) = current_section(wiz, section_index) else {
        *phase = WizardStepPhase::Text;
        return;
    };

    if section_has_inputs(sec) {
        *phase = WizardStepPhase::Inputs;
    } else if section_has_translation(sec) {
        *phase = WizardStepPhase::Translation;
    } else {
        *phase = WizardStepPhase::Text;
    }
}

fn is_last_step(wiz: &dw::WizardState, section_index: usize, phase: WizardStepPhase) -> bool {
    let doc_count = wiz.docs.len();
    let doc_index = wiz.doc_index;
    let Some(doc) = wiz.docs.get(doc_index) else {
        return true;
    };

    // About is never the last step if there are any sections.
    if matches!(phase, WizardStepPhase::About) {
        return doc.sections.is_empty() && (doc_index + 1 >= doc_count);
    }

    let section_count = doc.sections.len();
    let Some(sec) = doc.sections.get(section_index) else {
        return true;
    };

    // Determine whether there is any step after the current one.
    match phase {
        WizardStepPhase::Text => {
            if section_has_translation(sec) {
                return false;
            }
            if section_has_inputs(sec) {
                return false;
            }
            // no translation/inputs -> next section/doc
        }
        WizardStepPhase::Translation => {
            if section_has_inputs(sec) {
                return false;
            }
            // otherwise next section/doc
        }
        WizardStepPhase::Inputs => {
            // always next section/doc
        }

        // Already handled above, but keeps the match exhaustive.
        WizardStepPhase::About => return doc.sections.is_empty() && (doc_index + 1 >= doc_count),
    }

    if section_index + 1 < section_count {
        return false;
    }

    doc_index + 1 >= doc_count
}

fn ui_doc_text_window(ui: &mut egui::Ui, text: &mut String) {
    // Expand with window: width directly; height approximated via rows.
    let avail = ui.available_size();
    let w = avail.x.max(300.0);

    // Roughly: one text row ~= one line height.
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace).max(1.0);
    let target_h = avail.y.max(260.0);
    let rows = ((target_h / row_h).floor() as usize).max(10);

    ui.add(
        egui::TextEdit::multiline(text)
            .desired_width(w)
            .desired_rows(rows)
            .font(egui::TextStyle::Monospace)
            .interactive(false),
    );
}

fn ui_section_text(
    ui: &mut egui::Ui,
    s: &sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate,
) {
    let title = s
        .title
        .as_ref()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .unwrap_or("Section");

    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).strong().size(18.0));
            ui.add_space(6.0);

            let mut text = s.text.clone();
            ui_doc_text_window(ui, &mut text);
        });
}

fn ui_section_translation(
    ui: &mut egui::Ui,
    s: &sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate,
) {
    let Some(t) = s.translation.as_ref() else {
        ui.label("(No translation.)");
        return;
    };

    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Translation (non-authoritative)")
                    .strong()
                    .size(18.0),
            );
            ui.add_space(4.0);
            crate::ui::widgets::ui_notice(
                ui,
                "This translation is provided as a convenience, but only the actual document text is signed and is therefore canonical.

Please confirm the translation yourself or rely on someone you trust who has already done so.",
            );
            ui.add_space(6.0);
            ui.label(format!("Language: {}", t.lang));
            ui.add_space(6.0);

            let mut text = t.text.clone();
            ui_doc_text_window(ui, &mut text);
        });
}

fn ui_section_inputs(
    ui: &mut egui::Ui,
    msg: &mut PanelMsgState,
    input_buf: &mut BTreeMap<String, String>,
    json_buf: &mut BTreeMap<String, String>,
    wiz: &mut dw::WizardState,
    specs: &[InputSpec],
) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Inputs").strong().size(18.0));
        ui.add_space(6.0);

        if specs.is_empty() {
            ui.label("(No inputs for this section.)");
            return;
        }

        for spec in specs.iter().cloned() {
            let key = spec.key.clone();
            // existing per-input UI logic continues here

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
                            if let Err(e) = dw::set_input_value_current_doc(
                                wiz,
                                &key,
                                JsonValue::String(buf.clone()),
                            ) {
                                msg.set_warn(&format!("{e}"));
                            }
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
                                        if let Err(e) = dw::set_input_value_current_doc(
                                            wiz,
                                            &key,
                                            JsonValue::String(c.clone()),
                                        ) {
                                            msg.set_warn(&format!("{e}"));
                                        }
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
                                // allow clearing in UI buffer (value remains until policy changes)
                            } else if let Ok(x) = s.parse::<f64>() {
                                if let Some(n) = serde_json::Number::from_f64(x) {
                                    if let Err(e) =
                                        dw::set_input_value_current_doc(wiz, &key, n.into())
                                    {
                                        msg.set_warn(&format!("{e}"));
                                    }
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
                                // allow clearing in UI buffer (value remains until policy changes)
                            } else if let Ok(x) = s.parse::<i64>() {
                                if let Err(e) = dw::set_input_value_current_doc(
                                    wiz,
                                    &key,
                                    JsonValue::Number(x.into()),
                                ) {
                                    msg.set_warn(&format!("{e}"));
                                }
                            }
                        }
                    }

                    InputType::Bool => {
                        let cur = current_value_bool(wiz, &key);
                        let mut v = cur;

                        if ui.checkbox(&mut v, "true/false").changed() {
                            if let Err(e) = dw::set_input_value_current_doc(wiz, &key, v.into()) {
                                msg.set_warn(&format!("{e}"));
                            }
                        }
                    }

                    InputType::Json => {
                        let buf = json_buf
                            .entry(key.clone())
                            .or_insert_with(|| current_value_json_pretty(wiz, &key));

                        if let Some(sample) = spec.sample_json.as_ref() {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label("Input JSON");
                                    let resp = ui.add(
                                        egui::TextEdit::multiline(buf)
                                            .desired_rows(8)
                                            .code_editor(),
                                    );

                                    if resp.changed() {
                                        let s = buf.trim();
                                        if s.is_empty() {
                                            // Treat empty as "clear"
                                            if let Err(e) = dw::set_input_value_current_doc(
                                                wiz,
                                                &key,
                                                JsonValue::Null,
                                            ) {
                                                msg.set_warn(&format!("{e}"));
                                            }
                                        } else {
                                            match dw::set_input_json_from_str_current_doc(
                                                wiz, &key, buf,
                                            ) {
                                                Ok(()) => msg.clear(),
                                                Err(e) => msg.set_warn(&format!("{e}")),
                                            }
                                        }
                                    }
                                });

                                ui.add_space(12.0);

                                ui.vertical(|ui| {
                                    ui.label("Sample JSON");
                                    let mut sample_pretty = serde_json::to_string_pretty(sample)
                                        .unwrap_or_else(|_| sample.to_string());

                                    ui.add(
                                        egui::TextEdit::multiline(&mut sample_pretty)
                                            .desired_rows(8)
                                            .code_editor()
                                            .interactive(false),
                                    );
                                });
                            });
                        } else {
                            let resp = ui
                                .add(egui::TextEdit::multiline(buf).desired_rows(8).code_editor());

                            if resp.changed() {
                                let s = buf.trim();
                                if s.is_empty() {
                                    // Treat empty as "clear"
                                    if let Err(e) =
                                        dw::set_input_value_current_doc(wiz, &key, JsonValue::Null)
                                    {
                                        msg.set_warn(&format!("{e}"));
                                    }
                                } else {
                                    match dw::set_input_json_from_str_current_doc(wiz, &key, buf) {
                                        Ok(()) => msg.clear(),
                                        Err(e) => msg.set_warn(&format!("{e}")),
                                    }
                                }
                            }
                        }
                    }
                }
            });

            ui.add_space(6.0);
        }

        ui.separator();

        if ui.button("Validate Section").clicked() {
            match validate_current_section_inputs(wiz, specs) {
                Ok(()) => msg.set_success("Section validation OK"),
                Err(e) => msg.set_warn(&e),
            }
        }
    });
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

fn doc_has_about(wiz: &dw::WizardState) -> bool {
    wiz.docs
        .get(wiz.doc_index)
        .and_then(|d| d.doc_about.as_ref())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn current_doc_about(wiz: &dw::WizardState) -> Option<&str> {
    wiz.docs
        .get(wiz.doc_index)
        .and_then(|d| d.doc_about.as_deref())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}
