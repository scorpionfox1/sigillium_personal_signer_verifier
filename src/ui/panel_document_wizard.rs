// src/ui/panel_document_wizard.rs

use crate::ui::message::PanelMsgState;
use crate::ui::widgets;
use eframe::egui;
use serde_json::Value as JsonValue;
use sigillium_personal_signer_verifier_lib::context::AppCtx;
use sigillium_personal_signer_verifier_lib::types::{AppState, SignOutputMode, SignVerifyMode};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Route, RoutePrefill};

use sigillium_personal_signer_verifier_lib::command::document_wizard::{
    self as dw, all_docs_have_no_template_errors, current_doc_about, doc_has_about, is_last_step,
    step_back, step_next, validate_current_section_inputs, WizardStepPhase,
};
use sigillium_personal_signer_verifier_lib::template::doc_wizard::{InputSpec, InputType};
use sigillium_personal_signer_verifier_lib::template::doc_wizard_verify::canonical_doc_text_from_sections;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WizardPanelMode {
    EditDocs,
    ReviewBuild,
}

pub struct DocumentWizardPanel {
    msg: PanelMsgState,

    template_path: Option<PathBuf>,
    wizard: Option<dw::WizardState>,

    mode: WizardPanelMode,

    // UI-owned navigation state.
    section_index: usize,
    phase: dw::WizardStepPhase,

    // raw text buffers for inputs that are edited as text
    input_buf: BTreeMap<String, String>,

    // raw JSON buffers for json-type inputs
    json_buf: BTreeMap<String, String>,

    bundle_out: String,
    bundle_build_attempted: bool,
}

impl DocumentWizardPanel {
    pub fn new() -> Self {
        Self {
            msg: PanelMsgState::default(),
            template_path: None,
            wizard: None,
            mode: WizardPanelMode::EditDocs,
            section_index: 0,
            phase: dw::WizardStepPhase::Text,
            input_buf: BTreeMap::new(),
            json_buf: BTreeMap::new(),
            bundle_out: String::new(),
            bundle_build_attempted: false,
        }
    }

    pub fn reset_inputs(&mut self) {
        self.template_path = None;
        self.wizard = None;
        self.mode = WizardPanelMode::EditDocs;
        self.section_index = 0;
        self.phase = dw::WizardStepPhase::Text;
        self.input_buf.clear();
        self.json_buf.clear();
        self.bundle_out.clear();
        self.bundle_build_attempted = false;
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
        widgets::panel_title(ui, "Document wizard");
        ui.separator();
        ui.add_space(6.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                self.ui_template_picker(ui);

                if let Some(wiz) = self.wizard.as_ref() {
                    let doc_count = wiz.docs.len();
                    let doc_index = wiz.doc_index;
                    let section_count = wiz
                        .docs
                        .get(doc_index)
                        .map(|d| d.sections.len())
                        .unwrap_or(0);

                    let section_num = match self.phase {
                        WizardStepPhase::About => 0,
                        _ => self.section_index.saturating_add(1),
                    };

                    ui.label(format!(
                        "Doc {} of {} — Section {} of {}",
                        doc_index.saturating_add(1),
                        doc_count.max(1),
                        section_num,
                        section_count,
                    ));
                    ui.add_space(6.0);
                }

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
                let bundle_build_attempted = &mut self.bundle_build_attempted;
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
                            bundle_build_attempted,
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
                            bundle_build_attempted,
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
                            self.bundle_build_attempted = false;
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
        bundle_build_attempted: &mut bool,
        mode: &mut WizardPanelMode,
        section_index: &mut usize,
        phase: &mut WizardStepPhase,
        wiz: &mut dw::WizardState,
    ) {
        bundle_out.clear();
        *bundle_build_attempted = false;

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

        // Navigation state (buttons rendered below the current screen).
        let can_back = match *phase {
            WizardStepPhase::About => wiz.doc_index > 0,
            WizardStepPhase::Text => wiz.doc_index > 0 || *section_index > 0 || doc_has_about(wiz),
            WizardStepPhase::Translation | WizardStepPhase::Inputs => true,
        };

        let at_last = is_last_step(wiz, *section_index, *phase);
        let can_next = if at_last {
            all_docs_have_no_template_errors(wiz)
        } else {
            true
        };

        ui.add_space(8.0);

        // Current doc diagnostics: failures (hard) and warnings.
        if let Ok(d) = dw::current_doc(wiz) {
            if !d.template_errors.is_empty() {
                ui.group(|ui| {
                    widgets::section_header(ui, "Template problems (must fix)");
                    for e in d.template_errors.iter() {
                        ui.label(format!("- {e}"));
                    }
                });
                ui.add_space(8.0);
            }

            if !d.template_warnings.is_empty() {
                ui.group(|ui| {
                    widgets::section_header(ui, "Template warnings");
                    for w in d.template_warnings.iter() {
                        ui.label(format!("- {w}"));
                    }
                });
                ui.add_space(8.0);
            }
        }

        let mut markdown_preview: Option<MarkdownPreview> = None;

        // Centerpiece: section text / translation / inputs.
        match *phase {
            WizardStepPhase::About => {
                let Some(about) = current_doc_about(wiz) else {
                    *phase = WizardStepPhase::Text;
                    return;
                };

                markdown_preview = Some(MarkdownPreview {
                    title: "About this Document".to_string(),
                    body: about.to_string(),
                });

                ui_doc_screen_skeleton_notice_above_header(
                    ui,
                    "About this Document",
                    "This section contains context information about the document you are about to read. It is provided to help orient you, but understand it is not signed. Only the actual document text is hashed and signed.

 i.e. only the document text itself is canonical.",
                    |ui| {
                        let mut text = about.to_string();
                        ui_doc_text_window(ui, &mut text);
                    },
                );
            }

            WizardStepPhase::Text => {
                let Ok(section) = dw::current_section(wiz, *section_index) else {
                    ui.label("(No section.)");
                    return;
                };
                markdown_preview = Some(MarkdownPreview {
                    title: format!("{} (section)", doc_label),
                    body: section.text.clone(),
                });
                ui_section_text(ui, &doc_label, section);
            }
            WizardStepPhase::Translation => {
                let Ok(section) = dw::current_section(wiz, *section_index) else {
                    ui.label("(No section.)");
                    return;
                };
                if let Some(translation) = section.translation.as_ref() {
                    markdown_preview = Some(MarkdownPreview {
                        title: format!("{} (translation)", doc_label),
                        body: translation.text.clone(),
                    });
                }
                ui_section_translation(ui, &doc_label, section);
            }
            WizardStepPhase::Inputs => {
                let specs = dw::current_section(wiz, *section_index)
                    .ok()
                    .and_then(|s| s.inputs_spec.clone())
                    .unwrap_or_default();

                ui_doc_screen_skeleton(ui, Some(doc_label.as_str()), |ui| {
                    ui_section_inputs(ui, msg, input_buf, json_buf, wiz, &specs);
                });
            }
        }
        ui.add_space(12.0);

        // Navigation (placed below the current screen content).
        ui_doc_screen_skeleton(ui, None, |ui| {
            let button_height = 34.0;
            let next_w = 120.0;
            let back_w = 110.0;

            ui.horizontal(|ui| {
                // Back on the left.
                let back_btn =
                    widgets::large_button("← Back").min_size(egui::vec2(back_w, button_height));

                if ui.add_enabled(can_back, back_btn).clicked() {
                    if let Err(e) = step_back(wiz, section_index, phase) {
                        msg.set_warn(&format!("{e}"));
                    } else {
                        msg.clear();
                    }
                }

                let preview_btn = widgets::large_button("View in Browser")
                    .min_size(egui::vec2(150.0, button_height));
                if ui
                    .add_enabled(markdown_preview.is_some(), preview_btn)
                    .clicked()
                {
                    if let Some(preview) = markdown_preview.as_ref() {
                        open_markdown_preview(preview, msg);
                    }
                }

                // Next on the right, same baseline and height.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let next_btn =
                        widgets::large_button("Next →").min_size(egui::vec2(next_w, button_height));

                    if ui.add_enabled(can_next, next_btn).clicked() {
                        if *phase == WizardStepPhase::Inputs {
                            let specs = dw::current_section(wiz, *section_index)
                                .ok()
                                .and_then(|s| s.inputs_spec.clone())
                                .unwrap_or_default();

                            let mut errors = sync_json_buffers_for_specs(wiz, &specs, json_buf);
                            if let Err(e) = validate_current_section_inputs(wiz, &specs) {
                                errors.extend(e.lines().map(|line| line.to_string()));
                            }
                            if !errors.is_empty() {
                                msg.set_warn(&errors.join("\n"));

                                return;
                            }
                        }

                        if at_last {
                            bundle_out.clear();
                            *bundle_build_attempted = false;
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
        });
    }

    fn ui_review_build_impl(
        ui: &mut egui::Ui,
        msg: &mut PanelMsgState,
        bundle_out: &mut String,
        bundle_build_attempted: &mut bool,
        mode: &mut WizardPanelMode,
        wiz: &mut dw::WizardState,
        route: &mut Route,
        route_prefill: &mut Option<RoutePrefill>,
    ) {
        ui.heading("Review Document Bundle & Sign");
        ui.add_space(6.0);

        let can_build = all_docs_have_no_template_errors(wiz);
        if can_build && bundle_out.trim().is_empty() && !*bundle_build_attempted {
            *bundle_build_attempted = true;
            match dw::build_doc_bundle(wiz) {
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

        // This panel should be unreachable when there are template failures, but keep a defensive guard.
        if !can_build {
            ui.group(|ui| {
                widgets::section_header(ui, "Cannot build: template has hard failures.");
                ui.label("Go back and review the template problems.");
            });
            ui.add_space(6.0);

            if ui.button("Back").clicked() {
                *mode = WizardPanelMode::EditDocs;
                bundle_out.clear();
                *bundle_build_attempted = false;
                msg.clear();
            }
            return;
        }

        // Explanatory text (kept near the main header; constrained width so it doesn't run edge-to-edge).
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                let w = ui.available_width().min(950.0);
                ui.set_max_width(w);

                ui.label("The document bundle below represents one or more documents.");
                ui.label("It includes, for each document: (1) the raw document text hash, (2) the collected inputs, and (3) tags that will be replaced at signing time.");
                ui.label("Those signing-time tags will be replaced with the signing UTC datetime and the associated key id for the key you sign with.");
            },
        );

        ui.add_space(18.0);
        ui.separator();

        let gap = 16.0_f32;
        let avail = ui.available_width().max(1.0);

        // Keep the hash column readable even on narrow windows.
        let right_w = (avail * 0.42).clamp(280.0, 520.0);
        let left_w = (avail - gap - right_w).max(280.0);

        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(left_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.horizontal(|ui| {
                        widgets::section_header(ui, "Document bundle");

                        let can_copy = !bundle_out.trim().is_empty();
                        widgets::copy_json_icon_button(
                            ui,
                            can_copy,
                            "Copy document bundle",
                            bundle_out.trim(),
                            msg,
                        );
                    });

                    ui.add_space(6.0);

                    ui.add(
                        egui::TextEdit::multiline(bundle_out)
                            .desired_rows(12)
                            .code_editor()
                            .lock_focus(true),
                    );
                },
            );

            ui.add_space(gap);

            ui.allocate_ui_with_layout(
                egui::vec2(right_w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    widgets::section_header(ui, "Document hashes & raw text");
                    ui.add_space(6.0);

                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            for (i, d) in wiz.docs.iter().enumerate() {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label("•");
                                    ui.label(format!("Computed hash: {}", d.computed_hash_hex));
                                    ui.label("for doc");

                                    let link = ui.link(&d.doc_identity.label);
                                    if link.clicked() {
                                        let filename =
                                            default_raw_text_filename(i, &d.doc_identity.label);
                                        let canonical_text = doc_raw_text(d);
                                        if let Some(path) = rfd::FileDialog::new()
                                            .set_file_name(&filename)
                                            .save_file()
                                        {
                                            match std::fs::write(&path, canonical_text) {
                                                Ok(()) => msg.set_success(&format!(
                                                    "Saved raw document text to {}",
                                                    path.display()
                                                )),
                                                Err(e) => msg.set_warn(&format!(
                                                    "Failed to save raw document text: {e}"
                                                )),
                                            }
                                        }
                                    }
                                });
                                ui.add_space(4.0);
                            }
                        });
                },
            );
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.button("Back").clicked() {
                *mode = WizardPanelMode::EditDocs;
                bundle_out.clear();
                *bundle_build_attempted = false;
                msg.clear();
            }

            let can_sign_bundle = !bundle_out.trim().is_empty();
            if ui
                .add_enabled(
                    can_sign_bundle,
                    egui::Button::new(egui::RichText::new("Sign Document Bundle").strong()),
                )
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
    }
}

const DOC_PANEL_MAX_WIDTH: f32 = 900.0;

fn ui_doc_screen_skeleton_with_max_width(
    ui: &mut egui::Ui,
    header: Option<&str>,
    max_width: f32,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui.vertical_centered(|ui| {
        let w = ui.available_width().min(max_width);
        ui.set_width(w);

        // Intentionally no border: keep it boring and clean.
        egui::Frame::NONE
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                if let Some(h) = header {
                    widgets::screen_header(ui, h);
                    ui.add_space(6.0);
                }
                body(ui);
            });
    });
}

fn ui_doc_screen_skeleton(
    ui: &mut egui::Ui,
    header: Option<&str>,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui_doc_screen_skeleton_with_max_width(ui, header, DOC_PANEL_MAX_WIDTH, body);
}

fn doc_raw_text(doc: &dw::DocRunState) -> String {
    canonical_doc_text_from_sections(doc.sections.iter().map(|section| section.text.as_str()))
}

fn default_raw_text_filename(index: usize, label: &str) -> String {
    let mut slug = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_whitespace() || ch == '-' || ch == '_' {
            slug.push('_');
        }
    }

    let slug = slug.trim_matches('_');
    if slug.is_empty() {
        format!("raw-document-text-{}.txt", index + 1)
    } else {
        format!("raw-document-text-{}-{}.txt", index + 1, slug)
    }
}

struct MarkdownPreview {
    title: String,
    body: String,
}

fn open_markdown_preview(preview: &MarkdownPreview, msg: &mut PanelMsgState) {
    let html = markdown_preview_to_html(preview);
    let filename = temp_markdown_filename();
    let path = std::env::temp_dir().join(filename);

    if let Err(e) = std::fs::write(&path, html) {
        msg.set_warn(&format!("Failed to write preview HTML: {e}"));
        return;
    }

    let Some(path_str) = path.to_str() else {
        msg.set_warn("Failed to open preview: temp path is not valid UTF-8.");
        return;
    };

    if let Err(e) = webbrowser::open(path_str) {
        msg.set_warn(&format!("Failed to open preview in browser: {e}"));
        return;
    }

    msg.set_success(&format!("Opened preview in browser: {}", path.display()));
}

fn markdown_preview_to_html(preview: &MarkdownPreview) -> String {
    use pulldown_cmark::{html, Options, Parser};

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_SMART_PUNCTUATION);

    let parser = Parser::new_ext(&preview.body, options);
    let mut body_html = String::new();
    html::push_html(&mut body_html, parser);

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 24px; line-height: 1.5; }}
    pre, code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    pre {{ padding: 12px; background: #f4f4f4; overflow-x: auto; }}
    table {{ border-collapse: collapse; }}
    th, td {{ border: 1px solid #ccc; padding: 6px 10px; }}
  </style>
</head>
<body>
  <h1>{}</h1>
  {}
</body>
</html>
"#,
        escape_html(&preview.title),
        escape_html(&preview.title),
        body_html
    )
}

fn temp_markdown_filename() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("sigillium-docwizard-preview-{}.html", nanos)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn ui_doc_screen_skeleton_notice_above_header(
    ui: &mut egui::Ui,
    header: &str,
    notice: &str,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui_doc_screen_skeleton_with_max_width(ui, None, DOC_PANEL_MAX_WIDTH, |ui| {
        widgets::ui_notice(ui, notice, widgets::NoticeAlign::Center);
        ui.add_space(8.0);
        widgets::screen_header(ui, header);
        ui.add_space(6.0);
        body(ui);
    });
}

fn ui_doc_text_window(ui: &mut egui::Ui, code: &mut String) {
    // Size the box primarily from content, so short sections don't become giant empty panes.
    // Constrain height explicitly so it cannot expand to fill an unbounded parent (e.g. a ScrollArea).
    let line_count = code.lines().count().max(1);
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace).max(1.0);

    // Keep a small minimum for readability, but otherwise track content.
    let desired_rows = line_count.clamp(5, 40);
    let desired_h = row_h * desired_rows as f32;

    ui.add_sized(
        egui::vec2(ui.available_width(), desired_h),
        egui::TextEdit::multiline(code)
            .font(egui::TextStyle::Monospace)
            .interactive(false)
            .desired_rows(desired_rows),
    );
}

fn ui_section_text(
    ui: &mut egui::Ui,
    doc_label: &str,
    s: &sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate,
) {
    ui_doc_screen_skeleton(ui, Some(doc_label), |ui| {
        let mut text = s.text.clone();
        ui_doc_text_window(ui, &mut text);
    });
}

fn ui_section_translation(
    ui: &mut egui::Ui,
    doc_label: &str,
    s: &sigillium_personal_signer_verifier_lib::template::doc_wizard::SectionTemplate,
) {
    let Some(t) = s.translation.as_ref() else {
        ui.label("(No translation.)");
        return;
    };

    let header = format!("{} (translation)", doc_label);
    ui_doc_screen_skeleton_notice_above_header(ui, header.as_str(), "This translation is provided as a convenience, but only the actual document text is signed and is therefore canonical.

Please confirm the translation yourself or rely on someone you trust who has already done so.", |ui| {
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
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            widgets::section_header(ui, "Inputs");
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
                                if let Err(e) = dw::set_input_value_current_doc(wiz, &key, v.into())
                                {
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
                                        let _ = resp;
                                    });

                                    ui.add_space(12.0);

                                    ui.vertical(|ui| {
                                        ui.label("Sample JSON");
                                        let mut sample_pretty =
                                            serde_json::to_string_pretty(sample)
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
                                let resp = ui.add(
                                    egui::TextEdit::multiline(buf).desired_rows(8).code_editor(),
                                );

                                let _ = resp;
                            }
                        }
                    }
                });

                ui.add_space(6.0);
            }
        });
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

fn sync_json_buffers_for_specs(
    wiz: &mut dw::WizardState,
    specs: &[InputSpec],
    json_buf: &mut BTreeMap<String, String>,
) -> Vec<String> {
    let mut errors = Vec::new();

    for spec in specs {
        if !matches!(spec.input_type, InputType::Json) {
            continue;
        }

        let key = spec.key.clone();
        let buf = json_buf
            .entry(key.clone())
            .or_insert_with(|| current_value_json_pretty(wiz, &key));

        let s = buf.trim();
        if s.is_empty() {
            if let Err(e) = dw::set_input_value_current_doc(wiz, &key, JsonValue::Null) {
                errors.push(format!("{} ({}): {}", spec.label, key, e));
            }
            continue;
        }

        match serde_json::from_str::<JsonValue>(s) {
            Ok(v) => {
                if let Err(e) = dw::set_input_value_current_doc(wiz, &key, v) {
                    errors.push(format!("{} ({}): {}", spec.label, key, e));
                }
            }
            Err(e) => {
                errors.push(format!("{} ({}): invalid JSON: {}", spec.label, key, e));
            }
        }
    }
    errors
}
