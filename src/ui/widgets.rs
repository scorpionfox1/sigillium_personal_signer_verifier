// src/ui/widgets.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    notices::AppNotice,
    types::{AppState, KeyId, KeyMeta},
};
use std::time::{SystemTime, UNIX_EPOCH};

use super::message::PanelMsgState;

pub fn copy_icon_button(ui: &mut egui::Ui, enabled: bool, hover: &str) -> bool {
    ui.add_enabled(enabled, egui::Button::new("⧉"))
        .on_hover_text(hover)
        .clicked()
}

fn notify_string_copied(msg: &mut PanelMsgState) {
    msg.from_app_error(&AppNotice::StringCopied);
}

pub fn copy_value_with_button(
    ui: &mut egui::Ui,
    enabled: bool,
    hover: &str,
    value: &str,
    msg: &mut PanelMsgState,
) -> bool {
    if copy_icon_button(ui, enabled, hover) {
        ui.ctx().copy_text(value.to_string());
        notify_string_copied(msg);
        return true;
    }
    false
}

pub fn copy_json_icon_button(
    ui: &mut egui::Ui,
    enabled: bool,
    hover: &str,
    value: &str,
    msg: &mut PanelMsgState,
) -> bool {
    copy_value_with_button(ui, enabled, hover, value, msg)
}

pub const DOC_PANEL_MAX_WIDTH: f32 = 900.0;

const LARGE_BUTTON_TEXT_SIZE: f32 = 17.0;
const SECTION_HEADER_TEXT_SIZE: f32 = 16.0;
const SCREEN_HEADER_TEXT_SIZE: f32 = 19.0;

pub fn large_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label).size(LARGE_BUTTON_TEXT_SIZE))
}

pub fn section_header(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .strong()
            .size(SECTION_HEADER_TEXT_SIZE),
    );
}

pub fn screen_header(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .strong()
            .size(SCREEN_HEADER_TEXT_SIZE),
    );
}

pub fn panel_title(ui: &mut egui::Ui, label: &str) {
    let heading_size = ui
        .style()
        .text_styles
        .get(&egui::TextStyle::Heading)
        .map(|font_id| font_id.size)
        .unwrap_or(SCREEN_HEADER_TEXT_SIZE);

    ui.label(egui::RichText::new(label).strong().size(heading_size));
}

pub fn doc_panel_container(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
    doc_panel_container_with_header(ui, None, body);
}

pub fn doc_panel_container_with_header(
    ui: &mut egui::Ui,
    header: Option<&str>,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui.vertical_centered(|ui| {
        let w = ui.available_width().min(DOC_PANEL_MAX_WIDTH);
        ui.set_width(w);

        // Intentionally no border: keep it boring and clean.
        egui::Frame::NONE
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                if let Some(h) = header {
                    screen_header(ui, h);
                    ui.add_space(6.0);
                }
                body(ui);
            });
    });
}

pub fn copy_label_with_button(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    hover: &str,
    msg: &mut PanelMsgState,
) -> bool {
    let mut copied = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let ok = !value.trim().is_empty();
        if copy_value_with_button(ui, ok, hover, value, msg) {
            copied = true;
        }
    });
    copied
}

/// Standard Active Key selector used across panels.
/// - Shows None + installed keys.
/// - Selecting None clears active key.
/// - Selecting a key sets it active.
/// - Returns Err(String) if command layer rejects the change.
pub fn active_key_selector(
    ui: &mut egui::Ui,
    state: &AppState,
    ctx: &AppCtx,
    route: &mut super::Route,
    id_salt: &'static str,
    metas: &[KeyMeta],
) -> Result<Option<KeyId>, AppNotice> {
    let current_active_id: Option<KeyId> = lock_session(state).ok().and_then(|g| g.active_key_id);

    let mut choice: Option<KeyId> = current_active_id;

    let selected_text = match choice.and_then(|id| metas.iter().find(|k| k.id == id)) {
        Some(k) => format!("{} ({})", k.label.as_str(), k.domain),
        None => "None".to_string(),
    };

    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            let row_height = ui.spacing().interact_size.y;
            let max_rows = 5.0;

            egui::ScrollArea::vertical()
                .max_height(row_height * max_rows)
                .show(ui, |ui| {
                    ui.selectable_value(&mut choice, None, "None");
                    ui.separator();

                    for k in metas.iter() {
                        ui.selectable_value(
                            &mut choice,
                            Some(k.id),
                            format!("{} ({})", k.label.as_str(), k.domain),
                        );
                    }
                });
        });

    if choice != current_active_id {
        match choice {
            Some(id) => {
                let res = command::select_active_key(id, state, ctx);

                // If select failed due to quarantine/missing, clear active key and route to KeyfileSelect.
                if matches!(
                    res,
                    Err(AppNotice::KeyfileQuarantined { .. } | AppNotice::KeyfileMissing { .. })
                ) {
                    let _ = command::clear_active_key(state);
                    *route = super::Route::KeyfileSelect;
                }

                res.map(|_| Some(id)).map_err(|e| e)
            }

            None => command::clear_active_key(state)
                .map(|_| None)
                .map_err(|e| e),
        }
    } else {
        Ok(choice)
    }
}

fn ui_notice_inner(ui: &mut egui::Ui, body: &str) {
    // Intentionally bright "attention" yellow (not red, not muted).
    // Works in both dark and light mode.
    let accent = egui::Color32::from_rgb(255, 215, 90);

    // Strong border + noticeable (but not obnoxious) tint.
    let stroke = egui::Stroke::new(1.5, accent);
    let fill = egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 48);

    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12))
        .stroke(stroke)
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(8))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Notice")
                    .size(18.0)
                    .strong()
                    .color(accent),
            );
            ui.add_space(4.0);
            ui.label(body);
        });
}

const NOTICE_MAX_WIDTH: f32 = 640.0;

pub enum NoticeAlign {
    Left,
    Center,
}

pub fn ui_notice(ui: &mut egui::Ui, body: &str, align: NoticeAlign) {
    let available_width = ui.available_width();
    let width = available_width.min(NOTICE_MAX_WIDTH);

    match align {
        NoticeAlign::Left => {
            ui.scope(|ui| {
                ui.set_max_width(width);
                ui_notice_inner(ui, body);
            });
        }
        NoticeAlign::Center => {
            ui.allocate_ui_with_layout(
                egui::vec2(available_width, 0.0),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    ui.set_max_width(width);
                    ui_notice_inner(ui, body);
                },
            );
        }
    }
}

pub fn open_markdown_preview(title: &str, body: &str, msg: &mut PanelMsgState) {
    let html = markdown_preview_to_html(title, body);
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

fn markdown_preview_to_html(title: &str, body: &str) -> String {
    use pulldown_cmark::{html, Options, Parser};

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_SMART_PUNCTUATION);

    let parser = Parser::new_ext(body, options);
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
        escape_html(title),
        escape_html(title),
        body_html
    )
}

fn temp_markdown_filename() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("sigillium-preview-{}.html", nanos)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
