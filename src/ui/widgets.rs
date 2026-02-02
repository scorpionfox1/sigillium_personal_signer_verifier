// src/ui/widgets.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    error::AppError,
    types::{AppState, KeyId, KeyMeta},
};

pub fn copy_icon_button(ui: &mut egui::Ui, enabled: bool, hover: &str) -> bool {
    ui.add_enabled(enabled, egui::Button::new("⧉"))
        .on_hover_text(hover)
        .clicked()
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
) -> Result<Option<KeyId>, AppError> {
    let current_active_id: Option<KeyId> = lock_session(state).ok().and_then(|g| g.active_key_id);

    let mut choice: Option<KeyId> = current_active_id;

    let selected_text = match choice.and_then(|id| metas.iter().find(|k| k.id == id)) {
        Some(k) => format!("{} ({})", k.label, k.domain),
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
                            format!("{} ({})", k.label, k.domain),
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
                    Err(AppError::KeyfileQuarantined { .. } | AppError::KeyfileMissing { .. })
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

pub fn ui_notice(ui: &mut egui::Ui, body: &str) {
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
