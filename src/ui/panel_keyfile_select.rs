// src/ui/panel_keyfile_select.rs

use super::message::PanelMsgState;
use super::Route;
use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command::session::select_keyfile_dir,
    context::AppCtx,
    error::AppError,
    keyfile_store::{KeyfileDirRow, KeyfileStore},
    types::{AppState, KeyfileState},
};

pub struct KeyfileSelectPanel {
    msg: PanelMsgState,
    keyfiles: Vec<KeyfileDirRow>,
    selected: Option<String>,
    loaded: bool,
}

impl KeyfileSelectPanel {
    pub fn new() -> Self {
        Self {
            msg: PanelMsgState::default(),
            keyfiles: Vec::new(),
            selected: None,
            loaded: false,
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.selected = None;
        self.loaded = false;
        self.keyfiles.clear();
    }

    // Called by the UI router when the command layer quarantines a keyfile directory.
    pub fn set_quarantined_message(&mut self, dir_name: &str) {
        self.msg.set_warn(&format!(
            "Keyfile '{dir_name}' was quarantined due to corruption/tampering. Select another keyfile or create a new one."
        ));
    }

    // Called by the UI router when we land on this panel.
    pub fn refresh_on_enter(&mut self, ctx: &AppCtx) {
        self.refresh_list(ctx);
    }

    fn refresh_list(&mut self, ctx: &AppCtx) {
        let store = KeyfileStore::new(ctx.keyfiles_root());
        match store.list_keyfile_dirs() {
            Ok(list) => {
                self.keyfiles = list;

                // Preserve selection only if it still exists and is selectable.
                let keep = self.selected.as_deref().is_some_and(|sel| {
                    self.keyfiles
                        .iter()
                        .any(|row| row.has_keyfile && row.name == sel)
                });
                if !keep {
                    self.selected = None;
                }

                self.loaded = true;
            }
            Err(e) => {
                self.msg.set_warn(&format!("Failed to list keyfiles: {e}"));
                self.keyfiles.clear();
                self.selected = None;
                self.loaded = true;
            }
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        ctx: &AppCtx,
        route: &mut Route,
        return_route: &mut Option<Route>,
    ) {
        ui.heading("Select keyfile");
        ui.separator();

        if !self.loaded {
            self.refresh_list(ctx);
        }

        ui.add_space(12.0);

        if self.keyfiles.is_empty() {
            ui.label("No keyfiles found.");
            ui.label("Create a new keyfile to continue.");
            ui.add_space(12.0);
        } else {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(260.0)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    let mut picked: Option<String> = None;

                    for row in self.keyfiles.iter() {
                        let label = if row.has_keyfile {
                            row.name.clone()
                        } else {
                            format!("{} (no keyfile)", row.name)
                        };

                        let is_selected = self.selected.as_deref() == Some(row.name.as_str());

                        let resp = ui.add_enabled(
                            row.has_keyfile,
                            egui::Button::new(label).selected(is_selected),
                        );

                        if resp.clicked() && row.has_keyfile {
                            picked = Some(row.name.clone());
                        }
                    }

                    if let Some(name) = picked {
                        self.clear_messages();
                        self.selected = Some(name);
                    }
                });

            ui.add_space(12.0);
        }

        let can_select = self.selected.is_some();

        if ui
            .add_enabled(can_select, egui::Button::new("Select"))
            .clicked()
        {
            self.clear_messages();

            let Some(name) = self.selected.clone() else {
                self.msg.set_warn("Select a keyfile first.");
                return;
            };

            // Set selection in context
            match select_keyfile_dir(state, ctx, &name) {
                Ok(KeyfileState::NotCorrupted) => {
                    *return_route = Some(Route::Sign);
                    *route = Route::Locked;
                }

                Ok(KeyfileState::Missing) => {
                    // Should be rare (race / manual deletion). Keep user here.
                    self.msg.set_warn(
                        "Selected keyfile is missing. Choose another or create a new one.",
                    );
                    self.selected = None;
                    self.refresh_on_enter(ctx);
                    *route = Route::KeyfileSelect;
                }

                Ok(KeyfileState::Corrupted) => {
                    // Treat as non-selectable outcome; keep user here and show the quarantine-style message.
                    self.set_quarantined_message(&name);
                    self.selected = None;
                    self.refresh_on_enter(ctx);
                    *route = Route::KeyfileSelect;
                }

                Err(AppError::KeyfileQuarantined { dir_name }) => {
                    self.set_quarantined_message(&dir_name);
                    self.selected = None;
                    self.refresh_on_enter(ctx);
                    *route = Route::KeyfileSelect;
                }

                Err(e) => {
                    self.msg.set_warn(&format!("Failed to select keyfile: {e}"));
                    // stay on KeyfileSelect
                    *route = Route::KeyfileSelect;
                }
            }
        }

        if ui.button("Create new keyfile…").clicked() {
            self.clear_messages();
            *route = Route::CreateKeyfile;
        }

        self.msg.show(ui, false);
    }
}
