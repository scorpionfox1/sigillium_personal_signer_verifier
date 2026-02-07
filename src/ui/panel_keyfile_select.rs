// src/ui/panel_keyfile_select.rs

use super::message::PanelMsgState;
use super::{widgets, Route};
use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command::session::select_keyfile_dir,
    context::AppCtx,
    keyfile_store::{KeyfileDirRow, KeyfileStore},
    notices::AppNotice,
    types::AppState,
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
        if !self.loaded {
            self.refresh_list(ctx);
        }

        let _ = return_route;

        ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
            ui.set_min_width(420.0);

            ui.vertical(|ui| {
                ui.add_space(6.0);
                widgets::panel_title(ui, "Select a keyfile");
                ui.separator();
                ui.add_space(12.0);

                if self.keyfiles.is_empty() {
                    ui.label("No keyfiles found.");
                    ui.add_space(6.0);
                    ui.label("Create a new keyfile to continue.");
                } else {
                    ui.label("Keyfiles");
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(260.0)
                        .show(ui, |ui| {
                            let mut picked: Option<String> = None;

                            for row in self.keyfiles.iter() {
                                let label = if row.has_keyfile {
                                    row.name.clone()
                                } else {
                                    format!("{} (no keyfile)", row.name)
                                };

                                let is_selected =
                                    self.selected.as_deref() == Some(row.name.as_str());

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
                                self.selected = Some(name.clone());

                                match select_keyfile_dir(state, ctx, &name) {
                                    Ok(()) => {
                                        *return_route = Some(Route::Sign);
                                        *route = Route::Locked;
                                    }
                                    Err(AppNotice::KeyfileQuarantined { dir_name }) => {
                                        self.set_quarantined_message(&dir_name);
                                        self.selected = None;
                                        self.refresh_on_enter(ctx);
                                        *route = Route::KeyfileSelect;
                                    }
                                    Err(AppNotice::KeyfileMissing { .. }) => {
                                        self.msg.set_warn(
                                            "Selected keyfile is missing. Choose another.",
                                        );
                                        self.selected = None;
                                        self.refresh_on_enter(ctx);
                                        *route = Route::KeyfileSelect;
                                    }
                                    Err(e) => {
                                        self.msg
                                            .set_warn(&format!("Failed to select keyfile: {e}"));
                                        *route = Route::KeyfileSelect;
                                    }
                                }
                            }
                        });
                }

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(12.0);

                if ui.button("Create new keyfile…").clicked() {
                    self.clear_messages();
                    *route = Route::CreateKeyfile;
                }

                ui.add_space(8.0);
                self.msg.show(ui);
            });
        });
    }
}
