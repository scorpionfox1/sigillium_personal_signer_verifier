// src/ui/panel_keyfile_select.rs

use super::message::PanelMsgState;
use super::Route;
use eframe::egui;
use sigillum_personal_signer_verifier_lib::{
    context::AppCtx,
    keyfile_store::KeyfileStore,
    types::{AppState, KeyfileState},
};

pub struct KeyfileSelectPanel {
    msg: PanelMsgState,
    keyfiles: Vec<String>,
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

    fn refresh_list(&mut self, ctx: &AppCtx) {
        let store = KeyfileStore::new(ctx.keyfiles_root());
        match store.list_keyfiles() {
            Ok(list) => {
                self.keyfiles = list;
                if self.keyfiles.is_empty() {
                    self.selected = None;
                } else if self.selected.as_deref().is_none()
                    || !self
                        .keyfiles
                        .iter()
                        .any(|k| Some(k.as_str()) == self.selected.as_deref())
                {
                    self.selected = Some(self.keyfiles[0].clone());
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

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        ui.heading("Select keyfile");
        ui.separator();

        if !self.loaded {
            self.refresh_list(ctx);
        }

        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.clear_messages();
                self.refresh_list(ctx);
            }

            if ui.button("Create new keyfile…").clicked() {
                self.clear_messages();
                *route = Route::CreateKeyfile;
            }
        });

        ui.add_space(12.0);

        if self.keyfiles.is_empty() {
            ui.label("No keyfiles found.");
            ui.label("Create a new keyfile to continue.");
            self.msg.show(ui, false);
            return;
        }

        let selected_text = self
            .selected
            .as_deref()
            .unwrap_or("Select a keyfile…")
            .to_string();

        egui::ComboBox::from_id_salt("keyfile_select_combo")
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                for name in self.keyfiles.iter() {
                    ui.selectable_value(&mut self.selected, Some(name.clone()), name);
                }
            });

        ui.add_space(12.0);

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

            if let Ok(mut s) = state.session.lock() {
                s.unlocked = false;
                s.active_key_id = None;
                s.active_associated_key_id = None;
            }

            let dir = ctx.keyfiles_root().join(&name);
            ctx.set_selected_keyfile_dir(Some(dir));

            let Some(name) = self.selected.clone() else {
                self.msg.set_warn("Select a keyfile first.");
                self.msg.show(ui, false);
                return;
            };

            // Set selection in context
            let dir = ctx.keyfiles_root().join(&name);
            ctx.set_selected_keyfile_dir(Some(dir));

            // App becomes locked immediately
            if let Ok(mut s) = state.session.lock() {
                s.unlocked = false;
                s.active_key_id = None;
                s.active_associated_key_id = None;
            }
            if let Ok(mut sec) = state.secrets.lock() {
                *sec = None;
            }

            // Compute keyfile state for the selected keyfile.json
            let ks = match ctx.current_keyfile_path() {
                Some(p) => sigillum_personal_signer_verifier_lib::keyfile::check_keyfile_state(&p)
                    .unwrap_or(KeyfileState::Corrupted),
                None => KeyfileState::Missing,
            };

            if let Ok(mut g) = state.keyfile_state.lock() {
                *g = ks;
            }

            *route = Route::Locked;
        }

        self.msg.show(ui, false);
    }
}
