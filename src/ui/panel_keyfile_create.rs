// src/ui/panel_create_keyfile.rs

use super::Route;
use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command, context::AppCtx, keyfile_store::KeyfileStore, types::AppState,
};

use super::message::PanelMsgState;

pub struct CreateKeyfilePanel {
    passphrase: String,
    confirm_passphrase: String,
    show_passphrase: bool,
    msg: PanelMsgState,
    keyfile_name: String,
}

impl CreateKeyfilePanel {
    pub fn new() -> Self {
        Self {
            passphrase: String::new(),
            confirm_passphrase: String::new(),
            show_passphrase: false,
            msg: PanelMsgState::default(),
            keyfile_name: String::new(),
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.passphrase.clear();
        self.confirm_passphrase.clear();
        self.show_passphrase = false;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        ui.heading("Create keyfile");
        ui.separator();

        if ui.button("Cancel").clicked() {
            self.clear_messages();
            self.reset_inputs();
            *route = Route::KeyfileSelect;
            return;
        }

        // If we detected corruption/tampering, tell the user why they're here.
        if let Ok(ks) = state.keyfile_state.lock() {
            if *ks == sigillium_personal_signer_verifier_lib::types::KeyfileState::Corrupted {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::YELLOW, "Warn:");
                    ui.label("Your current keyfile appears corrupted (or has been tampered with). Create a new keyfile to continue.");
                });
                ui.add_space(8.0);
            }
        }

        let mask = !self.show_passphrase;

        ui.label("Keyfile name");
        ui.text_edit_singleline(&mut self.keyfile_name);
        ui.add_space(8.0);

        ui.label("Enter passphrase");
        ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(mask));

        ui.add_space(8.0);

        ui.label("Confirm passphrase");
        ui.add(egui::TextEdit::singleline(&mut self.confirm_passphrase).password(mask));

        ui.add_space(8.0);

        ui.checkbox(&mut self.show_passphrase, "Show passphrase");

        ui.add_space(12.0);

        let both_non_empty = !self.passphrase.is_empty() && !self.confirm_passphrase.is_empty();
        let matches = both_non_empty && self.passphrase == self.confirm_passphrase;

        if !self.confirm_passphrase.is_empty() && self.passphrase != self.confirm_passphrase {
            ui.label("Passphrases do not match.");
            ui.add_space(8.0);
        }

        let clicked = ui
            .add_enabled(matches, egui::Button::new("Create keyfile"))
            .clicked();

        if clicked {
            self.clear_messages();

            let name = self.keyfile_name.trim();
            if name.is_empty() {
                self.msg.set_warn("Keyfile name required.");
                return;
            }

            let store = KeyfileStore::new(ctx.keyfiles_root());

            let dir = match store.create_keyfile_dir(name) {
                Ok(d) => d,
                Err(e) => {
                    self.msg.from_app_error(&e, ctx.debug_ui);
                    return;
                }
            };

            ctx.set_selected_keyfile_dir(Some(dir));

            match command::create_keyfile(&self.passphrase, state, ctx) {
                Ok(_) => {
                    let msg = "Keyfile created successfully.".to_string();
                    self.msg.set_success(msg);
                    self.reset_inputs();
                    *route = Route::KeyfileSelect;
                    ctx.set_selected_keyfile_dir(None);

                    if let Ok(mut ks) = state.keyfile_state.lock() {
                        *ks = sigillium_personal_signer_verifier_lib::types::KeyfileState::NotCorrupted;
                    }
                }
                Err(e) => {
                    self.msg.from_app_error(&e, ctx.debug_ui);
                }
            }

            self.passphrase.clear();
            self.confirm_passphrase.clear();
            self.keyfile_name.clear();
        }

        self.msg.show(ui, false);
    }
}
