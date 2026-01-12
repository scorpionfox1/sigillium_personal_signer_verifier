// src/ui/panel_lock.rs

use super::Route;
use eframe::egui;
use sigillum_personal_signer_verifier_lib::{command, context::AppCtx, types::AppState};

use super::message::PanelMsgState;

pub struct LockPanel {
    passphrase: String,
    show_passphrase: bool,
    msg: PanelMsgState,
}

impl LockPanel {
    pub fn new() -> Self {
        Self {
            passphrase: String::new(),
            show_passphrase: false,
            msg: PanelMsgState::default(),
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.passphrase.clear();
        self.show_passphrase = false;
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        ctx: &AppCtx,
        route: &mut Route,
        return_route: &mut Option<Route>,
    ) {
        ui.heading("App locked");
        ui.separator();

        let unlocked = state.session.lock().map(|g| g.unlocked).unwrap_or(false);

        if unlocked {
            ui.label("App is unlocked.");
            self.msg.show(ui, false);
            return;
        }

        let mask = !self.show_passphrase;

        ui.label("Enter passphrase");
        ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(mask));

        ui.add_space(8.0);
        ui.checkbox(&mut self.show_passphrase, "Show passphrase");

        ui.add_space(12.0);

        let clicked = ui
            .add_enabled(!self.passphrase.is_empty(), egui::Button::new("Unlock"))
            .clicked();

        if clicked {
            self.clear_messages();

            match command::unlock_app(&self.passphrase, state, ctx) {
                Ok(()) => {
                    // Provide a default success message since the result is unit type.
                    self.msg.set_success("App unlocked successfully.");

                    let ks_ok = state
            .keyfile_state
            .lock()
            .map(|ks| {
                *ks == sigillum_personal_signer_verifier_lib::types::KeyfileState::NotCorrupted
            })
            .unwrap_or(false);

                    if ks_ok {
                        self.msg.clear();
                        *route = return_route.take().unwrap_or(Route::Sign);
                    }
                }
                Err(e) => self.msg.from_app_error(&e, ctx.debug_ui),
            }

            if let Ok(ks) = state.keyfile_state.lock() {
                if *ks == sigillum_personal_signer_verifier_lib::types::KeyfileState::Corrupted {
                    *route = Route::CreateKeyfile;
                }
            }

            self.passphrase.clear();
        }

        self.msg.show(ui, false);
    }
}
