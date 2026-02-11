// src/ui/panel_lock.rs

use crate::ui::widgets;

use super::message::PanelMsgState;
use super::Route;

use eframe::egui;

use sigillium_personal_signer_verifier_lib::{
    command, context::AppCtx, notices::AppNotice, types::AppState,
};

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
        widgets::panel_title(ui, "Application locked");
        ui.separator();

        let unlocked = state.session.lock().map(|g| g.unlocked).unwrap_or(false);

        if unlocked {
            ui.label("App is unlocked.");
            self.msg.show(ui);
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
                    self.msg.clear();
                    *route = return_route.take().unwrap_or(Route::Sign);
                }

                Err(AppNotice::KeyfileQuarantined { .. }) => {
                    // Quarantine is surfaced on the Select Keyfile panel.
                    self.msg.clear();
                    *return_route = None;
                    *route = Route::KeyfileSelect;
                }

                Err(AppNotice::KeyfileMissing { .. }) => {
                    self.msg.clear();
                    *return_route = None;
                    *route = Route::KeyfileSelect;
                }

                Err(e) => {
                    self.msg.from_app_error(&e);
                }
            }

            self.passphrase.clear();
        }

        self.msg.show(ui);
    }
}
