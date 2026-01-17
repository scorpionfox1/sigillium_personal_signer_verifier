// src/ui/panel_key_registry.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command, command_state::lock_session, context::AppCtx, error::AppError, types::AppState,
};

use super::Route;
use super::{message::PanelMsgState, widgets};

pub struct KeyRegistryPanel {
    mnemonic: String,
    domain: String,
    label: String,
    associated_key_id: String,

    // Install-time option
    enforce_standard_domain: bool,

    msg: PanelMsgState,

    // Uninstall confirmation modal
    confirm_uninstall: bool,
}

impl KeyRegistryPanel {
    pub fn new() -> Self {
        Self {
            mnemonic: String::new(),
            domain: String::new(),
            label: String::new(),
            associated_key_id: String::new(),
            enforce_standard_domain: true,
            msg: PanelMsgState::default(),
            confirm_uninstall: false,
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.mnemonic.clear();
        self.domain.clear();
        self.label.clear();
        self.associated_key_id.clear();
        self.enforce_standard_domain = true;
        self.confirm_uninstall = false;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.heading("Key Registry");
                ui.separator();

                let current_active_id = lock_session(state).ok().and_then(|g| g.active_key_id);

                let metas = state.keys.lock().map(|g| g.clone()).unwrap_or_default();

                let active_meta = current_active_id.and_then(|id| metas.iter().find(|m| m.id == id));

                let active_domain = active_meta.map(|m| m.domain.clone()).unwrap_or_default();
                let active_label = active_meta.map(|m| m.label.clone()).unwrap_or_default();
                let active_pubkey_hex = active_meta
                    .map(|m| hex::encode(m.public_key))
                    .unwrap_or_default();

                let active_assoc_id = lock_session(state)
                    .ok()
                    .and_then(|g| g.active_associated_key_id.clone())
                    .unwrap_or_default();

                let has_active_key = current_active_id.is_some();

                ui.group(|ui| {
                    ui.label("Active key");

                    if let Err(e) = widgets::active_key_selector(
                        ui,
                        state,
                        ctx,
                        route,
                        "active_key_select",
                        &metas,
                    ) {
                        if let AppError::KeyfileQuarantined { .. } = e {
                            *route = Route::KeyfileSelect;
                            return;
                        }
                        self.msg.from_app_error(&e, ctx.debug_ui);
                    }

                    ui.add_space(6.0);

                    if has_active_key {
                        ui.weak("Active key details");
                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.label("Label");
                            let ok = !active_label.is_empty();
                            if widgets::copy_icon_button(ui, ok, "Copy label") {
                                ui.ctx().copy_text(active_label.clone());
                            }
                        });
                        let mut v = active_label.clone();
                        ui.add(egui::TextEdit::singleline(&mut v).interactive(false));

                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.label("Domain");
                            let ok = !active_domain.is_empty();
                            if widgets::copy_icon_button(ui, ok, "Copy domain") {
                                ui.ctx().copy_text(active_domain.clone());
                            }
                        });
                        let mut v = active_domain.clone();
                        ui.add(egui::TextEdit::singleline(&mut v).interactive(false));

                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.label("Associated ID");
                            let ok = !active_assoc_id.is_empty();
                            if widgets::copy_icon_button(ui, ok, "Copy associated ID") {
                                ui.ctx().copy_text(active_assoc_id.clone());
                            }
                        });
                        let mut v = active_assoc_id.clone();
                        ui.add(
                            egui::TextEdit::singleline(&mut v)
                                .interactive(false)
                                .hint_text("—"),
                        );

                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.label("Public key (hex)");
                            let ok = !active_pubkey_hex.is_empty();
                            if widgets::copy_icon_button(ui, ok, "Copy public key") {
                                ui.ctx().copy_text(active_pubkey_hex.clone());
                            }
                        });
                        let mut v = active_pubkey_hex.clone();
                        ui.add(
                            egui::TextEdit::singleline(&mut v)
                                .interactive(false)
                                .hint_text("No active key"),
                        );

                        ui.add_space(6.0);
                        ui.weak("Set Active key to None to install a new key.");
                    } else {
                        ui.weak("No active key selected.");
                    }
                });

                ui.add_space(10.0);

                ui.group(|ui| {
                    ui.label("Install key");

                    let install_enabled = !has_active_key;
                    if !install_enabled {
                        ui.weak("Clear the active key (set to None) to install a new key.");
                        ui.add_space(6.0);
                    }

                    ui.add_enabled_ui(install_enabled, |ui| {
                        ui.label("Label");
                        ui.add(egui::TextEdit::singleline(&mut self.label));

                        ui.add_space(6.0);

                        ui.label("Mnemonic");
                        ui.add(egui::TextEdit::multiline(&mut self.mnemonic).desired_rows(3));

                        ui.add_space(6.0);

                        ui.label("Domain (optional; empty = default)");
                        ui.add(egui::TextEdit::singleline(&mut self.domain));

                        ui.add_space(4.0);

                        ui.checkbox(
                            &mut self.enforce_standard_domain,
                            "Enforce standardized domain (recommended)",
                        );

                        if !self.enforce_standard_domain {
                            ui.add_space(4.0);
                            ui.colored_label(
                                egui::Color32::YELLOW,
                                "Warning: Standardization is OFF. The domain will be used EXACTLY as typed (no trimming, no lowercasing, no validation). Invisible characters, spaces, and typos will change the derived key.",
                            );
                        }

                        ui.add_space(6.0);

                        ui.label("Associated Key ID (optional)");
                        ui.add(egui::TextEdit::singleline(&mut self.associated_key_id));

                        ui.add_space(8.0);

                        let can_install =
                            !self.mnemonic.trim().is_empty() && !self.label.trim().is_empty();

                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(can_install, egui::Button::new("Install"))
                                .clicked()
                            {
                                self.clear_messages();

                                // We still trim label/mnemonic for basic UX; domain behavior is controlled by the checkbox.
                                let mnemonic = self.mnemonic.trim();
                                let label = self.label.trim();

                                let assoc = self.associated_key_id.trim();
                                let assoc_opt = if assoc.is_empty() { None } else { Some(assoc) };

                                // IMPORTANT: pass domain exactly as entered; command decides whether to normalize/validate.
                                let res = command::install_key(

                                    mnemonic,
                                    &self.domain,
                                    label,
                                    assoc_opt,
                                    self.enforce_standard_domain,
                                    state,
                                    ctx,
                                );

                                if res.is_err() {
                                    *route = Route::KeyfileSelect;
                                }

                                match res {
                                    Ok(()) => {
                                        self.msg.set_success("Key installed");
                                        self.mnemonic.clear();
                                        self.domain.clear();
                                        self.label.clear();
                                        self.associated_key_id.clear();
                                        self.enforce_standard_domain = true;
                                    }
                                    Err(e) => {
                                        if let AppError::KeyfileQuarantined { .. } = e {
                                            *route = Route::KeyfileSelect;
                                            return;
                                        }
                                        self.msg.from_app_error(&e, ctx.debug_ui)
                                    }
                                }
                            }

                            if ui.button("Clear fields").clicked() {
                                self.reset_inputs();
                                self.clear_messages();
                            }
                        });

                        ui.add_space(10.0);

                        egui::Frame::group(ui.style())
                            .stroke(egui::Stroke::new(1.0, egui::Color32::YELLOW))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new("IMPORTANT: backup required")
                                        .strong()
                                        .color(egui::Color32::YELLOW),
                                );
                                ui.add_space(4.0);
                                ui.label(
                                    "Do NOT rely on this app as permanent storage. Securely record and store your \
                    mnemonic + domain and any associated ID on a physical medium. Otherwise, loss of this device/keyfile would mean permanent loss of key.",
                                );
                            });
                    });
                });

                self.msg.show(ui, cfg!(debug_assertions));

                ui.add_space(10.0);

                ui.group(|ui| {
                    ui.label("Uninstall key");

                    ui.add_space(4.0);
                    ui.weak("Uninstalls the currently selected key.");

                    ui.add_space(8.0);

                    if ui
                        .add_enabled(has_active_key, egui::Button::new("Uninstall key"))
                        .clicked()
                    {
                        self.clear_messages();
                        self.confirm_uninstall = true;
                    }
                });

                // ==============================
                // Confirm uninstall modal
                // ==============================
                if self.confirm_uninstall {
                    // NOTE: `ui.ctx()` is the egui Context for the whole app.
                    egui::Window::new("Confirm uninstall")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                        .show(ui.ctx(), |ui| {
                            ui.label("This will remove the currently active key from your keyfile. If you want to reinstall it you will need the mnemoic and domain string.");
                            ui.add_space(10.0);

                            ui.horizontal(|ui| {
                                if ui.button("Cancel").clicked() {
                                    self.confirm_uninstall = false;
                                }

                                if ui
                                    .add(egui::Button::new("Uninstall").fill(ui.visuals().error_fg_color))
                                    .clicked()
                                {
                                    self.confirm_uninstall = false;
                                    self.clear_messages();

                                    let res = command::uninstall_active_key(state, ctx);

                                    match res {
                                        Ok(()) => {
                                            self.msg.set_success("Key uninstalled successfully.");
                                        }
                                        Err(e) => {
                                            if let AppError::KeyfileQuarantined { .. } = e {
                                                *route = Route::KeyfileSelect;
                                                return;
                                            }
                                            self.msg.from_app_error(&e, ctx.debug_ui)
                                        }
                                    }
                                }
                            });
                        });
                }
            });
    }
}
