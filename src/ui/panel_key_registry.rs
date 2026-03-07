// src/ui/panel_key_registry.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command, command_state::lock_session, context::AppCtx, notices::AppNotice, types::AppState,
};

use super::Route;
use super::{message::PanelMsgState, widgets};

#[derive(Clone, Copy, PartialEq, Eq)]
enum InstallKeyType {
    SignVerify,
    VerifyOnly,
}

pub struct KeyRegistryPanel {
    mnemonic: String,
    public_key_hex: String,
    domain: String,
    label: String,
    associated_key_id: String,

    // Install-time option
    enforce_standard_domain: bool,
    install_key_type: InstallKeyType,

    msg: PanelMsgState,

    // Uninstall confirmation modal
    confirm_uninstall: bool,
}

impl KeyRegistryPanel {
    pub fn new() -> Self {
        Self {
            mnemonic: String::new(),
            public_key_hex: String::new(),
            domain: String::new(),
            label: String::new(),
            associated_key_id: String::new(),
            enforce_standard_domain: true,
            install_key_type: InstallKeyType::SignVerify,
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
        self.public_key_hex.clear();
        self.label.clear();
        self.associated_key_id.clear();
        self.enforce_standard_domain = true;
        self.install_key_type = InstallKeyType::SignVerify;
        self.confirm_uninstall = false;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        widgets::panel_title(ui, "Key Registry");
        ui.separator();

        // Keep selector outside ScrollArea (same placement pattern as Sign panel)
        // to avoid popup viewport differences after runtime key mutations.
        let metas = state.keys.lock().map(|g| g.clone()).unwrap_or_default();

        let mut active_key_error: Option<AppNotice> = None;
        let mut active_key_changed = false;
        ui.horizontal(|ui| {
            ui.label("Key:");
            match widgets::active_key_selector(
                ui,
                state,
                ctx,
                route,
                (
                    "active_key_select",
                    widgets::key_selector_state_revision(&metas),
                ),
                &metas,
            ) {
                Ok(changed) => active_key_changed = changed,
                Err(e) => active_key_error = Some(e),
            }
        });
        if active_key_changed {
            self.clear_messages();
        }
        if let Some(e) = active_key_error {
            if let AppNotice::KeyfileQuarantined { .. } = e {
                *route = Route::KeyfileSelect;
                return;
            }
            self.msg.from_app_error(&e);
        }

        ui.add_space(8.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let dialog_width = ui.available_width().min(576.0);

                let current_active_id = lock_session(state).ok().and_then(|g| g.active_key_id);
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

                if has_active_key {
                    copyable_readonly_field(
                        ui,
                        "Label",
                        active_label.as_str(),
                        "Copy label",
                        None,
                        dialog_width,
                        &mut self.msg,
                    );

                    ui.add_space(6.0);

                    copyable_readonly_field(
                        ui,
                        "Domain",
                        &active_domain,
                        "Copy domain",
                        None,
                        dialog_width,
                        &mut self.msg,
                    );

                    ui.add_space(6.0);

                    copyable_readonly_field(
                        ui,
                        "Associated ID",
                        &active_assoc_id,
                        "Copy associated ID",
                        Some("—"),
                        dialog_width,
                        &mut self.msg,
                    );

                    ui.add_space(6.0);

                    copyable_readonly_field(
                        ui,
                        "Public key (hex)",
                        &active_pubkey_hex,
                        "Copy public key",
                        Some("No active key"),
                        dialog_width,
                        &mut self.msg,
                    );
                }

                ui.add_space(10.0);

                let install_enabled = !has_active_key;
                if install_enabled {
                    ui.weak("Enter information to install a new key into the keyfile.");
                    ui.add_space(6.0);

                    ui.add_enabled_ui(install_enabled, |ui| {
                        ui.label("Label");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.label)
                                .desired_width(dialog_width),
                        );

                        ui.add_space(6.0);

                        ui.label("Key type");
                        ui.horizontal(|ui| {
                            ui.radio_value(
                                &mut self.install_key_type,
                                InstallKeyType::SignVerify,
                                "Sign / Verify",
                            );
                            ui.radio_value(
                                &mut self.install_key_type,
                                InstallKeyType::VerifyOnly,
                                "Verify only",
                            );
                        });

                        ui.add_space(6.0);

                        if self.install_key_type == InstallKeyType::SignVerify {
                            ui.label("Mnemonic");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.mnemonic)
                                    .desired_rows(3)
                                    .desired_width(dialog_width),
                            );
                        } else {
                            ui.label("Public key (hex)");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.public_key_hex)
                                    .desired_rows(3)
                                    .desired_width(dialog_width),
                            );
                        }

                        ui.add_space(6.0);

                        ui.label("Domain (optional; empty = default)");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.domain)
                                .desired_width(dialog_width),
                        );

                        ui.add_space(4.0);

                        ui.checkbox(
                            &mut self.enforce_standard_domain,
                            "Enforce standardized domain (recommended)",
                        );

                        if !self.enforce_standard_domain {
                            ui.add_space(4.0);
                            crate::ui::widgets::ui_notice(
                                ui,
                                "Key standardization is currently disabled.
                            Be sure to record EXACTLY the text string used for domain. Otherwise, key recovery may be more difficult.",
                                crate::ui::widgets::NoticeAlign::Left,
                            );
                        }

                        ui.add_space(6.0);

                        ui.label("Associated Key ID (optional)");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.associated_key_id)
                                .desired_width(dialog_width),
                        );

                        ui.add_space(8.0);

                        let can_install = !self.label.trim().is_empty()
                            && match self.install_key_type {
                                InstallKeyType::SignVerify => !self.mnemonic.trim().is_empty(),
                                InstallKeyType::VerifyOnly => !self.public_key_hex.trim().is_empty(),
                            };

                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    can_install,
                                    egui::Button::new(egui::RichText::new("Install Key").strong()),
                                )
                                .clicked()
                            {
                                self.clear_messages();

                                let label = self.label.trim();

                                let assoc = self.associated_key_id.trim();
                                let assoc_opt = if assoc.is_empty() { None } else { Some(assoc) };

                                let res = match self.install_key_type {
                                    InstallKeyType::SignVerify => command::install_key(
                                        self.mnemonic.trim(),
                                        &self.domain,
                                        label,
                                        assoc_opt,
                                        self.enforce_standard_domain,
                                        state,
                                        ctx,
                                    ),
                                    InstallKeyType::VerifyOnly => command::install_verify_only_key(
                                        self.public_key_hex.trim(),
                                        &self.domain,
                                        label,
                                        assoc_opt,
                                        self.enforce_standard_domain,
                                        state,
                                        ctx,
                                    ),
                                };

                                if res.is_err() {
                                    *route = Route::KeyfileSelect;
                                }

                                match res {
                                    Ok(()) => {
                                        self.msg.set_success("Key installed");
                                        self.mnemonic.clear();
                                        self.public_key_hex.clear();
                                        self.domain.clear();
                                        self.label.clear();
                                        self.associated_key_id.clear();
                                        self.enforce_standard_domain = true;
                                        self.install_key_type = InstallKeyType::SignVerify;
                                    }
                                    Err(e) => {
                                        if let AppNotice::KeyfileQuarantined { .. } = e {
                                            *route = Route::KeyfileSelect;
                                            return;
                                        }
                                        self.msg.from_app_error(&e)
                                    }
                                }
                            }

                            if ui.button("Clear fields").clicked() {
                                self.reset_inputs();
                                self.clear_messages();
                            }
                        });

                        ui.add_space(10.0);

                        crate::ui::widgets::ui_notice(
                            ui,
                            "DO NOT rely on this application as permanent key storage!
                        Create and securely store physical backups of your mnemonics and any associated meta-data. Otherwise, key recovery is impossible.",
                            crate::ui::widgets::NoticeAlign::Left,
                        );
                    });
                }

                self.msg.show(ui);

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                if !has_active_key {
                    ui.weak("Select a key to uninstall.");
                    ui.add_space(6.0);
                }

                if ui
                    .add_enabled(has_active_key, egui::Button::new("Uninstall key"))
                    .clicked()
                {
                    self.clear_messages();
                    self.confirm_uninstall = true;
                }

                if self.confirm_uninstall {
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
                                            if let AppNotice::KeyfileQuarantined { .. } = e {
                                                *route = Route::KeyfileSelect;
                                                return;
                                            }
                                            self.msg.from_app_error(&e)
                                        }
                                    }
                                }
                            });
                        });
                }
            });
    }
}

fn copyable_readonly_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    hover: &str,
    hint: Option<&str>,
    dialog_width: f32,
    msg: &mut PanelMsgState,
) {
    widgets::copy_label_with_button(ui, label, value, hover, msg);
    let mut v = value.to_string();
    let mut field = egui::TextEdit::singleline(&mut v)
        .desired_width(dialog_width)
        .interactive(false);
    if let Some(hint) = hint {
        field = field.hint_text(hint);
    }
    ui.add(field);
}
