// src/ui/panel_security.rs

use eframe::egui;
use sigillium_personal_signer_verifier_lib::{
    command, context::AppCtx, security_log::SecurityEvent, types::AppState,
};

use super::message::PanelMsgState;
use super::Route;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecurityTab {
    SecurityLog,
    ChangePassphrase,
    SelfDestruct,
}

pub struct SecurityPanel {
    tab: SecurityTab,

    security_log_rendered: String,

    old_pass: String,
    new_pass: String,
    new_pass_confirm: String,
    show_passphrases: bool,
    msg: PanelMsgState,

    confirm_phrase: String,
    confirm_self_destruct: bool,
}

impl SecurityPanel {
    pub fn new() -> Self {
        Self {
            tab: SecurityTab::SecurityLog,
            security_log_rendered: String::new(),
            old_pass: String::new(),
            new_pass: String::new(),
            new_pass_confirm: String::new(),
            show_passphrases: false,
            msg: PanelMsgState::default(),
            confirm_phrase: String::new(),
            confirm_self_destruct: false,
        }
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn reset_inputs(&mut self) {
        self.old_pass.clear();
        self.new_pass.clear();
        self.new_pass_confirm.clear();
        self.show_passphrases = false;
        self.confirm_phrase.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &AppState, ctx: &AppCtx, route: &mut Route) {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.heading("Security");
                ui.separator();

                let prev_tab = self.tab;

                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, SecurityTab::SecurityLog, "Security Log");
                    ui.selectable_value(
                        &mut self.tab,
                        SecurityTab::ChangePassphrase,
                        "Change Passphrase",
                    );
                    ui.selectable_value(&mut self.tab, SecurityTab::SelfDestruct, "Self-Destruct");
                });

                if self.tab != prev_tab {
                    self.clear_messages();

                    if self.tab == SecurityTab::SecurityLog {
                        self.security_log_rendered = render_events(read_events(state));
                    }
                }

                ui.add_space(10.0);

                match self.tab {
                    SecurityTab::SecurityLog => self.ui_security_log(ui, state),
                    SecurityTab::ChangePassphrase => {
                        self.ui_change_passphrase(ui, state, ctx, route)
                    }
                    SecurityTab::SelfDestruct => self.ui_self_destruct(ui, ctx, route),
                }
            });
    }

    fn ui_security_log(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.label("Security log");
        ui.add_space(6.0);

        if self.security_log_rendered.is_empty() {
            self.security_log_rendered = render_events(read_events(state));
        }

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.security_log_rendered)
                        .desired_rows(18)
                        .interactive(false)
                        .hint_text("No security events recorded."),
                );
            });
    }

    fn ui_change_passphrase(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        ctx: &AppCtx,
        _route: &mut Route,
    ) {
        ui.label("Change passphrase");
        ui.add_space(6.0);

        let mask = !self.show_passphrases;

        ui.label("Old passphrase");
        let r = ui.add(egui::TextEdit::singleline(&mut self.old_pass).password(mask));
        if r.changed() {
            self.msg.clear();
        }

        ui.add_space(8.0);

        ui.label("New passphrase");
        let r = ui.add(egui::TextEdit::singleline(&mut self.new_pass).password(mask));
        if r.changed() {
            self.msg.clear();
        }

        ui.add_space(8.0);

        ui.label("Confirm new passphrase");
        let r = ui.add(egui::TextEdit::singleline(&mut self.new_pass_confirm).password(mask));
        if r.changed() {
            self.msg.clear();
        }

        ui.add_space(8.0);

        ui.checkbox(&mut self.show_passphrases, "Show passphrases");

        ui.add_space(12.0);

        let old_ok = !self.old_pass.is_empty();
        let both_new_non_empty = !self.new_pass.is_empty() && !self.new_pass_confirm.is_empty();
        let matches = both_new_non_empty && self.new_pass == self.new_pass_confirm;

        if both_new_non_empty && !matches {
            ui.label("Passphrases do not match.");
            ui.add_space(8.0);
        }

        let can_submit = old_ok && both_new_non_empty && matches;

        ui.horizontal(|ui| {
            if ui
                .add_enabled(can_submit, egui::Button::new("Change passphrase"))
                .clicked()
            {
                self.clear_messages();

                let res = command::change_passphrase(
                    self.old_pass.trim(),
                    self.new_pass.trim(),
                    state,
                    ctx,
                );

                match res {
                    Ok(()) => {
                        self.reset_inputs();
                        self.msg.set_success("Passphrase changed successfully.");
                    }
                    Err(e) => self.msg.from_app_error(&e),
                }
            }
        });

        self.msg.show(ui);
    }

    fn ui_self_destruct(&mut self, ui: &mut egui::Ui, ctx: &AppCtx, route: &mut Route) {
        ui.label("Self-destruct");
        ui.add_space(6.0);

        ui.weak("This will delete the keyfile using best-effort secure deletion.");
        ui.weak("Type exactly:  self destruct");
        ui.add_space(8.0);

        ui.label("Keyfile path (for sanity check)");

        let path_buf_opt = ctx.current_keyfile_path();
        let mut path = match &path_buf_opt {
            Some(p) => p.display().to_string(),
            None => "<no keyfile selected>".to_string(),
        };

        ui.add(egui::TextEdit::singleline(&mut path).interactive(false));

        ui.add_space(10.0);

        ui.label("Confirmation phrase");
        ui.add(egui::TextEdit::singleline(&mut self.confirm_phrase).hint_text("self destruct"));

        ui.add_space(10.0);

        let armed = self.confirm_phrase.trim() == "self destruct";

        if ui
            .add_enabled(armed, egui::Button::new("Delete keyfile"))
            .clicked()
        {
            self.confirm_self_destruct = true;
        }

        if self.confirm_self_destruct {
            egui::Window::new("Confirm self-destruct")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.label("This will permanently delete the keyfile.");
                    ui.add_space(6.0);
                    ui.label("This action cannot be undone.");
                    ui.add_space(12.0);

                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.confirm_self_destruct = false;
                        }

                        if ui.button("OK, delete keyfile").clicked() {
                            self.confirm_self_destruct = false;
                            self.clear_messages();

                            let Some(keyfile_path) = ctx.current_keyfile_path() else {
                                self.msg.set_warn("No keyfile selected.");
                                return;
                            };

                            let Some(dir) = keyfile_path.parent() else {
                                self.msg.set_error("Invalid keyfile path.");
                                return;
                            };

                            sigillium_personal_signer_verifier_lib::keyfile_store::destroy_keyfile_dir_best_effort(dir);

                            ctx.set_selected_keyfile_dir(None);
                            self.msg.set_success("Keyfile destroyed.");

                            *route = Route::KeyfileSelect;

                            self.confirm_phrase.clear();
                            self.old_pass.clear();
                            self.new_pass.clear();
                            self.new_pass_confirm.clear();
                            self.show_passphrases = false;

                        }
                    });
                });
        }

        self.msg.show(ui);
    }
}

fn read_events(state: &AppState) -> Vec<SecurityEvent> {
    state
        .security_log
        .lock()
        .map(|g| g.recent())
        .unwrap_or_default()
}

fn render_events(mut evs: Vec<SecurityEvent>) -> String {
    if evs.is_empty() {
        return String::new();
    }

    evs.sort_by(|a, b| b.ts_ms.cmp(&a.ts_ms));

    let mut out = String::new();
    for e in evs {
        let errno = e
            .errno
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string());
        let ts = fmt_ts_ms_utc(e.ts_ms);

        out.push_str(&format!(
            "#{} | {} | {:?} | {} | {} | {} | errno:{}\n{}\n\n",
            e.id, ts, e.class, e.os, e.kind, e.context, errno, e.msg
        ));
    }
    out
}

fn fmt_ts_ms_utc(ts_ms: u64) -> String {
    use chrono::{DateTime, TimeZone, Utc};

    let secs = (ts_ms / 1000) as i64;
    let nsec = ((ts_ms % 1000) * 1_000_000) as u32;

    // Using timestamp_opt for safer handling of the timestamp
    let dt: DateTime<Utc> = Utc
        .timestamp_opt(secs, nsec)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap()); // Use timestamp_opt for fallback

    dt.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string()
}
