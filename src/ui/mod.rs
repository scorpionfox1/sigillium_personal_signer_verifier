// src/ui/mod.rs

pub mod nav;
pub mod panel_key_registry;
pub mod panel_keyfile_create;
pub mod panel_keyfile_select;
pub mod panel_lock;
pub mod panel_security;
pub mod panel_sign;
pub mod panel_verify;

pub mod message;
pub mod route_policy;
pub mod widgets;

use eframe::egui;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nav::{LeftNav, NavModel};
use route_policy::{
    apply_route_guards, entering_locked, message_clear_policy, MessageClearPolicy, RouteCtx,
};

use message::PanelMsgState;
use panel_key_registry::KeyRegistryPanel;
use panel_keyfile_create::CreateKeyfilePanel;
use panel_keyfile_select::KeyfileSelectPanel;
use panel_lock::LockPanel;
use panel_security::SecurityPanel;
use panel_sign::SignPanel;
use panel_verify::VerifyPanel;
use sigillium_personal_signer_verifier_lib::command_state::lock_app_inner_if_unlocked;
use sigillium_personal_signer_verifier_lib::context::AppCtx;
use sigillium_personal_signer_verifier_lib::security_log::take_best_effort_warn_pending;
use sigillium_personal_signer_verifier_lib::types::AppState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    KeyfileSelect,
    CreateKeyfile,
    Locked,
    Sign,
    Verify,
    KeyRegistry,
    Security,
}

pub struct UiApp {
    state: Arc<AppState>,
    ctx: Arc<AppCtx>,

    route: Route,
    last_route: Route,
    prev_route: Route,
    return_route: Option<Route>,

    nav: LeftNav,
    keyfile_select: KeyfileSelectPanel,
    create_keyfile: CreateKeyfilePanel,
    lock: LockPanel,
    sign: SignPanel,
    verify: VerifyPanel,
    key_registry: KeyRegistryPanel,
    security: SecurityPanel,
    last_activity: Instant,
    best_effort_warn: PanelMsgState,
    secure_close_requested: bool,
}

impl UiApp {
    pub fn new(state: Arc<AppState>, ctx: Arc<AppCtx>) -> Self {
        // Always start locked (and no active key)
        if let Ok(mut s) = state.session.lock() {
            s.unlocked = false;
            s.active_key_id = None;
            s.active_associated_key_id = None;
        }
        if let Ok(mut sec) = state.secrets.lock() {
            *sec = None;
        }

        // Explicitly start with "no keyfile selected" and route to KeyfileSelect.
        ctx.set_selected_keyfile_dir(None);

        let route = Route::KeyfileSelect;

        Self {
            state,
            ctx,
            route,
            last_route: route,
            prev_route: route,
            return_route: None,
            nav: LeftNav::new(),
            keyfile_select: KeyfileSelectPanel::new(),
            create_keyfile: CreateKeyfilePanel::new(),
            lock: LockPanel::new(),
            sign: SignPanel::new(),
            verify: VerifyPanel::new(),
            key_registry: KeyRegistryPanel::new(),
            security: SecurityPanel::new(),
            last_activity: Instant::now(),
            best_effort_warn: PanelMsgState::default(),
            secure_close_requested: false,
        }
    }

    fn reset_all_inputs(&mut self) {
        self.keyfile_select.reset_inputs();
        self.create_keyfile.reset_inputs();
        self.lock.reset_inputs();
        self.sign.reset_inputs();
        self.verify.reset_inputs();
        self.key_registry.reset_inputs();
        self.security.reset_inputs();
    }

    fn derive_route_ctx(&self) -> RouteCtx {
        let unlocked = self
            .state
            .session
            .lock()
            .map(|g| g.unlocked)
            .unwrap_or(false);

        RouteCtx {
            keyfile_selected: self.ctx.is_keyfile_selected(),
            unlocked,
        }
    }

    fn derive_nav_model(&self, rctx: RouteCtx) -> NavModel {
        NavModel {
            show_nav_tabs: rctx.keyfile_selected,
        }
    }

    fn current_selected_keyfile_dir_name(&self) -> Option<String> {
        let keyfile_path = self.ctx.current_keyfile_path()?;
        let dir = keyfile_path.parent()?;
        let name = dir.file_name()?.to_str()?;
        Some(name.to_string())
    }
}

impl eframe::App for UiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let rctx = self.derive_route_ctx();
        let debug_ui = cfg!(debug_assertions);

        let had_activity = ctx.input(|i| {
            i.raw.events.iter().any(|e| {
                matches!(
                    e,
                    egui::Event::PointerButton { pressed: true, .. }
                        | egui::Event::Key { pressed: true, .. }
                        | egui::Event::Text(_)
                        | egui::Event::Paste(_)
                )
            })
        });

        if had_activity {
            self.last_activity = Instant::now();
        }

        if rctx.unlocked
            && self.route != Route::Locked
            && self.last_activity.elapsed() >= Duration::from_secs(60)
        {
            *&mut self.route = Route::Locked;
        }

        if self.route != self.prev_route {
            match message_clear_policy(self.prev_route, self.route) {
                MessageClearPolicy::ClearAllNonLockPanels => {
                    self.keyfile_select.clear_messages();
                    self.create_keyfile.clear_messages();
                    self.sign.clear_messages();
                    self.verify.clear_messages();
                    self.key_registry.clear_messages();
                    self.security.clear_messages();
                }
                MessageClearPolicy::ClearOnlyLockPanel => {
                    self.lock.clear_messages();
                }
            }
            self.best_effort_warn.clear();

            let guarded = apply_route_guards(&rctx, self.route);

            // If the guard changed the route, apply it.
            if guarded != self.route {
                self.route = guarded;
            }

            if self.route == Route::KeyfileSelect {
                self.keyfile_select.refresh_on_enter(&self.ctx);
            }

            if entering_locked(self.prev_route, self.route) {
                let _ = lock_app_inner_if_unlocked(self.state.as_ref(), "ui_enter_locked");
                self.reset_all_inputs();
                self.last_activity = Instant::now();
            }

            self.prev_route = self.route;
        }

        if take_best_effort_warn_pending(self.state.as_ref()) {
            self.best_effort_warn
                .set_warn("Some security hardening steps failed. See Security Log.");
        }

        let nav_model = self.derive_nav_model(rctx);
        self.nav.ui(
            ctx,
            nav_model,
            &mut self.route,
            &mut self.secure_close_requested,
        );

        if self.secure_close_requested {
            self.secure_close_requested = false;

            match sigillium_personal_signer_verifier_lib::command::session::secure_prepare_for_quit(
                self.state.as_ref(),
            ) {
                Ok(()) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                }
                Err(e) => {
                    self.best_effort_warn
                        .set_warn(&format!("Secure close failed: {e}"));
                }
            }
        }

        // ------------------------------------------------------------------
        // Keyfile footer (reserved bottom area; never clipped by ScrollAreas)
        // ------------------------------------------------------------------
        if !matches!(
            self.route,
            Route::Locked | Route::KeyfileSelect | Route::CreateKeyfile
        ) {
            egui::TopBottomPanel::bottom("keyfile_footer").show(ctx, |ui| {
                ui.add_space(4.0);

                let name = self
                    .current_selected_keyfile_dir_name()
                    .unwrap_or_else(|| "(none)".to_string());

                ui.label(format!("keyfile: {name}"));
                ui.add_space(4.0);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            self.best_effort_warn.show(ui, debug_ui);

            match self.route {
                Route::KeyfileSelect => self.keyfile_select.ui(
                    ui,
                    self.state.as_ref(),
                    &self.ctx,
                    &mut self.route,
                    &mut self.return_route,
                ),

                Route::CreateKeyfile => {
                    self.create_keyfile
                        .ui(ui, self.state.as_ref(), &self.ctx, &mut self.route)
                }

                Route::Locked => {
                    if self.last_route != Route::Locked && self.return_route.is_none() {
                        self.return_route = Some(if self.last_route == Route::CreateKeyfile {
                            Route::Sign
                        } else {
                            self.last_route
                        });
                    }

                    self.lock.ui(
                        ui,
                        self.state.as_ref(),
                        &self.ctx,
                        &mut self.route,
                        &mut self.return_route,
                    );
                }

                Route::Sign => self
                    .sign
                    .ui(ui, self.state.as_ref(), &self.ctx, &mut self.route),

                Route::Verify => {
                    self.verify
                        .ui(ui, self.state.as_ref(), &self.ctx, &mut self.route)
                }

                Route::KeyRegistry => {
                    self.key_registry
                        .ui(ui, self.state.as_ref(), &self.ctx, &mut self.route)
                }

                Route::Security => {
                    self.security
                        .ui(ui, self.state.as_ref(), &self.ctx, &mut self.route)
                }
            }
        });

        if self.route != Route::Locked {
            self.last_route = self.route;
        }
    }
}
