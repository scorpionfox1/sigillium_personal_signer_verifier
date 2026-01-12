// src/ui/mod.rs

pub mod nav;
pub mod panel_create_keyfile;
pub mod panel_key_registry;
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
use panel_create_keyfile::CreateKeyfilePanel;
use panel_key_registry::KeyRegistryPanel;
use panel_lock::LockPanel;
use panel_security::SecurityPanel;
use panel_sign::SignPanel;
use panel_verify::VerifyPanel;
use sigillum_personal_signer_verifier_lib::command_state::lock_app_inner_if_unlocked;
use sigillum_personal_signer_verifier_lib::context::AppCtx;
use sigillum_personal_signer_verifier_lib::security_log::take_best_effort_warn_pending;
use sigillum_personal_signer_verifier_lib::types::{AppState, KeyfileState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
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
    create_keyfile: CreateKeyfilePanel,
    lock: LockPanel,
    sign: SignPanel,
    verify: VerifyPanel,
    key_registry: KeyRegistryPanel,
    security: SecurityPanel,
    last_activity: Instant,
    best_effort_warn: PanelMsgState,
}

impl UiApp {
    pub fn new(state: Arc<AppState>, ctx: Arc<AppCtx>) -> Self {
        // Always start locked
        // Always start locked
        if let Ok(mut s) = state.session.lock() {
            s.unlocked = false;
            s.active_key_id = None;
        }
        if let Ok(mut sec) = state.secrets.lock() {
            *sec = None;
        }

        // Detect keyfile state and persist
        let ks =
            sigillum_personal_signer_verifier_lib::keyfile::check_keyfile_state(&ctx.keyfile_path)
                .unwrap_or(KeyfileState::Corrupted);

        if let Ok(mut g) = state.keyfile_state.lock() {
            *g = ks;
        }

        let route = match ks {
            KeyfileState::NotCorrupted => Route::Locked,
            KeyfileState::Missing | KeyfileState::Corrupted => Route::CreateKeyfile,
        };

        Self {
            state,
            ctx,
            route,
            last_route: route,
            prev_route: route,
            return_route: None,
            nav: LeftNav::new(),
            create_keyfile: CreateKeyfilePanel::new(),
            lock: LockPanel::new(),
            sign: SignPanel::new(),
            verify: VerifyPanel::new(),
            key_registry: KeyRegistryPanel::new(),
            security: SecurityPanel::new(),
            last_activity: Instant::now(),
            best_effort_warn: PanelMsgState::default(),
        }
    }

    fn reset_all_inputs(&mut self) {
        self.create_keyfile.reset_inputs();
        self.lock.reset_inputs();
        self.sign.reset_inputs();
        self.verify.reset_inputs();
        self.key_registry.reset_inputs();
        self.security.reset_inputs();
    }

    /// Derive minimal routing context once per frame
    fn derive_route_ctx(&self) -> RouteCtx {
        let unlocked = self
            .state
            .session
            .lock()
            .map(|g| g.unlocked)
            .unwrap_or(false);

        let keyfile_state = self
            .state
            .keyfile_state
            .lock()
            .map(|g| *g)
            .unwrap_or(KeyfileState::Missing);

        RouteCtx {
            unlocked,
            keyfile_state,
        }
    }

    /// Build a pure nav model once per frame
    fn derive_nav_model(&self, rctx: RouteCtx) -> NavModel {
        NavModel {
            show_tabs: rctx.keyfile_state == KeyfileState::NotCorrupted,
        }
    }
}

impl eframe::App for UiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let rctx = self.derive_route_ctx();
        let debug_ui = cfg!(debug_assertions);

        // Activity = clicks or deliberate text/keyboard input (not mouse movement).
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

        // Inactivity auto-lock (60s)
        if rctx.unlocked
            && self.route != Route::Locked
            && self.last_activity.elapsed() >= Duration::from_secs(60)
        {
            *&mut self.route = Route::Locked;
        }

        // Route transition hooks
        if self.route != self.prev_route {
            match message_clear_policy(self.prev_route, self.route) {
                MessageClearPolicy::ClearAllNonLockPanels => {
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

            let guarded = apply_route_guards(self.route, rctx);
            if guarded != self.route {
                self.route = guarded;
            }

            if entering_locked(self.prev_route, self.route) {
                // Lock app state (best-effort unlocks + clear unlocked + clear cached keys)
                let _ = lock_app_inner_if_unlocked(self.state.as_ref(), "ui_enter_locked");

                self.reset_all_inputs();

                // Reset inactivity timer so we don't immediately re-lock-loop after unlock
                self.last_activity = Instant::now();
            }

            self.prev_route = self.route;
        }

        if take_best_effort_warn_pending(self.state.as_ref()) {
            self.best_effort_warn
                .set_warn("Some security hardening steps failed. See Security Log.");
        }

        // Nav (pure view)
        let nav_model = self.derive_nav_model(rctx);
        self.nav.ui(ctx, nav_model, &mut self.route);

        // Panels
        egui::CentralPanel::default().show(ctx, |ui| {
            self.best_effort_warn.show(ui, debug_ui);

            match self.route {
                Route::CreateKeyfile => {
                    self.create_keyfile
                        .ui(ui, self.state.as_ref(), &self.ctx, &mut self.route)
                }

                Route::Locked => {
                    if self.last_route != Route::Locked {
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
