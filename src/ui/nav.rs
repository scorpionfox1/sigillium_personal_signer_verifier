// src/ui/nav.rs

use crate::ui::Route;
use eframe::egui;

/// What the nav should show (derived by ui/mod.rs)
#[derive(Clone, Copy, Debug)]
pub struct NavModel {
    pub show_tabs: bool,
}

pub struct LeftNav;

impl LeftNav {
    pub fn new() -> Self {
        Self
    }

    /// Pure view: renders from NavModel and mutates route on click
    pub fn ui(&mut self, ctx: &egui::Context, model: NavModel, route: &mut Route) {
        egui::SidePanel::left("left_nav")
            .resizable(false)
            .min_width(160.0)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    // Lock button (top)
                    let is_locked = matches!(*route, Route::Locked);
                    if !matches!(*route, Route::CreateKeyfile) {
                        if ui
                            .add_enabled(!is_locked, egui::Button::new("Lock"))
                            .clicked()
                        {
                            *route = Route::Locked;
                        }
                    }

                    ui.separator();

                    if model.show_tabs {
                        ui.add_enabled_ui(!is_locked, |ui| {
                            nav_btn(ui, route, Route::Sign, "Sign");
                            nav_btn(ui, route, Route::Verify, "Verify");
                            nav_btn(ui, route, Route::KeyRegistry, "Key Registry");
                            nav_btn(ui, route, Route::Security, "Security");
                        });
                    }
                });
            });
    }
}

fn nav_btn(ui: &mut egui::Ui, route: &mut Route, target: Route, label: &str) {
    let selected = *route == target;
    if ui.selectable_label(selected, label).clicked() {
        *route = target;
    }
}
