// src/ui/message.rs

use sigillium_personal_signer_verifier_lib::error::{AppError, UserMsgKind};

use super::egui;
use super::egui::{Color32, Ui};

#[derive(Clone, Debug, Default)]
pub struct PanelMsgState {
    kind: Option<UserMsgKind>,
    short: Option<String>,
    detail: Option<String>,
}

impl PanelMsgState {
    pub fn clear(&mut self) {
        self.kind = None;
        self.short = None;
        self.detail = None;
    }

    pub fn is_set(&self) -> bool {
        self.kind.is_some() && self.short.is_some()
    }

    pub fn set_success(&mut self, short: impl Into<String>) {
        self.kind = Some(UserMsgKind::Success);
        self.short = Some(short.into());
        self.detail = None;
    }

    pub fn set_warn(&mut self, short: impl Into<String>) {
        self.kind = Some(UserMsgKind::Warn);
        self.short = Some(short.into());
        self.detail = None;
    }

    pub fn set_info(&mut self, short: impl Into<String>) {
        self.kind = Some(UserMsgKind::Info);
        self.short = Some(short.into());
        self.detail = None;
    }

    pub fn set_error(&mut self, short: impl Into<String>) {
        self.kind = Some(UserMsgKind::Error);
        self.short = Some(short.into());
        self.detail = None;
    }

    pub fn from_app_error(&mut self, err: &AppError, debug_ui: bool) {
        let msg = if debug_ui {
            err.to_string()
        } else {
            err.user_msg().short.to_string()
        };

        self.set_error(msg);
    }

    pub fn show(&self, ui: &mut Ui, debug_ui: bool) {
        if !self.is_set() {
            return;
        }

        let kind = self.kind.unwrap();
        let short = self.short.as_deref().unwrap_or("");
        let detail = self.detail.as_deref();

        let text = if debug_ui {
            detail.unwrap_or(short)
        } else {
            short
        };

        let (stroke, fill) = match kind {
            UserMsgKind::Success => (
                Color32::from_rgb(0, 220, 90), // neon green stroke
                Color32::from_rgb(0, 80, 40),  // dark green fill
            ),
            UserMsgKind::Warn => (
                Color32::from_rgb(255, 170, 0), // neon amber stroke
                Color32::from_rgb(90, 60, 0),   // dark amber fill
            ),
            UserMsgKind::Error => (
                Color32::from_rgb(255, 60, 60), // neon red stroke
                Color32::from_rgb(90, 0, 0),    // dark red fill
            ),
            UserMsgKind::Info => (
                Color32::from_rgb(80, 180, 255), // cool blue stroke
                Color32::from_rgb(10, 40, 80),   // dark blue fill
            ),
        };

        egui::Frame::NONE
            .fill(fill)
            .stroke(egui::Stroke::new(1.0, stroke))
            .corner_radius(egui::CornerRadius::same(8u8))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.colored_label(stroke, text);
            });
    }
}
