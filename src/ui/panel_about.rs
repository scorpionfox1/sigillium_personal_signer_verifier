// src/ui/panel_about.rs

use crate::ui::message::PanelMsgState;
use crate::ui::widgets;
use eframe::egui;

const README_TEXT: &str = include_str!("../../README.md");

pub struct AboutPanel {
    msg: PanelMsgState,
    readme_text: String,
}

impl AboutPanel {
    pub fn new() -> Self {
        Self {
            msg: PanelMsgState::default(),
            readme_text: README_TEXT.to_string(),
        }
    }

    pub fn reset_inputs(&mut self) {
        self.msg.clear();
    }

    pub fn clear_messages(&mut self) {
        self.msg.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        widgets::panel_title(ui, "About");
        ui.separator();
        ui.add_space(6.0);

        widgets::doc_panel_container(ui, |ui| {
            ui.horizontal(|ui| {
                let preview_btn =
                    widgets::large_button("View in Browser").min_size(egui::vec2(160.0, 34.0));
                if ui.add(preview_btn).clicked() {
                    widgets::open_markdown_preview(
                        "Sigillium Personal Signer & Verifier",
                        &self.readme_text,
                        &mut self.msg,
                    );
                }
            });

            ui.add_space(6.0);
            self.msg.show(ui);
            ui.add_space(6.0);

            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    let available_width = ui.available_width();
                    ui.add(
                        egui::TextEdit::multiline(&mut self.readme_text)
                            .interactive(false)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(24)
                            .desired_width(available_width),
                    );
                });
        });
    }
}
