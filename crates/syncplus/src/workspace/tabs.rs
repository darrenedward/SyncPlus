use eframe::egui;

use crate::theme::BrandTheme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkspaceTab {
    #[default]
    Folders,
    Options,
    Plan,
}

impl WorkspaceTab {
    pub const ALL: [Self; 3] = [Self::Folders, Self::Options, Self::Plan];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Folders => "Folders",
            Self::Options => "Options",
            Self::Plan => "Plan",
        }
    }
}

pub fn draw_tab_bar(ui: &mut egui::Ui, selected: &mut WorkspaceTab, theme: BrandTheme) {
    let height = 38.0;
    let full_width = ui.available_width();
    let (bar_rect, _) =
        ui.allocate_exact_size(egui::vec2(full_width, height), egui::Sense::hover());
    ui.painter().hline(
        bar_rect.x_range(),
        bar_rect.bottom() - 1.0,
        egui::Stroke::new(1.0, theme.border),
    );

    let mut cursor = bar_rect.left();
    for (index, tab) in WorkspaceTab::ALL.into_iter().enumerate() {
        let is_selected = *selected == tab;
        let color = if is_selected {
            theme.copper
        } else {
            theme.muted
        };
        let galley = ui.painter().layout_no_wrap(
            tab.label().to_owned(),
            egui::FontId::proportional(15.0),
            color,
        );
        let tab_width = (galley.size().x + 32.0).max(100.0);
        let tab_rect = egui::Rect::from_min_size(
            egui::pos2(cursor, bar_rect.top()),
            egui::vec2(tab_width, height),
        );
        let response = ui.interact(
            tab_rect,
            ui.id().with("workspace-tab").with(index),
            egui::Sense::click(),
        );
        if is_selected {
            ui.painter().rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(tab_rect.left() + 12.0, tab_rect.bottom() - 3.0),
                    egui::pos2(tab_rect.right() - 12.0, tab_rect.bottom()),
                ),
                egui::CornerRadius::same(2),
                theme.copper,
            );
        } else if response.hovered() {
            ui.painter().rect_filled(
                tab_rect.shrink2(egui::vec2(4.0, 6.0)),
                egui::CornerRadius::same(6),
                theme.copper_soft,
            );
        }
        ui.painter().galley(
            egui::pos2(
                tab_rect.center().x - galley.size().x / 2.0,
                tab_rect.center().y - galley.size().y / 2.0 - 1.0,
            ),
            galley,
            color,
        );
        if response.clicked() {
            *selected = tab;
        }
        cursor += tab_width;
    }
}

#[cfg(test)]
mod tests {
    use super::WorkspaceTab;

    #[test]
    fn workspace_tabs_are_folders_options_and_plan() {
        assert_eq!(
            WorkspaceTab::ALL.map(WorkspaceTab::label),
            ["Folders", "Options", "Plan"]
        );
        assert_ne!(WorkspaceTab::Options.label(), "Advance");
        assert_ne!(WorkspaceTab::Options.label(), "Advanced");
    }
}
