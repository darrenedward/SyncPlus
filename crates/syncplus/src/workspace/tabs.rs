use eframe::egui;

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

pub fn draw_tab_bar(ui: &mut egui::Ui, selected: &mut WorkspaceTab) {
    ui.horizontal(|ui| {
        for tab in WorkspaceTab::ALL {
            if ui.selectable_label(*selected == tab, tab.label()).clicked() {
                *selected = tab;
            }
        }
    });
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
