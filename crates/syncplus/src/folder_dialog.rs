use std::path::PathBuf;

use rfd::FileDialog;

/// Native folder picker parented to the SyncPlus window so it cannot open behind it.
pub fn pick_folder(frame: &eframe::Frame, title: &str) -> Option<PathBuf> {
    let dialog = FileDialog::new().set_title(title);
    match frame.winit_window() {
        Some(window) => dialog.set_parent(window.as_ref()).pick_folder(),
        None => dialog.pick_folder(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFolderPick {
    pub peer_a: bool,
    pub title: String,
    pub check_folders: bool,
}

impl PendingFolderPick {
    pub fn source(check_folders: bool) -> Self {
        Self {
            peer_a: true,
            title: "Select source folder".to_owned(),
            check_folders,
        }
    }

    pub fn destination(check_folders: bool) -> Self {
        Self {
            peer_a: false,
            title: "Select destination folder".to_owned(),
            check_folders,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PendingFolderPick;

    #[test]
    fn wizard_and_workspace_browse_name_the_same_saved_folders() {
        let source = PendingFolderPick::source(false);
        let destination = PendingFolderPick::destination(true);
        assert!(source.peer_a);
        assert!(!destination.peer_a);
        assert!(!source.check_folders);
        assert!(destination.check_folders);
        assert_eq!(source.title, "Select source folder");
        assert_eq!(destination.title, "Select destination folder");
        assert!(!source.title.to_ascii_lowercase().contains("shell"));
    }
}
