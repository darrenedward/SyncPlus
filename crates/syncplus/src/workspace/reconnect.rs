use std::path::{Path, PathBuf};

use syncplus_core::{OneWaySource, PrecheckBlockerKind, PrecheckResult, SyncMode, SyncProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderRole {
    Source,
    Destination,
    PeerA,
    PeerB,
}

impl FolderRole {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
            Self::PeerA => "Peer A",
            Self::PeerB => "Peer B",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnavailableFolder {
    pub role: FolderRole,
    pub path: PathBuf,
    pub looks_removable: bool,
}

impl UnavailableFolder {
    pub fn headline(&self) -> String {
        format!("The {} folder is not connected.", self.role.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectPrompt {
    pub folders: Vec<UnavailableFolder>,
}

impl ReconnectPrompt {
    pub fn from_profile_precheck(profile: &SyncProfile, precheck: &PrecheckResult) -> Option<Self> {
        let (source, destination) = mapped_peers(profile);
        let mut folders = Vec::new();
        for blocker in precheck.blockers() {
            if blocker.kind() != PrecheckBlockerKind::PeerUnavailable {
                continue;
            }
            let path = blocker.path();
            let role = if path == source.root() {
                if profile.mode() == SyncMode::OneWay {
                    FolderRole::Source
                } else {
                    FolderRole::PeerA
                }
            } else if path == destination.root() {
                if profile.mode() == SyncMode::OneWay {
                    FolderRole::Destination
                } else {
                    FolderRole::PeerB
                }
            } else {
                continue;
            };
            folders.push(UnavailableFolder {
                role,
                path: path.to_path_buf(),
                looks_removable: looks_like_removable_mount(path),
            });
        }
        folders.sort_by_key(|folder| folder.role as u8);
        folders.dedup_by(|left, right| left.path == right.path);
        (!folders.is_empty()).then_some(Self { folders })
    }

    pub fn window_title(&self) -> &'static str {
        if self.folders.len() > 1 {
            "Folders not connected"
        } else {
            "Folder not connected"
        }
    }

    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for folder in &self.folders {
            lines.push(folder.headline());
            lines.push(folder.path.display().to_string());
            if folder.looks_removable {
                lines.push(
                    "This looks like a removable drive. Plug it in, wait until the folder is available, then retry."
                        .to_owned(),
                );
            } else {
                lines.push("Connect or mount this folder, then retry.".to_owned());
            }
        }
        lines.push("Retry checks the same saved path. It does not start a Sync Run.".to_owned());
        lines.push("No files were changed.".to_owned());
        lines
    }
}

pub fn looks_like_removable_mount(path: &Path) -> bool {
    path.starts_with("/media") || path.starts_with("/run/media") || path.starts_with("/mnt")
}

fn mapped_peers(profile: &SyncProfile) -> (&syncplus_core::Peer, &syncplus_core::Peer) {
    match profile.mode() {
        SyncMode::OneWay => match profile.source() {
            OneWaySource::PeerA => (profile.peer_a(), profile.peer_b()),
            OneWaySource::PeerB => (profile.peer_b(), profile.peer_a()),
        },
        SyncMode::Mirror => (profile.peer_a(), profile.peer_b()),
    }
}

#[cfg(test)]
mod tests {
    use super::{FolderRole, ReconnectPrompt, UnavailableFolder, looks_like_removable_mount};
    use std::path::PathBuf;

    fn prompt(folders: Vec<UnavailableFolder>) -> ReconnectPrompt {
        ReconnectPrompt { folders }
    }

    #[test]
    fn removable_hint_uses_common_mount_prefixes_without_naming_a_device_class() {
        assert!(looks_like_removable_mount(
            PathBuf::from("/mnt/elements/Charts").as_path()
        ));
        assert!(looks_like_removable_mount(
            PathBuf::from("/media/curryman/USB").as_path()
        ));
        assert!(looks_like_removable_mount(
            PathBuf::from("/run/media/curryman/SD").as_path()
        ));
        assert!(!looks_like_removable_mount(
            PathBuf::from("/home/curryman/Documents").as_path()
        ));
        let copy = prompt(vec![UnavailableFolder {
            role: FolderRole::Source,
            path: PathBuf::from("/mnt/elements/Charts"),
            looks_removable: true,
        }])
        .lines()
        .join("\n");
        assert!(copy.contains("removable drive"));
        assert!(!copy.to_ascii_lowercase().contains("dvd"));
        assert!(!copy.to_ascii_lowercase().contains("cd-rom"));
        assert!(!copy.to_ascii_lowercase().contains("usb"));
        assert!(!copy.to_ascii_lowercase().contains("memory card"));
    }

    #[test]
    fn source_reconnect_copy_names_the_folder_and_offers_retry_without_starting_a_run() {
        let copy = prompt(vec![UnavailableFolder {
            role: FolderRole::Source,
            path: PathBuf::from("/mnt/elements/Charts"),
            looks_removable: true,
        }]);
        assert_eq!(copy.window_title(), "Folder not connected");
        let joined = copy.lines().join("\n");
        assert!(joined.contains("The source folder is not connected."));
        assert!(joined.contains("/mnt/elements/Charts"));
        assert!(joined.contains("Retry checks the same saved path. It does not start a Sync Run."));
        assert!(joined.contains("No files were changed."));
    }

    #[test]
    fn both_peers_use_the_plural_window_title() {
        let copy = prompt(vec![
            UnavailableFolder {
                role: FolderRole::Source,
                path: PathBuf::from("/mnt/a"),
                looks_removable: true,
            },
            UnavailableFolder {
                role: FolderRole::Destination,
                path: PathBuf::from("/mnt/b"),
                looks_removable: true,
            },
        ]);
        assert_eq!(copy.window_title(), "Folders not connected");
        let joined = copy.lines().join("\n");
        assert!(joined.contains("The source folder is not connected."));
        assert!(joined.contains("The destination folder is not connected."));
    }
}
