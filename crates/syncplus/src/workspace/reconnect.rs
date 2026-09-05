use std::path::{Path, PathBuf};

use syncplus_core::{OneWaySource, PrecheckBlockerKind, PrecheckResult, SyncMode, SyncProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderRole {
    Source,
    Destination,
    PeerA,
    PeerB,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnavailableFolder {
    pub role: FolderRole,
    pub path: PathBuf,
    pub looks_removable: bool,
}

pub const RETRY_HINT: &str = "Retry checks the same saved path. It does not start a Sync Run.";

impl UnavailableFolder {
    pub fn inline_message(&self) -> &'static str {
        if self.looks_removable {
            "This folder is not connected. Plug the drive in, then retry."
        } else {
            "This folder is not connected. Connect or mount it, then retry."
        }
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

    pub fn folder_matching_path(&self, path: &str) -> Option<&UnavailableFolder> {
        let path = std::path::Path::new(path.trim());
        self.folders.iter().find(|folder| folder.path == path)
    }

    pub fn inline_message_for_path(&self, path: &str) -> Option<&'static str> {
        self.folder_matching_path(path)
            .map(UnavailableFolder::inline_message)
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
    use super::{
        FolderRole, RETRY_HINT, ReconnectPrompt, UnavailableFolder, looks_like_removable_mount,
    };
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
        .inline_message_for_path("/mnt/elements/Charts")
        .expect("source path");
        assert_eq!(
            copy,
            "This folder is not connected. Plug the drive in, then retry."
        );
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
        assert_eq!(
            copy.inline_message_for_path("/mnt/elements/Charts"),
            Some("This folder is not connected. Plug the drive in, then retry.")
        );
        assert_eq!(
            copy.folder_matching_path("/mnt/elements/Charts")
                .map(|folder| folder.role),
            Some(FolderRole::Source)
        );
        assert_eq!(
            RETRY_HINT,
            "Retry checks the same saved path. It does not start a Sync Run."
        );
    }

    #[test]
    fn destination_error_stays_on_the_destination_path() {
        let copy = prompt(vec![UnavailableFolder {
            role: FolderRole::Destination,
            path: PathBuf::from("/home/curryman/Charts"),
            looks_removable: false,
        }]);
        assert_eq!(
            copy.inline_message_for_path("/home/curryman/Charts"),
            Some("This folder is not connected. Connect or mount it, then retry.")
        );
        assert_eq!(copy.inline_message_for_path("/mnt/elements/Charts"), None);
    }

    #[test]
    fn both_peers_keep_independent_inline_messages() {
        let copy = prompt(vec![
            UnavailableFolder {
                role: FolderRole::Source,
                path: PathBuf::from("/mnt/a"),
                looks_removable: true,
            },
            UnavailableFolder {
                role: FolderRole::Destination,
                path: PathBuf::from("/home/curryman/Charts"),
                looks_removable: false,
            },
        ]);
        assert_eq!(
            copy.inline_message_for_path("/mnt/a"),
            Some("This folder is not connected. Plug the drive in, then retry.")
        );
        assert_eq!(
            copy.inline_message_for_path("/home/curryman/Charts"),
            Some("This folder is not connected. Connect or mount it, then retry.")
        );
    }
}
