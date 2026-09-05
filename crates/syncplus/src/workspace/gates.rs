#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FolderGate {
    #[default]
    Unknown,
    Checking,
    Ready,
    Blocked,
    RemoteUnproven,
}

impl FolderGate {
    pub const fn dry_run_enabled(self) -> bool {
        matches!(self, Self::Ready | Self::RemoteUnproven)
    }

    pub const fn synchronise_enabled(self, review_confirmed: bool) -> bool {
        self.dry_run_enabled() && review_confirmed
    }

    pub const fn check_folders_enabled(self) -> bool {
        matches!(self, Self::Unknown | Self::Blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::FolderGate;

    #[test]
    fn missing_folders_block_dry_run_and_synchronise() {
        assert!(!FolderGate::Blocked.dry_run_enabled());
        assert!(!FolderGate::Blocked.synchronise_enabled(true));
        assert!(!FolderGate::Unknown.dry_run_enabled());
        assert!(!FolderGate::Checking.dry_run_enabled());
        assert!(FolderGate::Blocked.check_folders_enabled());
    }

    #[test]
    fn ready_folders_allow_dry_run_but_not_sync_until_confirmation() {
        assert!(FolderGate::Ready.dry_run_enabled());
        assert!(!FolderGate::Ready.synchronise_enabled(false));
        assert!(FolderGate::Ready.synchronise_enabled(true));
    }

    #[test]
    fn ssh_peers_stay_unproven_until_dry_run() {
        assert!(FolderGate::RemoteUnproven.dry_run_enabled());
        assert!(!FolderGate::RemoteUnproven.synchronise_enabled(false));
    }
}
