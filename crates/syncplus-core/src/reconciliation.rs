use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ActionJournalEntry, ActionOutcome, ActionReason, AnalysisError, AnalysisOutcome, FreshAnalysis,
    InventoryItem, ItemType, PlanActionKind, SyncProfile,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationFindingKind {
    Unexplained,
    Excluded,
    NewlyAppeared,
    Changed,
    Failed,
    Unavailable,
    Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationReason {
    Unexplained,
    Excluded,
    NewlyAppeared,
    Changed,
    Failed(ActionReason),
    Unavailable,
    Unverifiable,
}

impl ReconciliationReason {
    pub const fn kind(&self) -> ReconciliationFindingKind {
        match self {
            Self::Unexplained => ReconciliationFindingKind::Unexplained,
            Self::Excluded => ReconciliationFindingKind::Excluded,
            Self::NewlyAppeared => ReconciliationFindingKind::NewlyAppeared,
            Self::Changed => ReconciliationFindingKind::Changed,
            Self::Failed(_) => ReconciliationFindingKind::Failed,
            Self::Unavailable => ReconciliationFindingKind::Unavailable,
            Self::Unverifiable => ReconciliationFindingKind::Unverifiable,
        }
    }
}

impl fmt::Display for ReconciliationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unexplained => formatter.write_str("the item remains without an approved explanation"),
            Self::Excluded => formatter.write_str("the item is outside the approved synchronization scope"),
            Self::NewlyAppeared => formatter.write_str("the item appeared after the Source Inventory was frozen"),
            Self::Changed => formatter.write_str("the item changed after the Source Inventory was frozen"),
            Self::Failed(reason) => write!(formatter, "the action failed: {reason}"),
            Self::Unavailable => formatter.write_str("the peer or item was unavailable for verification"),
            Self::Unverifiable => formatter.write_str("the required destination or removal proof is unavailable"),
        }
    }
}

impl fmt::Display for ActionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TransferFailed => "transfer failed",
            Self::VerificationMismatch => "verification did not match",
            Self::SourceChanged => "the source changed",
            Self::PermissionDenied => "permission was denied",
            Self::CancellationRequested => "cancellation was requested",
            Self::DeferredForReview => "deferred for review",
            Self::FilesystemUncertain => "filesystem state is uncertain",
            Self::InterruptedBoundary => "an action boundary was interrupted",
            Self::DestinationUnavailable => "the destination was unavailable",
        };
        formatter.write_str(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceDrainStatus {
    NotApplicable,
    Drained,
    NotEmpty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationFinding {
    relative_path: PathBuf,
    reason: ReconciliationReason,
}

impl ReconciliationFinding {
    fn new(relative_path: PathBuf, reason: ReconciliationReason) -> Self {
        Self {
            relative_path,
            reason,
        }
    }

    pub(crate) fn from_parts(relative_path: PathBuf, reason: ReconciliationReason) -> Self {
        Self::new(relative_path, reason)
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn kind(&self) -> ReconciliationFindingKind {
        self.reason.kind()
    }

    pub fn reason(&self) -> &ReconciliationReason {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventorySnapshotItem {
    relative_path: PathBuf,
    item_type: ItemType,
    outcome: AnalysisOutcome,
    size: u64,
    modified_at_unix_nanos: Option<i64>,
    readonly: bool,
    permissions: Option<u32>,
    symlink_target: Option<PathBuf>,
    content_fingerprint: Option<[u8; 32]>,
}

impl InventorySnapshotItem {
    fn from_item(item: &InventoryItem) -> Self {
        Self {
            relative_path: item.relative_path().to_path_buf(),
            item_type: item.item_type(),
            outcome: item.outcome(),
            size: item.metadata().size(),
            modified_at_unix_nanos: unix_nanos(item.metadata().modified_at()),
            readonly: item.metadata().is_readonly(),
            permissions: item.metadata().permissions(),
            symlink_target: item.metadata().symlink_target().map(Path::to_path_buf),
            content_fingerprint: item.content_fingerprint().copied(),
        }
    }

    pub(crate) fn from_parts_with_permissions(
        relative_path: PathBuf,
        item_type: ItemType,
        outcome: AnalysisOutcome,
        size: u64,
        modified_at_unix_nanos: Option<i64>,
        readonly: bool,
        permissions: Option<u32>,
        symlink_target: Option<PathBuf>,
        content_fingerprint: Option<[u8; 32]>,
    ) -> Self {
        Self {
            relative_path,
            item_type,
            outcome,
            size,
            modified_at_unix_nanos,
            readonly,
            permissions,
            symlink_target,
            content_fingerprint,
        }
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
    }

    pub const fn outcome(&self) -> AnalysisOutcome {
        self.outcome
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn modified_at_unix_nanos(&self) -> Option<i64> {
        self.modified_at_unix_nanos
    }

    pub const fn is_readonly(&self) -> bool {
        self.readonly
    }

    pub const fn permissions(&self) -> Option<u32> {
        self.permissions
    }

    pub fn executable_permissions(&self) -> Option<u32> {
        self.permissions.map(|permissions| permissions & 0o111)
    }

    pub fn symlink_target(&self) -> Option<&Path> {
        self.symlink_target.as_deref()
    }

    pub fn content_fingerprint(&self) -> Option<&[u8; 32]> {
        self.content_fingerprint.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInventorySnapshot {
    peer_name: String,
    root: PathBuf,
    items: Vec<InventorySnapshotItem>,
}

impl SourceInventorySnapshot {
    pub fn from_inventory(inventory: &crate::SourceInventory) -> Self {
        Self {
            peer_name: inventory.peer_name().to_owned(),
            root: inventory.root().to_path_buf(),
            items: inventory.items().iter().map(InventorySnapshotItem::from_item).collect(),
        }
    }

    pub(crate) fn from_parts(
        peer_name: String,
        root: PathBuf,
        items: Vec<InventorySnapshotItem>,
    ) -> Self {
        Self {
            peer_name,
            root,
            items,
        }
    }

    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn items(&self) -> &[InventorySnapshotItem] {
        &self.items
    }

    pub fn item(&self, relative_path: impl AsRef<Path>) -> Option<&InventorySnapshotItem> {
        self.items
            .iter()
            .find(|item| item.relative_path == relative_path.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionReconciliation {
    source_drain_status: SourceDrainStatus,
    findings: Vec<ReconciliationFinding>,
}

impl CompletionReconciliation {
    pub fn reconcile(
        profile: &SyncProfile,
        inventory: &SourceInventorySnapshot,
        current: &FreshAnalysis,
        journal: &[ActionJournalEntry],
    ) -> Self {
        let mut findings = Vec::new();
        let mut expected_paths = BTreeSet::new();

        for expected in inventory.items() {
            expected_paths.insert(expected.relative_path().to_path_buf());
            if expected.outcome() == AnalysisOutcome::Excluded {
                push_unique(&mut findings, expected.relative_path().to_path_buf(), ReconciliationReason::Excluded);
                continue;
            }
            if expected.outcome() == AnalysisOutcome::Unsupported {
                push_unique(&mut findings, expected.relative_path().to_path_buf(), ReconciliationReason::Unverifiable);
                continue;
            }

            let current_source = current.source_inventory().item(expected.relative_path());
            let current_destination = current.destination_inventory().item(expected.relative_path());
            if let Some(source) = current_source {
                if !source_matches_snapshot(profile, expected, source) {
                    push_unique(&mut findings, expected.relative_path().to_path_buf(), ReconciliationReason::Changed);
                    continue;
                }
            }

            let path_journal: Vec<_> = journal
                .iter()
                .filter(|entry| entry.relative_path() == expected.relative_path())
                .collect();
            if let Some(reason) = journal_reason(&path_journal) {
                push_unique(&mut findings, expected.relative_path().to_path_buf(), reason);
                continue;
            }

            let destination_verified = current_destination
                .is_some_and(|destination| destination_matches_source(profile, expected, destination));
            let removal_verified = path_journal.iter().any(|entry| {
                entry.operation() == PlanActionKind::RemoveSourceAfterVerification
                    && matches!(entry.outcome(), ActionOutcome::Completed)
                    && entry
                        .removal_result()
                        .is_some_and(|result| removal_evidence_matches(expected, result.evidence()))
            });

            if current_source.is_none() && !removal_verified {
                push_unique(
                    &mut findings,
                    expected.relative_path().to_path_buf(),
                    if path_journal.is_empty() {
                        ReconciliationReason::Unexplained
                    } else {
                        ReconciliationReason::Unverifiable
                    },
                );
                continue;
            }

            if profile.options().safe_delete {
                let source_removal_required = matches!(
                    expected.item_type(),
                    ItemType::RegularFile | ItemType::Symlink
                );
                if (source_removal_required && current_source.is_some())
                    || !destination_verified
                    || (source_removal_required && !removal_verified)
                {
                    push_unique(
                        &mut findings,
                        expected.relative_path().to_path_buf(),
                        ReconciliationReason::Unverifiable,
                    );
                }
            } else if current_source.is_none() || !destination_verified {
                push_unique(
                    &mut findings,
                    expected.relative_path().to_path_buf(),
                    ReconciliationReason::Unverifiable,
                );
            }
        }

        for current_item in current.source_inventory().items() {
            if expected_paths.contains(current_item.relative_path()) {
                continue;
            }
            let reason = if current_item.outcome() == AnalysisOutcome::Excluded {
                ReconciliationReason::Excluded
            } else {
                ReconciliationReason::NewlyAppeared
            };
            push_unique(&mut findings, current_item.relative_path().to_path_buf(), reason);
        }

        if profile.options().destination_cleanup {
            for current_item in current.destination_inventory().items() {
                if current_item.outcome() != AnalysisOutcome::Included
                    || expected_paths.contains(current_item.relative_path())
                {
                    continue;
                }
                let has_completed_removal = journal.iter().any(|entry| {
                    entry.relative_path() == current_item.relative_path()
                        && entry.operation() == PlanActionKind::RemoveDestination
                        && matches!(entry.outcome(), ActionOutcome::Completed)
                });
                let path_journal: Vec<_> = journal
                    .iter()
                    .filter(|entry| entry.relative_path() == current_item.relative_path())
                    .collect();
                let reason = if has_completed_removal {
                    ReconciliationReason::Unverifiable
                } else {
                    journal_reason(&path_journal).unwrap_or(ReconciliationReason::Unexplained)
                };
                push_unique(&mut findings, current_item.relative_path().to_path_buf(), reason);
            }
        }

        let source_drain_status = if profile.options().safe_delete {
            if findings.is_empty() {
                SourceDrainStatus::Drained
            } else {
                SourceDrainStatus::NotEmpty
            }
        } else {
            SourceDrainStatus::NotApplicable
        };
        Self {
            source_drain_status,
            findings,
        }
    }

    pub fn unavailable(
        profile: &SyncProfile,
        inventory: &SourceInventorySnapshot,
        journal: &[ActionJournalEntry],
        error: &AnalysisError,
    ) -> Self {
        let mut findings = Vec::new();
        let affected_path = analysis_error_path(profile, error)
            .unwrap_or_else(|| inventory.root().to_path_buf());
        push_unique(&mut findings, affected_path, ReconciliationReason::Unavailable);
        for entry in journal {
            if let Some(reason) = journal_reason(std::slice::from_ref(&entry)) {
                push_unique(&mut findings, entry.relative_path().to_path_buf(), reason);
            }
        }
        Self {
            source_drain_status: if profile.options().safe_delete {
                SourceDrainStatus::NotEmpty
            } else {
                SourceDrainStatus::NotApplicable
            },
            findings,
        }
    }

    pub(crate) fn from_parts(
        source_drain_status: SourceDrainStatus,
        findings: Vec<ReconciliationFinding>,
    ) -> Self {
        Self {
            source_drain_status,
            findings,
        }
    }

    pub const fn source_drain_status(&self) -> SourceDrainStatus {
        self.source_drain_status
    }

    pub fn findings(&self) -> &[ReconciliationFinding] {
        &self.findings
    }

    pub const fn requires_review(&self) -> bool {
        !self.findings.is_empty()
    }
}

fn source_matches_snapshot(
    profile: &SyncProfile,
    expected: &InventorySnapshotItem,
    current: &InventoryItem,
) -> bool {
    if expected.item_type() != current.item_type()
        || expected.outcome() != current.outcome()
        || expected.size() != current.metadata().size()
        || expected.is_readonly() != current.metadata().is_readonly()
        || expected.executable_permissions() != current.metadata().executable_permissions()
        || expected.symlink_target() != current.metadata().symlink_target()
        || expected.content_fingerprint() != current.content_fingerprint()
    {
        return false;
    }
    if profile.options().metadata.timestamps() {
        return expected.modified_at_unix_nanos() == unix_nanos(current.metadata().modified_at());
    }
    true
}

fn destination_matches_source(
    profile: &SyncProfile,
    expected: &InventorySnapshotItem,
    destination: &InventoryItem,
) -> bool {
    if expected.item_type() != destination.item_type() {
        return false;
    }
    if expected.executable_permissions() != destination.metadata().executable_permissions() {
        return false;
    }
    match expected.item_type() {
        ItemType::RegularFile => {
            expected.size() == destination.metadata().size()
                && expected.content_fingerprint().is_some()
                && expected.content_fingerprint() == destination.content_fingerprint()
        }
        ItemType::Symlink => {
            !profile.options().metadata.symlink_targets()
                || expected.symlink_target() == destination.metadata().symlink_target()
        }
        ItemType::Directory => true,
        ItemType::Unsupported => false,
    }
}

fn removal_evidence_matches(expected: &InventorySnapshotItem, evidence: &crate::RecoveryEvidence) -> bool {
    evidence.destination_present()
        && evidence.destination_size() == Some(expected.size())
        && expected
            .content_fingerprint()
            .is_none_or(|hash| evidence.destination_sha256() == Some(hash))
}

fn journal_reason(entries: &[&ActionJournalEntry]) -> Option<ReconciliationReason> {
    entries.iter().find_map(|entry| match entry.outcome() {
        ActionOutcome::Failed(reason) => Some(if *reason == ActionReason::DestinationUnavailable {
            ReconciliationReason::Unavailable
        } else {
            ReconciliationReason::Failed(*reason)
        }),
        ActionOutcome::Unresolved(reason) => Some(if *reason == ActionReason::DestinationUnavailable {
                ReconciliationReason::Unavailable
            } else {
                ReconciliationReason::Failed(*reason)
            }),
        ActionOutcome::RecoveryReview(_) => Some(ReconciliationReason::Unverifiable),
        ActionOutcome::Cancelled
        | ActionOutcome::Interrupted
        | ActionOutcome::Deferred
        | ActionOutcome::InProgress => Some(ReconciliationReason::Unverifiable),
        ActionOutcome::Completed => None,
    })
}

fn push_unique(findings: &mut Vec<ReconciliationFinding>, path: PathBuf, reason: ReconciliationReason) {
    if !findings
        .iter()
        .any(|finding| finding.relative_path == path && finding.reason == reason)
    {
        findings.push(ReconciliationFinding::new(path, reason));
    }
}

fn analysis_error_path(profile: &SyncProfile, error: &AnalysisError) -> Option<PathBuf> {
    match error {
        AnalysisError::RootUnavailable { path, .. }
        | AnalysisError::RootNotDirectory { path, .. } => Some(path.clone()),
        AnalysisError::ReadDirectory { peer, path }
        | AnalysisError::ReadMetadata { peer, path }
        | AnalysisError::ReadFileContents { peer, path } => {
            let root = if profile.peer_a().name() == peer {
                profile.peer_a().root()
            } else {
                profile.peer_b().root()
            };
            Some(if path.is_absolute() {
                path.clone()
            } else {
                root.join(path)
            })
        }
        AnalysisError::ProcessSpecification(_)
        | AnalysisError::Plan(_)
        | AnalysisError::ProfileChanged
        | AnalysisError::StaleAnalysis { .. } => Some(selected_destination_root(profile).to_path_buf()),
    }
}

fn selected_destination_root(profile: &SyncProfile) -> &Path {
    match profile.source() {
        crate::OneWaySource::PeerA => profile.peer_b().root(),
        crate::OneWaySource::PeerB => profile.peer_a().root(),
    }
}

fn unix_nanos(time: Option<SystemTime>) -> Option<i64> {
    let time = time?;
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).ok(),
        Err(error) => i64::try_from(error.duration().as_nanos())
            .ok()
            .and_then(|nanos| nanos.checked_neg()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        DeletionMethod, FreshAnalysis, OneWaySource, Peer, SyncOptions, SyncProfile,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "syncplus-reconciliation-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("source")).expect("source should be creatable");
            fs::create_dir_all(root.join("destination"))
                .expect("destination should be creatable");
            Self { root }
        }

        fn source(&self) -> PathBuf {
            self.root.join("source")
        }

        fn destination(&self) -> PathBuf {
            self.root.join("destination")
        }

        fn profile(&self) -> SyncProfile {
            SyncProfile::new(
                "reconciliation fixture",
                Peer::new("source", self.source()),
                Peer::new("destination", self.destination()),
            )
            .with_source(OneWaySource::PeerA)
            .with_options(SyncOptions {
                safe_delete: true,
                deletion_method: Some(DeletionMethod::PermanentRemoval),
                ..SyncOptions::default()
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn write(path: impl AsRef<Path>, contents: &[u8]) {
        fs::write(path, contents).expect("fixture file should be writable");
    }

    #[test]
    fn reconciliation_requires_current_destination_proof_before_source_drained() {
        let fixture = Fixture::new();
        write(fixture.source().join("critical.txt"), b"critical source");
        let profile = fixture.profile();
        let initial = FreshAnalysis::analyze(&profile).expect("initial analysis");
        let inventory = SourceInventorySnapshot::from_inventory(initial.source_inventory());
        let current = FreshAnalysis::analyze(&profile).expect("current analysis");

        let result = CompletionReconciliation::reconcile(&profile, &inventory, &current, &[]);

        assert_eq!(result.source_drain_status(), SourceDrainStatus::NotEmpty);
        assert!(result.findings().iter().any(|finding| {
            finding.relative_path() == Path::new("critical.txt")
                && finding.kind() == ReconciliationFindingKind::Unverifiable
        }));
        assert!(result.requires_review());
    }

    #[test]
    fn reconciliation_preserves_excluded_changed_and_newly_appeared_reasons() {
        let fixture = Fixture::new();
        write(fixture.source().join("ignored.tmp"), b"ignored");
        write(fixture.source().join("changed.txt"), b"before");
        let profile = fixture.profile().with_exclusion("*.tmp");
        let initial = FreshAnalysis::analyze(&profile).expect("initial analysis");
        let inventory = SourceInventorySnapshot::from_inventory(initial.source_inventory());

        write(fixture.source().join("changed.txt"), b"after");
        write(fixture.source().join("new.txt"), b"new");
        let current = FreshAnalysis::analyze(&profile).expect("current analysis");
        let result = CompletionReconciliation::reconcile(&profile, &inventory, &current, &[]);

        assert!(result.findings().iter().any(|finding| {
            finding.relative_path() == Path::new("ignored.tmp")
                && finding.kind() == ReconciliationFindingKind::Excluded
        }));
        assert!(result.findings().iter().any(|finding| {
            finding.relative_path() == Path::new("changed.txt")
                && finding.kind() == ReconciliationFindingKind::Changed
        }));
        assert!(result.findings().iter().any(|finding| {
            finding.relative_path() == Path::new("new.txt")
                && finding.kind() == ReconciliationFindingKind::NewlyAppeared
        }));
    }

    #[test]
    fn reconciliation_reports_an_unexplained_source_disappearance() {
        let fixture = Fixture::new();
        write(fixture.source().join("missing.txt"), b"missing");
        let profile = fixture.profile();
        let initial = FreshAnalysis::analyze(&profile).expect("initial analysis");
        let inventory = SourceInventorySnapshot::from_inventory(initial.source_inventory());
        fs::remove_file(fixture.source().join("missing.txt")).expect("source should be removable");
        let current = FreshAnalysis::analyze(&profile).expect("current analysis");

        let result = CompletionReconciliation::reconcile(&profile, &inventory, &current, &[]);

        assert!(result.findings().iter().any(|finding| {
            finding.relative_path() == Path::new("missing.txt")
                && finding.kind() == ReconciliationFindingKind::Unexplained
        }));
        assert_eq!(result.source_drain_status(), SourceDrainStatus::NotEmpty);
    }
}
