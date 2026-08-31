use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crate::{
    ActionJournalEntry, ActionOutcome, AnalysisOutcome, CompletionReconciliation,
    InventoryItem, InventorySnapshotItem, ItemType, MetadataRequirements, SourceInventorySnapshot,
};

/// The fields that define equality for a Mirror path.
///
/// Content and item type are always fundamental. The remaining fields are
/// compared only when their named metadata requirement is enabled. Specialist
/// metadata is not present in the inventory evidence yet, so requesting it
/// makes equality fail closed rather than silently settling an unverified path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorEquality {
    metadata: MetadataRequirements,
}

impl MirrorEquality {
    pub const fn new(metadata: MetadataRequirements) -> Self {
        Self { metadata }
    }

    pub const fn metadata_requirements(self) -> MetadataRequirements {
        self.metadata
    }

    pub fn equal(&self, left: &InventorySnapshotItem, right: &InventorySnapshotItem) -> bool {
        if left.outcome() != AnalysisOutcome::Included
            || right.outcome() != AnalysisOutcome::Included
        {
            return false;
        }
        self.equal_parts(
            left.item_type(),
            left.size(),
            left.modified_at_unix_nanos(),
            left.executable_permissions(),
            left.symlink_target(),
            left.content_fingerprint(),
            right.item_type(),
            right.size(),
            right.modified_at_unix_nanos(),
            right.executable_permissions(),
            right.symlink_target(),
            right.content_fingerprint(),
        )
    }

    pub(crate) fn equal_inventory(&self, left: &InventoryItem, right: &InventoryItem) -> bool {
        if left.outcome() != AnalysisOutcome::Included
            || right.outcome() != AnalysisOutcome::Included
        {
            return false;
        }
        self.equal_parts(
            left.item_type(),
            left.metadata().size(),
            left.metadata().modified_at(),
            left.metadata().executable_permissions(),
            left.metadata().symlink_target(),
            left.content_fingerprint(),
            right.item_type(),
            right.metadata().size(),
            right.metadata().modified_at(),
            right.metadata().executable_permissions(),
            right.metadata().symlink_target(),
            right.content_fingerprint(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn equal_parts(
        &self,
        left_type: ItemType,
        left_size: u64,
        left_modified_at: Option<impl IntoUnixNanos>,
        left_executable_permissions: Option<u32>,
        left_symlink_target: Option<&Path>,
        left_content: Option<&[u8; 32]>,
        right_type: ItemType,
        right_size: u64,
        right_modified_at: Option<impl IntoUnixNanos>,
        right_executable_permissions: Option<u32>,
        right_symlink_target: Option<&Path>,
        right_content: Option<&[u8; 32]>,
    ) -> bool {
        if left_type != right_type {
            return false;
        }
        if self.metadata.specialist_metadata().any() {
            return false;
        }
        if left_type == ItemType::RegularFile
            && (left_size != right_size || left_content.is_none() || left_content != right_content)
        {
            return false;
        }
        if self.metadata.executable_permissions()
            && left_executable_permissions != right_executable_permissions
        {
            return false;
        }
        if self.metadata.symlink_targets() && left_symlink_target != right_symlink_target {
            return false;
        }
        if self.metadata.timestamps()
            && normalize_modified_at(left_modified_at) != normalize_modified_at(right_modified_at)
        {
            return false;
        }
        true
    }
}

fn normalize_modified_at<T: IntoUnixNanos>(value: Option<T>) -> Option<i64> {
    value.and_then(IntoUnixNanos::into_unix_nanos)
}

trait IntoUnixNanos {
    fn into_unix_nanos(self) -> Option<i64>;
}

impl IntoUnixNanos for i64 {
    fn into_unix_nanos(self) -> Option<i64> {
        Some(self)
    }
}

impl IntoUnixNanos for std::time::SystemTime {
    fn into_unix_nanos(self) -> Option<i64> {
        const NANOS_PER_SECOND: i128 = 1_000_000_000;
        match self.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => i64::try_from(
                i128::from(duration.as_secs()) * NANOS_PER_SECOND
                    + i128::from(duration.subsec_nanos()),
            )
            .ok(),
            Err(error) => i64::try_from(
                -(i128::from(error.duration().as_secs()) * NANOS_PER_SECOND
                    + i128::from(error.duration().subsec_nanos())),
            )
            .ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBaselineItemState {
    item_type: ItemType,
    size: u64,
    modified_at_unix_nanos: Option<i64>,
    readonly: bool,
    executable_permissions: Option<u32>,
    symlink_target: Option<PathBuf>,
    content_fingerprint: Option<[u8; 32]>,
}

impl SyncBaselineItemState {
    fn from_snapshot(item: &InventorySnapshotItem) -> Self {
        Self {
            item_type: item.item_type(),
            size: item.size(),
            modified_at_unix_nanos: item.modified_at_unix_nanos(),
            readonly: item.is_readonly(),
            executable_permissions: item.executable_permissions(),
            symlink_target: item.symlink_target().map(Path::to_path_buf),
            content_fingerprint: item.content_fingerprint().copied(),
        }
    }

    pub(crate) fn from_parts(
        item_type: ItemType,
        size: u64,
        modified_at_unix_nanos: Option<i64>,
        readonly: bool,
        executable_permissions: Option<u32>,
        symlink_target: Option<PathBuf>,
        content_fingerprint: Option<[u8; 32]>,
    ) -> Self {
        Self {
            item_type,
            size,
            modified_at_unix_nanos,
            readonly,
            executable_permissions,
            symlink_target,
            content_fingerprint,
        }
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
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

    pub const fn executable_permissions(&self) -> Option<u32> {
        self.executable_permissions
    }

    pub fn symlink_target(&self) -> Option<&Path> {
        self.symlink_target.as_deref()
    }

    pub fn content_fingerprint(&self) -> Option<&[u8; 32]> {
        self.content_fingerprint.as_ref()
    }

    fn equal(&self, other: &Self, equality: MirrorEquality) -> bool {
        equality.equal_parts(
            self.item_type,
            self.size,
            self.modified_at_unix_nanos,
            self.executable_permissions,
            self.symlink_target(),
            self.content_fingerprint(),
            other.item_type,
            other.size,
            other.modified_at_unix_nanos,
            other.executable_permissions,
            other.symlink_target(),
            other.content_fingerprint(),
        )
    }

    pub(crate) fn equal_inventory(
        &self,
        current: &InventorySnapshotItem,
        equality: MirrorEquality,
    ) -> bool {
        let current = Self::from_snapshot(current);
        self.equal(&current, equality)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBaselineItem {
    relative_path: PathBuf,
    peer_a: Option<SyncBaselineItemState>,
    peer_b: Option<SyncBaselineItemState>,
}

impl SyncBaselineItem {
    pub(crate) fn from_parts(
        relative_path: PathBuf,
        peer_a: Option<SyncBaselineItemState>,
        peer_b: Option<SyncBaselineItemState>,
    ) -> Self {
        Self {
            relative_path,
            peer_a,
            peer_b,
        }
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn peer_a(&self) -> Option<&SyncBaselineItemState> {
        self.peer_a.as_ref()
    }

    pub fn peer_b(&self) -> Option<&SyncBaselineItemState> {
        self.peer_b.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncBaselineItemStatus {
    Unchanged,
    New,
    Changed,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBaselineComparison {
    relative_path: PathBuf,
    peer_a: SyncBaselineItemStatus,
    peer_b: SyncBaselineItemStatus,
}

impl SyncBaselineComparison {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn peer_a(&self) -> SyncBaselineItemStatus {
        self.peer_a
    }

    pub const fn peer_b(&self) -> SyncBaselineItemStatus {
        self.peer_b
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBaseline {
    profile_name: String,
    peer_a_name: String,
    peer_a_root: PathBuf,
    peer_b_name: String,
    peer_b_root: PathBuf,
    metadata: MetadataRequirements,
    items: Vec<SyncBaselineItem>,
}

impl SyncBaseline {
    pub fn from_inventories(
        profile_name: impl Into<String>,
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
        metadata: MetadataRequirements,
    ) -> Self {
        let mut by_path: BTreeMap<PathBuf, (Option<SyncBaselineItemState>, Option<SyncBaselineItemState>)> =
            BTreeMap::new();
        for item in peer_a.items().iter().filter(|item| item.outcome() == AnalysisOutcome::Included) {
            by_path.entry(item.relative_path().to_path_buf()).or_default().0 =
                Some(SyncBaselineItemState::from_snapshot(item));
        }
        for item in peer_b.items().iter().filter(|item| item.outcome() == AnalysisOutcome::Included) {
            by_path.entry(item.relative_path().to_path_buf()).or_default().1 =
                Some(SyncBaselineItemState::from_snapshot(item));
        }
        Self::from_parts(
            profile_name.into(),
            peer_a.peer_name().to_owned(),
            peer_a.root().to_path_buf(),
            peer_b.peer_name().to_owned(),
            peer_b.root().to_path_buf(),
            metadata,
            by_path
                .into_iter()
                .map(|(relative_path, (peer_a, peer_b))| SyncBaselineItem {
                    relative_path,
                    peer_a,
                    peer_b,
                })
                .collect(),
        )
    }

    pub fn from_reconciled_inventories(
        profile_name: impl Into<String>,
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
        journal: &[ActionJournalEntry],
        reconciliation: &CompletionReconciliation,
        metadata: MetadataRequirements,
    ) -> Self {
        let equality = MirrorEquality::new(metadata);
        let blocked_paths: BTreeSet<_> = reconciliation
            .findings()
            .iter()
            .map(|finding| finding.relative_path().to_path_buf())
            .collect();
        let journal_blocked = |path: &Path| {
            journal.iter().any(|entry| {
                entry.relative_path() == path && !matches!(entry.outcome(), ActionOutcome::Completed)
            })
        };
        let mut settled_a = Vec::new();
        let mut settled_b = Vec::new();
        for path in peer_a
            .items()
            .iter()
            .map(|item| item.relative_path())
            .chain(peer_b.items().iter().map(|item| item.relative_path()))
            .collect::<BTreeSet<_>>()
        {
            if blocked_paths.contains(path) || journal_blocked(path) {
                continue;
            }
            let Some(left) = peer_a.item(path) else { continue };
            let Some(right) = peer_b.item(path) else { continue };
            if !equality.equal(left, right) {
                continue;
            }
            settled_a.push(left.clone());
            settled_b.push(right.clone());
        }
        Self::from_inventories(
            profile_name,
            &SourceInventorySnapshot::from_parts(
                peer_a.peer_name().to_owned(),
                peer_a.root().to_path_buf(),
                settled_a,
            ),
            &SourceInventorySnapshot::from_parts(
                peer_b.peer_name().to_owned(),
                peer_b.root().to_path_buf(),
                settled_b,
            ),
            metadata,
        )
    }

    pub(crate) fn from_parts(
        profile_name: String,
        peer_a_name: String,
        peer_a_root: PathBuf,
        peer_b_name: String,
        peer_b_root: PathBuf,
        metadata: MetadataRequirements,
        items: Vec<SyncBaselineItem>,
    ) -> Self {
        Self {
            profile_name,
            peer_a_name,
            peer_a_root,
            peer_b_name,
            peer_b_root,
            metadata,
            items,
        }
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn peer_a_name(&self) -> &str {
        &self.peer_a_name
    }

    pub fn peer_a_root(&self) -> &Path {
        &self.peer_a_root
    }

    pub fn peer_b_name(&self) -> &str {
        &self.peer_b_name
    }

    pub fn peer_b_root(&self) -> &Path {
        &self.peer_b_root
    }

    pub const fn metadata_requirements(&self) -> MetadataRequirements {
        self.metadata
    }

    pub fn items(&self) -> &[SyncBaselineItem] {
        &self.items
    }

    pub fn item(&self, relative_path: impl AsRef<Path>) -> Option<&SyncBaselineItem> {
        self.items
            .iter()
            .find(|item| item.relative_path() == relative_path.as_ref())
    }

    pub fn compare(
        &self,
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
    ) -> Vec<SyncBaselineComparison> {
        let equality = MirrorEquality::new(self.metadata);
        let current_a: BTreeMap<_, _> = peer_a
            .items()
            .iter()
            .filter(|item| item.outcome() == AnalysisOutcome::Included)
            .map(|item| (item.relative_path(), item))
            .collect();
        let current_b: BTreeMap<_, _> = peer_b
            .items()
            .iter()
            .filter(|item| item.outcome() == AnalysisOutcome::Included)
            .map(|item| (item.relative_path(), item))
            .collect();
        let mut paths: BTreeSet<PathBuf> = self
            .items
            .iter()
            .map(|item| item.relative_path.clone())
            .collect();
        paths.extend(current_a.keys().map(|path| (*path).to_path_buf()));
        paths.extend(current_b.keys().map(|path| (*path).to_path_buf()));

        paths
            .into_iter()
            .map(|relative_path| {
                let baseline = self.item(&relative_path);
                let baseline_a = baseline.and_then(SyncBaselineItem::peer_a);
                let baseline_b = baseline.and_then(SyncBaselineItem::peer_b);
                let current_a_item = current_a.get(relative_path.as_path()).copied();
                let current_b_item = current_b.get(relative_path.as_path()).copied();
                SyncBaselineComparison {
                    relative_path,
                    peer_a: compare_side(baseline_a, current_a_item, equality),
                    peer_b: compare_side(baseline_b, current_b_item, equality),
                }
            })
            .collect()
    }

    pub fn merge_settled(&self, updates: &Self) -> Self {
        if self.profile_name != updates.profile_name
            || self.peer_a_name != updates.peer_a_name
            || self.peer_a_root != updates.peer_a_root
            || self.peer_b_name != updates.peer_b_name
            || self.peer_b_root != updates.peer_b_root
        {
            return updates.clone();
        }
        let mut items: BTreeMap<_, _> = self
            .items
            .iter()
            .cloned()
            .map(|item| (item.relative_path.clone(), item))
            .collect();
        for item in &updates.items {
            items.insert(item.relative_path.clone(), item.clone());
        }
        Self::from_parts(
            self.profile_name.clone(),
            self.peer_a_name.clone(),
            self.peer_a_root.clone(),
            self.peer_b_name.clone(),
            self.peer_b_root.clone(),
            updates.metadata,
            items.into_values().collect(),
        )
    }
}

fn compare_side(
    baseline: Option<&SyncBaselineItemState>,
    current: Option<&InventorySnapshotItem>,
    equality: MirrorEquality,
) -> SyncBaselineItemStatus {
    match (baseline, current) {
        (None, None) => SyncBaselineItemStatus::Unchanged,
        (None, Some(_)) => SyncBaselineItemStatus::New,
        (Some(_), None) => SyncBaselineItemStatus::Absent,
        (Some(baseline), Some(current)) => {
            let current = SyncBaselineItemState::from_snapshot(current);
            if baseline.equal(&current, equality) {
                SyncBaselineItemStatus::Unchanged
            } else {
                SyncBaselineItemStatus::Changed
            }
        }
    }
}
