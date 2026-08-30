use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, DirEntry, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{OneWaySource, ProcessSpecError, ProcessSpecification, SyncProfile};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    RegularFile,
    Directory,
    Symlink,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemMetadata {
    size: u64,
    modified_at: Option<SystemTime>,
    readonly: bool,
    symlink_target: Option<PathBuf>,
}

impl ItemMetadata {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn modified_at(&self) -> Option<SystemTime> {
        self.modified_at
    }

    pub const fn is_readonly(&self) -> bool {
        self.readonly
    }

    pub fn symlink_target(&self) -> Option<&Path> {
        self.symlink_target.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisOutcome {
    Included,
    Excluded,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecision {
    InApprovedSyncScope,
    OutsideApprovedSyncScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryItem {
    relative_path: PathBuf,
    item_type: ItemType,
    metadata: ItemMetadata,
    outcome: AnalysisOutcome,
    // This detects stale analysis only; it never authorizes Verified Removal.
    content_fingerprint: Option<[u8; 32]>,
}

impl InventoryItem {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn path_identity(&self) -> &Path {
        self.relative_path()
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
    }

    pub fn metadata(&self) -> &ItemMetadata {
        &self.metadata
    }

    pub const fn outcome(&self) -> AnalysisOutcome {
        self.outcome
    }

    pub const fn analysis_outcome(&self) -> AnalysisOutcome {
        self.outcome()
    }

    pub const fn scope(&self) -> ScopeDecision {
        match self.outcome {
            AnalysisOutcome::Included => ScopeDecision::InApprovedSyncScope,
            AnalysisOutcome::Excluded | AnalysisOutcome::Unsupported => {
                ScopeDecision::OutsideApprovedSyncScope
            }
        }
    }

    pub const fn is_eligible(&self) -> bool {
        matches!(self.outcome, AnalysisOutcome::Included)
    }

    pub fn content_fingerprint(&self) -> Option<&[u8; 32]> {
        self.content_fingerprint.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedSyncScope {
    included_paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
}

impl ApprovedSyncScope {
    pub fn included_paths(&self) -> impl Iterator<Item = &Path> {
        self.included_paths.iter().map(PathBuf::as_path)
    }

    pub fn excluded_paths(&self) -> impl Iterator<Item = &Path> {
        self.excluded_paths.iter().map(PathBuf::as_path)
    }

    pub fn included_count(&self) -> usize {
        self.included_paths.len()
    }

    pub fn excluded_count(&self) -> usize {
        self.excluded_paths.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInventory {
    peer_name: String,
    root: PathBuf,
    items: Vec<InventoryItem>,
    approved_scope: ApprovedSyncScope,
}

pub type PeerInventory = SourceInventory;

impl SourceInventory {
    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn items(&self) -> &[InventoryItem] {
        &self.items
    }

    pub fn item(&self, relative_path: impl AsRef<Path>) -> Option<&InventoryItem> {
        self.items
            .iter()
            .find(|item| item.relative_path == relative_path.as_ref())
    }

    pub fn included_items(&self) -> impl Iterator<Item = &InventoryItem> {
        self.items.iter().filter(|item| item.is_eligible())
    }

    pub fn excluded_items(&self) -> impl Iterator<Item = &InventoryItem> {
        self.items
            .iter()
            .filter(|item| item.outcome == AnalysisOutcome::Excluded)
    }

    pub fn approved_scope(&self) -> &ApprovedSyncScope {
        &self.approved_scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSide {
    PeerA,
    PeerB,
}

impl From<OneWaySource> for PeerSide {
    fn from(source: OneWaySource) -> Self {
        match source {
            OneWaySource::PeerA => Self::PeerA,
            OneWaySource::PeerB => Self::PeerB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanActionKind {
    CopyToDestination,
    OverwriteDestination,
    RemoveDestination,
    RemoveSourceAfterVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanAction {
    relative_path: PathBuf,
    kind: PlanActionKind,
    consequence: &'static str,
    source_side: PeerSide,
    size: Option<u64>,
}

impl PlanAction {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn kind(&self) -> PlanActionKind {
        self.kind
    }

    pub const fn consequence(&self) -> &'static str {
        self.consequence
    }

    pub const fn source_side(&self) -> PeerSide {
        self.source_side
    }

    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    pub const fn incoming_size(&self) -> Option<u64> {
        self.size()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanSummary {
    considered_count: usize,
    included_count: usize,
    excluded_count: usize,
    copy_count: usize,
    overwrite_count: usize,
    destination_removal_count: usize,
    source_removal_count: usize,
    copy_bytes: u64,
    overwrite_bytes: u64,
    destination_removal_bytes: u64,
    source_removal_bytes: u64,
}

impl PlanSummary {
    pub const fn considered_count(&self) -> usize {
        self.considered_count
    }

    pub const fn included_count(&self) -> usize {
        self.included_count
    }

    pub const fn excluded_count(&self) -> usize {
        self.excluded_count
    }

    pub const fn copy_count(&self) -> usize {
        self.copy_count
    }

    pub const fn overwrite_count(&self) -> usize {
        self.overwrite_count
    }

    pub const fn destination_removal_count(&self) -> usize {
        self.destination_removal_count
    }

    pub const fn source_removal_count(&self) -> usize {
        self.source_removal_count
    }

    pub const fn excluded_item_count(&self) -> usize {
        self.excluded_count()
    }

    pub const fn copy_bytes(&self) -> u64 {
        self.copy_bytes
    }

    pub const fn overwrite_bytes(&self) -> u64 {
        self.overwrite_bytes
    }

    pub const fn destination_removal_bytes(&self) -> u64 {
        self.destination_removal_bytes
    }

    pub const fn source_removal_bytes(&self) -> u64 {
        self.source_removal_bytes
    }

    pub const fn total_bytes(&self) -> u64 {
        self.copy_bytes + self.overwrite_bytes
    }

    pub const fn total_action_count(&self) -> usize {
        self.copy_count
            + self.overwrite_count
            + self.destination_removal_count
            + self.source_removal_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    ActionOutsideApprovedScope { path: PathBuf },
    ActionNotInPlan { path: PathBuf },
    ActionNotAllowed { kind: PlanActionKind },
    SummaryMismatch,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActionOutsideApprovedScope { path } => {
                write!(formatter, "plan action is outside the approved scope: {path:?}")
            }
            Self::ActionNotInPlan { path } => {
                write!(formatter, "plan does not contain the requested action: {path:?}")
            }
            Self::ActionNotAllowed { kind } => {
                write!(formatter, "plan action is not allowed by the process specification: {kind:?}")
            }
            Self::SummaryMismatch => write!(formatter, "plan summary does not match its actions"),
        }
    }
}

impl std::error::Error for PlanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneWayPlan {
    specification: ProcessSpecification,
    source_inventory: SourceInventory,
    approved_scope: ApprovedSyncScope,
    actions: Vec<PlanAction>,
    summary: PlanSummary,
}

impl OneWayPlan {
    pub fn specification(&self) -> &ProcessSpecification {
        &self.specification
    }

    pub fn process_specification(&self) -> &ProcessSpecification {
        self.specification()
    }

    pub fn source_inventory(&self) -> &SourceInventory {
        &self.source_inventory
    }

    pub fn inventory(&self) -> &SourceInventory {
        self.source_inventory()
    }

    pub fn approved_scope(&self) -> &ApprovedSyncScope {
        &self.approved_scope
    }

    pub fn actions(&self) -> &[PlanAction] {
        &self.actions
    }

    pub fn action_for(&self, relative_path: impl AsRef<Path>) -> Option<&PlanAction> {
        self.actions
            .iter()
            .find(|action| action.relative_path == relative_path.as_ref())
    }

    pub fn is_deletion_candidate(&self, relative_path: impl AsRef<Path>) -> bool {
        self.action_for(relative_path).is_some_and(|action| {
            matches!(
                action.kind,
                PlanActionKind::RemoveDestination | PlanActionKind::RemoveSourceAfterVerification
            )
        })
    }

    pub fn summary(&self) -> &PlanSummary {
        &self.summary
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn validate(&self) -> Result<(), PlanError> {
        for action in &self.actions {
            if self
                .source_inventory
                .item(&action.relative_path)
                .is_some_and(|item| !item.is_eligible())
            {
                return Err(PlanError::ActionOutsideApprovedScope {
                    path: action.relative_path.clone(),
                });
            }

            match action.kind {
                PlanActionKind::RemoveDestination
                    if !self.specification.options().destination_cleanup() =>
                {
                    return Err(PlanError::ActionNotAllowed { kind: action.kind });
                }
                PlanActionKind::RemoveSourceAfterVerification
                    if !self.specification.options().safe_delete() =>
                {
                    return Err(PlanError::ActionNotAllowed { kind: action.kind });
                }
                PlanActionKind::CopyToDestination | PlanActionKind::OverwriteDestination => {}
                PlanActionKind::RemoveDestination
                | PlanActionKind::RemoveSourceAfterVerification => {}
            }
        }

        if summary_for(&self.actions, &self.source_inventory) != self.summary {
            return Err(PlanError::SummaryMismatch);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRevision {
    source: Vec<RevisionItem>,
    destination: Vec<RevisionItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevisionItem {
    relative_path: PathBuf,
    item_type: ItemType,
    metadata: ItemMetadata,
    outcome: AnalysisOutcome,
    content_fingerprint: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    ProcessSpecification(ProcessSpecError),
    RootUnavailable { peer: String, path: PathBuf },
    RootNotDirectory { peer: String, path: PathBuf },
    ReadDirectory { peer: String, path: PathBuf },
    ReadMetadata { peer: String, path: PathBuf },
    ReadFileContents { peer: String, path: PathBuf },
    Plan(PlanError),
    ProfileChanged,
    StaleAnalysis { changed_paths: Vec<PathBuf> },
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessSpecification(error) => write!(formatter, "process specification: {error}"),
            Self::RootUnavailable { peer, path } => {
                write!(formatter, "root for peer {peer} is unavailable: {path:?}")
            }
            Self::RootNotDirectory { peer, path } => {
                write!(formatter, "root for peer {peer} is not a directory: {path:?}")
            }
            Self::ReadDirectory { peer, path } => {
                write!(formatter, "could not read directory for peer {peer}: {path:?}")
            }
            Self::ReadMetadata { peer, path } => {
                write!(formatter, "could not inspect item for peer {peer}: {path:?}")
            }
            Self::ReadFileContents { peer, path } => {
                write!(formatter, "could not compare item contents for peer {peer}: {path:?}")
            }
            Self::Plan(error) => write!(formatter, "plan: {error}"),
            Self::ProfileChanged => write!(formatter, "the profile changed after analysis"),
            Self::StaleAnalysis { changed_paths } => {
                write!(formatter, "analysis is stale for {changed_paths:?}")
            }
        }
    }
}

impl std::error::Error for AnalysisError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedPlan {
    plan: OneWayPlan,
}

impl ConfirmedPlan {
    pub fn plan(&self) -> &OneWayPlan {
        &self.plan
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshAnalysis {
    profile: SyncProfile,
    specification: ProcessSpecification,
    source_inventory: SourceInventory,
    destination_inventory: PeerInventory,
    plan: OneWayPlan,
    revision: AnalysisRevision,
}

impl FreshAnalysis {
    pub fn analyze(profile: &SyncProfile) -> Result<Self, AnalysisError> {
        let specification = ProcessSpecification::from_profile(profile)
            .map_err(AnalysisError::ProcessSpecification)?;
        let (source, destination) = selected_peers(profile);
        let exclusions: Vec<String> = specification
            .exclusions()
            .map(ToOwned::to_owned)
            .collect();
        let source_inventory = collect_inventory(source, &exclusions)?;
        let destination_inventory = collect_inventory(destination, &exclusions)?;
        let plan = build_plan(
            specification.clone(),
            source_inventory.clone(),
            destination_inventory.clone(),
        )?;
        let revision = AnalysisRevision::from_inventories(&source_inventory, &destination_inventory);

        Ok(Self {
            profile: profile.clone(),
            specification,
            source_inventory,
            destination_inventory,
            plan,
            revision,
        })
    }

    pub fn specification(&self) -> &ProcessSpecification {
        &self.specification
    }

    pub fn source_inventory(&self) -> &SourceInventory {
        &self.source_inventory
    }

    pub fn destination_inventory(&self) -> &PeerInventory {
        &self.destination_inventory
    }

    pub fn plan(&self) -> &OneWayPlan {
        &self.plan
    }

    pub fn revision(&self) -> AnalysisRevision {
        self.revision.clone()
    }

    pub fn confirm(&self, current_profile: &SyncProfile) -> Result<ConfirmedPlan, AnalysisError> {
        if self.profile != *current_profile {
            return Err(AnalysisError::ProfileChanged);
        }

        let refreshed = Self::analyze(current_profile)?;
        let mut changed_paths = self.revision.changed_paths(&refreshed.revision);
        if self.plan.actions != refreshed.plan.actions {
            changed_paths.extend(
                self.plan
                    .actions
                    .iter()
                    .map(|action| action.relative_path.clone()),
            );
            changed_paths.extend(
                refreshed
                    .plan
                    .actions
                    .iter()
                    .map(|action| action.relative_path.clone()),
            );
            changed_paths.sort();
            changed_paths.dedup();
        }
        if !changed_paths.is_empty() {
            return Err(AnalysisError::StaleAnalysis { changed_paths });
        }

        Ok(ConfirmedPlan {
            plan: self.plan.clone(),
        })
    }
}

impl AnalysisRevision {
    fn from_inventories(source: &SourceInventory, destination: &PeerInventory) -> Self {
        Self {
            source: source.items.iter().map(RevisionItem::from_item).collect(),
            destination: destination
                .items
                .iter()
                .map(RevisionItem::from_item)
                .collect(),
        }
    }

    fn changed_paths(&self, other: &Self) -> Vec<PathBuf> {
        let mut paths = BTreeSet::new();
        if revision_map(&self.source) != revision_map(&other.source) {
            paths.extend(changed_paths_for(&self.source, &other.source));
        }
        if revision_map(&self.destination) != revision_map(&other.destination) {
            paths.extend(changed_paths_for(&self.destination, &other.destination));
        }
        paths.into_iter().collect()
    }
}

impl RevisionItem {
    fn from_item(item: &InventoryItem) -> Self {
        Self {
            relative_path: item.relative_path.clone(),
            item_type: item.item_type,
            metadata: item.metadata.clone(),
            outcome: item.outcome,
            content_fingerprint: item.content_fingerprint,
        }
    }
}

fn selected_peers(profile: &SyncProfile) -> (&crate::Peer, &crate::Peer) {
    match profile.source() {
        OneWaySource::PeerA => (profile.peer_a(), profile.peer_b()),
        OneWaySource::PeerB => (profile.peer_b(), profile.peer_a()),
    }
}

fn collect_inventory(
    peer: &crate::Peer,
    exclusions: &[String],
) -> Result<SourceInventory, AnalysisError> {
    let root_metadata = fs::symlink_metadata(peer.root()).map_err(|_| {
        AnalysisError::RootUnavailable {
            peer: peer.name().to_owned(),
            path: peer.root().to_path_buf(),
        }
    })?;
    if !root_metadata.is_dir() {
        return Err(AnalysisError::RootNotDirectory {
            peer: peer.name().to_owned(),
            path: peer.root().to_path_buf(),
        });
    }

    let mut items = Vec::new();
    walk_directory(
        peer,
        peer.root(),
        Path::new(""),
        false,
        exclusions,
        &mut items,
    )?;
    items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let included_paths = items
        .iter()
        .filter(|item| item.outcome == AnalysisOutcome::Included)
        .map(|item| item.relative_path.clone())
        .collect();
    let excluded_paths = items
        .iter()
        .filter(|item| item.outcome == AnalysisOutcome::Excluded)
        .map(|item| item.relative_path.clone())
        .collect();

    Ok(SourceInventory {
        peer_name: peer.name().to_owned(),
        root: peer.root().to_path_buf(),
        items,
        approved_scope: ApprovedSyncScope {
            included_paths,
            excluded_paths,
        },
    })
}

fn walk_directory(
    peer: &crate::Peer,
    directory: &Path,
    relative_directory: &Path,
    inherited_exclusion: bool,
    exclusions: &[String],
    items: &mut Vec<InventoryItem>,
) -> Result<(), AnalysisError> {
    let mut entries = Vec::new();
    let read_directory = fs::read_dir(directory).map_err(|_| AnalysisError::ReadDirectory {
        peer: peer.name().to_owned(),
        path: directory.to_path_buf(),
    })?;
    for entry in read_directory {
        entries.push(entry.map_err(|_| AnalysisError::ReadDirectory {
            peer: peer.name().to_owned(),
            path: directory.to_path_buf(),
        })?);
    }
    entries.sort_by_key(DirEntry::file_name);

    for entry in entries {
        let absolute_path = entry.path();
        let relative_path = relative_directory.join(entry.file_name());
        let metadata = fs::symlink_metadata(&absolute_path).map_err(|_| {
            AnalysisError::ReadMetadata {
                peer: peer.name().to_owned(),
                path: relative_path.clone(),
            }
        })?;
        let item_type = item_type(&metadata);
        let excluded = inherited_exclusion
            || exclusions
                .iter()
                .any(|pattern| matches_exclusion(&relative_path, item_type, pattern));
        let outcome = if excluded {
            AnalysisOutcome::Excluded
        } else if item_type == ItemType::Unsupported {
            AnalysisOutcome::Unsupported
        } else {
            AnalysisOutcome::Included
        };

        let metadata_snapshot = metadata_snapshot(&absolute_path, &metadata).map_err(|_| {
            AnalysisError::ReadMetadata {
                peer: peer.name().to_owned(),
                path: relative_path.clone(),
            }
        })?;
        let content_fingerprint = if outcome == AnalysisOutcome::Included
            && item_type == ItemType::RegularFile
        {
            Some(file_fingerprint(&absolute_path).map_err(|_| AnalysisError::ReadFileContents {
                peer: peer.name().to_owned(),
                path: relative_path.clone(),
            })?)
        } else {
            None
        };

        items.push(InventoryItem {
            relative_path: relative_path.clone(),
            item_type,
            metadata: metadata_snapshot,
            outcome,
            content_fingerprint,
        });

        if item_type == ItemType::Directory {
            walk_directory(
                peer,
                &absolute_path,
                &relative_path,
                excluded,
                exclusions,
                items,
            )?;
        }
    }

    Ok(())
}

fn item_type(metadata: &Metadata) -> ItemType {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        ItemType::RegularFile
    } else if file_type.is_dir() {
        ItemType::Directory
    } else if file_type.is_symlink() {
        ItemType::Symlink
    } else {
        ItemType::Unsupported
    }
}

fn metadata_snapshot(path: &Path, metadata: &Metadata) -> Result<ItemMetadata, ()> {
    let symlink_target = if metadata.file_type().is_symlink() {
        Some(fs::read_link(path).map_err(|_| ())?)
    } else {
        None
    };

    Ok(ItemMetadata {
        size: metadata.len(),
        modified_at: metadata.modified().ok(),
        readonly: metadata.permissions().readonly(),
        symlink_target,
    })
}

fn matches_exclusion(relative_path: &Path, item_type: ItemType, pattern: &str) -> bool {
    let directory_pattern = pattern.ends_with('/');
    let pattern = pattern.trim_end_matches('/');
    if pattern.is_empty() {
        return false;
    }

    if directory_pattern && item_type != ItemType::Directory {
        return false;
    }

    if pattern.contains('/') {
        return wildcard_match(pattern, &path_for_matching(relative_path));
    }

    if directory_pattern {
        return relative_path.components().any(|component| {
            wildcard_match(pattern, &component.as_os_str().to_string_lossy())
        });
    }

    relative_path
        .file_name()
        .is_some_and(|file_name| wildcard_match(pattern, &file_name.to_string_lossy()))
}

fn path_for_matching(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut pattern_index = 0;
    let mut value_index = 0;
    let mut star_index = None;
    let mut star_value_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            star_value_index = value_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

fn build_plan(
    specification: ProcessSpecification,
    source: SourceInventory,
    destination: PeerInventory,
) -> Result<OneWayPlan, AnalysisError> {
    let source_side = PeerSide::from(specification.source());
    let source_by_path: BTreeMap<_, _> = source
        .items
        .iter()
        .map(|item| (item.relative_path.clone(), item))
        .collect();
    let destination_by_path: BTreeMap<_, _> = destination
        .items
        .iter()
        .map(|item| (item.relative_path.clone(), item))
        .collect();
    let mut actions = Vec::new();

    for source_item in source.included_items() {
        let destination_item = destination_by_path
            .get(source_item.relative_path())
            .copied();

        let transfer_kind = match destination_item {
            None => Some(PlanActionKind::CopyToDestination),
            Some(destination_item)
                if !destination_item.is_eligible() => None,
            Some(destination_item)
                if !same_item_state(source_item, destination_item) =>
            {
                Some(PlanActionKind::OverwriteDestination)
            }
            Some(_) => None,
        };

        if let Some(kind) = transfer_kind {
            actions.push(PlanAction {
                relative_path: source_item.relative_path.clone(),
                kind,
                consequence: consequence_for(kind),
                source_side,
                size: data_size(source_item),
            });
        }

        let destination_is_eligible_or_absent =
            destination_item.is_none_or(|item| item.is_eligible());
        if specification.options().safe_delete()
            && destination_is_eligible_or_absent
            && matches!(source_item.item_type, ItemType::RegularFile | ItemType::Symlink)
        {
            let kind = PlanActionKind::RemoveSourceAfterVerification;
            actions.push(PlanAction {
                relative_path: source_item.relative_path.clone(),
                kind,
                consequence: consequence_for(kind),
                source_side,
                size: data_size(source_item),
            });
        }
    }

    if specification.options().destination_cleanup() {
        for destination_item in destination.included_items() {
            if !source_by_path.contains_key(destination_item.relative_path()) {
                let kind = PlanActionKind::RemoveDestination;
                actions.push(PlanAction {
                    relative_path: destination_item.relative_path.clone(),
                    kind,
                    consequence: consequence_for(kind),
                    source_side,
                    size: data_size(destination_item),
                });
            }
        }
    }

    let approved_scope = source.approved_scope.clone();
    let summary = summary_for(&actions, &source);
    let plan = OneWayPlan {
        specification,
        source_inventory: source,
        approved_scope,
        actions,
        summary,
    };
    plan.validate().map_err(AnalysisError::Plan)?;
    Ok(plan)
}

fn same_item_state(source_item: &InventoryItem, destination_item: &InventoryItem) -> bool {
    if source_item.item_type != destination_item.item_type
        || source_item.metadata != destination_item.metadata
    {
        return false;
    }

    if source_item.item_type != ItemType::RegularFile {
        return true;
    }

    source_item.content_fingerprint == destination_item.content_fingerprint
}

fn consequence_for(kind: PlanActionKind) -> &'static str {
    match kind {
        PlanActionKind::CopyToDestination => {
            "Copy the selected source item to the destination; preserve the source."
        }
        PlanActionKind::OverwriteDestination => {
            "Replace the destination version with the selected source version after verification."
        }
        PlanActionKind::RemoveDestination => {
            "Remove the destination item because it is absent from the selected source scope."
        }
        PlanActionKind::RemoveSourceAfterVerification => {
            "Remove the source item only after the destination result is independently verified."
        }
    }
}

fn data_size(item: &InventoryItem) -> Option<u64> {
    (item.item_type == ItemType::RegularFile).then_some(item.metadata.size)
}

fn file_fingerprint(path: &Path) -> Result<[u8; 32], ()> {
    let mut file = File::open(path).map_err(|_| ())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().into())
}

fn summary_for(actions: &[PlanAction], source: &SourceInventory) -> PlanSummary {
    let mut summary = PlanSummary {
        considered_count: source.items.len(),
        included_count: source.approved_scope.included_count(),
        excluded_count: source.approved_scope.excluded_count(),
        ..PlanSummary::default()
    };

    for action in actions {
        match action.kind {
            PlanActionKind::CopyToDestination => {
                summary.copy_count += 1;
                summary.copy_bytes += action.size.unwrap_or_default();
            }
            PlanActionKind::OverwriteDestination => {
                summary.overwrite_count += 1;
                summary.overwrite_bytes += action.size.unwrap_or_default();
            }
            PlanActionKind::RemoveDestination => {
                summary.destination_removal_count += 1;
                summary.destination_removal_bytes += action.size.unwrap_or_default();
            }
            PlanActionKind::RemoveSourceAfterVerification => {
                summary.source_removal_count += 1;
                summary.source_removal_bytes += action.size.unwrap_or_default();
            }
        }
    }

    summary
}

fn revision_map(items: &[RevisionItem]) -> BTreeMap<&Path, (&ItemType, &ItemMetadata, &AnalysisOutcome)> {
    items
        .iter()
        .map(|item| {
            (
                item.relative_path.as_path(),
                (&item.item_type, &item.metadata, &item.outcome),
            )
        })
        .collect()
}

fn changed_paths_for(left: &[RevisionItem], right: &[RevisionItem]) -> BTreeSet<PathBuf> {
    let left = revision_map(left);
    let right = revision_map(right);
    left.keys()
        .chain(right.keys())
        .filter(|path| left.get(*path) != right.get(*path))
        .map(|path| path.to_path_buf())
        .collect()
}
