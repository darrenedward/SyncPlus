use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    verify_content, ConflictResolution, ConflictResolutionAction, DestinationNamingPolicy,
    ItemType, NamingRule, PeerSide, SourceObservation,
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

/// A preserved conflict copy intentionally remains available for a later,
/// separately confirmed removal decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreservedCopyReviewState {
    ReviewLater,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreservedCopyError {
    UnsafeRelativePath { path: PathBuf },
    MissingFileName { path: PathBuf },
    NonUtf8FileName { path: PathBuf },
    InvalidGeneratedPath { path: PathBuf, rule: NamingRule },
    NoAvailableName { path: PathBuf, source_peer: PeerSide },
}

impl fmt::Display for PreservedCopyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeRelativePath { path } => {
                write!(formatter, "preserved-copy path is not a safe relative path: {path:?}")
            }
            Self::MissingFileName { path } => {
                write!(formatter, "preserved-copy path has no file name: {path:?}")
            }
            Self::NonUtf8FileName { path } => {
                write!(formatter, "preserved-copy path has a non-UTF-8 file name: {path:?}")
            }
            Self::InvalidGeneratedPath { path, rule } => {
                write!(formatter, "generated preserved-copy path {path:?} violates {rule:?}")
            }
            Self::NoAvailableName { path, source_peer } => write!(
                formatter,
                "no collision-safe preserved-copy name is available for {path:?} from {source_peer:?}"
            ),
        }
    }
}

impl std::error::Error for PreservedCopyError {}

/// The paths already present or reserved in each peer. The inventory uses the
/// destination naming policy's collision key so case-insensitive and Unicode-
/// normalized filesystems are handled before any filesystem mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedPathInventory {
    policy: DestinationNamingPolicy,
    peer_a: BTreeSet<String>,
    peer_b: BTreeSet<String>,
}

impl PreservedPathInventory {
    pub fn new<A, B>(policy: DestinationNamingPolicy, peer_a: A, peer_b: B) -> Self
    where
        A: IntoIterator<Item = PathBuf>,
        B: IntoIterator<Item = PathBuf>,
    {
        let peer_a = peer_a
            .into_iter()
            .map(|path| policy.collision_key(&path))
            .collect();
        let peer_b = peer_b
            .into_iter()
            .map(|path| policy.collision_key(&path))
            .collect();
        Self {
            policy,
            peer_a,
            peer_b,
        }
    }

    pub fn contains(&self, peer: PeerSide, path: &Path) -> bool {
        let key = self.policy.collision_key(path);
        self.keys(peer).contains(&key)
    }

    fn reserve(&mut self, peer: PeerSide, path: &Path) {
        let key = self.policy.collision_key(path);
        self.keys_mut(peer).insert(key);
    }

    fn keys(&self, peer: PeerSide) -> &BTreeSet<String> {
        match peer {
            PeerSide::PeerA => &self.peer_a,
            PeerSide::PeerB => &self.peer_b,
        }
    }

    fn keys_mut(&mut self, peer: PeerSide) -> &mut BTreeSet<String> {
        match peer {
            PeerSide::PeerA => &mut self.peer_a,
            PeerSide::PeerB => &mut self.peer_b,
        }
    }
}

/// Allocates and reserves all generated names for a preserved-copy decision.
/// Reservation is kept across calls so a single run cannot plan two copies to
/// the same effective path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedCopyPlanner {
    occupied: PreservedPathInventory,
}

impl PreservedCopyPlanner {
    pub fn new(occupied: PreservedPathInventory) -> Self {
        Self { occupied }
    }

    pub fn plan(
        &mut self,
        action: &ConflictResolutionAction,
    ) -> Result<Option<PreservedCopyPlan>, PreservedCopyError> {
        if !matches!(
            action.resolution(),
            ConflictResolution::PreserveBoth | ConflictResolution::RenamePreserveForReview
        ) {
            return Ok(None);
        }

        let original_path = action.relative_path().to_path_buf();
        validate_relative_path(&original_path)?;

        // Treat the original path as occupied even when the caller's current
        // inventory has already classified it differently. A generated copy
        // must never replace either original at execution time.
        let mut planned_inventory = self.occupied.clone();
        planned_inventory.reserve(PeerSide::PeerA, &original_path);
        planned_inventory.reserve(PeerSide::PeerB, &original_path);

        let peer_a_copy = allocate_copy(
            &mut planned_inventory,
            PeerSide::PeerA,
            PeerSide::PeerB,
            &original_path,
            action.resolution(),
        )?;
        let peer_b_copy = allocate_copy(
            &mut planned_inventory,
            PeerSide::PeerB,
            PeerSide::PeerA,
            &original_path,
            action.resolution(),
        )?;

        self.occupied = planned_inventory;
        Ok(Some(PreservedCopyPlan {
            resolution: action.resolution(),
            copies: vec![peer_a_copy, peer_b_copy],
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedCopyPlan {
    resolution: ConflictResolution,
    copies: Vec<PreservedCopyReportItem>,
}

impl PreservedCopyPlan {
    pub const fn resolution(&self) -> ConflictResolution {
        self.resolution
    }

    pub fn copies(&self) -> &[PreservedCopyReportItem] {
        &self.copies
    }

    pub fn copy_for(&self, source_peer: PeerSide) -> Option<&PreservedCopyReportItem> {
        self.copies
            .iter()
            .find(|copy| copy.source_peer() == source_peer)
    }

    pub const fn requires_review(&self) -> bool {
        true
    }

    pub fn is_available_for_later_removal(&self) -> bool {
        !self.copies.is_empty()
            && self
                .copies
                .iter()
                .all(PreservedCopyReportItem::requires_explicit_removal)
    }
}

/// Durable/report-shaped provenance for one generated preserved copy. The
/// generated path is relative to `target_peer`; the original path is relative
/// to `source_peer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedCopyReportItem {
    original_path: PathBuf,
    generated_path: PathBuf,
    source_peer: PeerSide,
    target_peer: PeerSide,
    resolution: ConflictResolution,
    review_state: PreservedCopyReviewState,
}

impl PreservedCopyReportItem {
    pub fn original_path(&self) -> &Path {
        &self.original_path
    }

    pub fn generated_path(&self) -> &Path {
        &self.generated_path
    }

    pub const fn source_peer(&self) -> PeerSide {
        self.source_peer
    }

    pub const fn target_peer(&self) -> PeerSide {
        self.target_peer
    }

    pub const fn resolution(&self) -> ConflictResolution {
        self.resolution
    }

    pub const fn review_state(&self) -> PreservedCopyReviewState {
        self.review_state
    }

    /// The generated path is planned separately from and never equal to the
    /// original path. The eventual executor must install it with no-overwrite
    /// semantics after its own verification boundary.
    pub fn preserves_original(&self) -> bool {
        self.original_path != self.generated_path
    }

    pub const fn requires_explicit_removal(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreservedCopyExecutionError {
    UnsafePath(PathBuf),
    SourceUnavailable(PathBuf, String),
    UnsupportedItem(PathBuf),
    DestinationOccupied(PathBuf),
    Io(PathBuf, String),
    Verification(PathBuf, String),
    SourceChanged(PathBuf),
}

impl fmt::Display for PreservedCopyExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(path) => write!(formatter, "preserved-copy path escapes its peer root: {path:?}"),
            Self::SourceUnavailable(path, reason) => {
                write!(formatter, "preserved-copy source {path:?} is unavailable: {reason}")
            }
            Self::UnsupportedItem(path) => {
                write!(formatter, "preserved-copy source is not a regular file: {path:?}")
            }
            Self::DestinationOccupied(path) => {
                write!(formatter, "preserved-copy destination is already occupied: {path:?}")
            }
            Self::Io(path, reason) => {
                write!(formatter, "preserved-copy filesystem operation failed at {path:?}: {reason}")
            }
            Self::Verification(path, reason) => {
                write!(formatter, "preserved-copy verification failed at {path:?}: {reason}")
            }
            Self::SourceChanged(path) => {
                write!(formatter, "preserved-copy source changed during copying: {path:?}")
            }
        }
    }
}

impl std::error::Error for PreservedCopyExecutionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreservedCopyExecutionOutcome {
    Copied,
    Unresolved(PreservedCopyExecutionError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedCopyExecutionItem {
    copy: PreservedCopyReportItem,
    outcome: PreservedCopyExecutionOutcome,
}

impl PreservedCopyExecutionItem {
    pub fn copy(&self) -> &PreservedCopyReportItem {
        &self.copy
    }

    pub fn outcome(&self) -> &PreservedCopyExecutionOutcome {
        &self.outcome
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreservedCopyExecutionReport {
    items: Vec<PreservedCopyExecutionItem>,
}

impl PreservedCopyExecutionReport {
    pub fn items(&self) -> &[PreservedCopyExecutionItem] {
        &self.items
    }

    pub fn has_unresolved(&self) -> bool {
        self.items.iter().any(|item| {
            matches!(
                item.outcome(),
                PreservedCopyExecutionOutcome::Unresolved(_)
            )
        })
    }
}

/// Executes a preserved-copy plan for two local peers. Each item is copied to
/// a newly-created, separately named path; the executor never replaces an
/// existing destination and returns a report that keeps any failed item
/// unresolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedCopyExecutor {
    peer_a_root: PathBuf,
    peer_b_root: PathBuf,
}

impl PreservedCopyExecutor {
    pub fn new(peer_a_root: PathBuf, peer_b_root: PathBuf) -> Self {
        Self {
            peer_a_root,
            peer_b_root,
        }
    }

    pub fn execute(&self, plan: &PreservedCopyPlan) -> PreservedCopyExecutionReport {
        let mut report = PreservedCopyExecutionReport::default();
        for copy in plan.copies() {
            let outcome = self
                .execute_copy(copy)
                .map_or_else(PreservedCopyExecutionOutcome::Unresolved, |_| {
                    PreservedCopyExecutionOutcome::Copied
                });
            report.items.push(PreservedCopyExecutionItem {
                copy: copy.clone(),
                outcome,
            });
        }
        report
    }

    fn execute_copy(
        &self,
        copy: &PreservedCopyReportItem,
    ) -> Result<(), PreservedCopyExecutionError> {
        validate_relative_path(copy.original_path())
            .map_err(|_| PreservedCopyExecutionError::UnsafePath(copy.original_path().to_path_buf()))?;
        validate_relative_path(copy.generated_path())
            .map_err(|_| PreservedCopyExecutionError::UnsafePath(copy.generated_path().to_path_buf()))?;

        let source_root = self.root(copy.source_peer());
        let target_root = self.root(copy.target_peer());
        let source = source_root.join(copy.original_path());
        let target = target_root.join(copy.generated_path());
        ensure_within_root(source_root, &source)?;
        ensure_within_root(target_root, &target)?;

        let source_observation = SourceObservation::capture(&source).map_err(|error| {
            PreservedCopyExecutionError::SourceUnavailable(source.clone(), error.to_string())
        })?;
        if source_observation.metadata().item_type() != ItemType::RegularFile {
            return Err(PreservedCopyExecutionError::UnsupportedItem(source));
        }
        let expected = source_observation.content();
        let parent = target.parent().ok_or_else(|| {
            PreservedCopyExecutionError::UnsafePath(target.clone())
        })?;
        fs::create_dir_all(parent).map_err(|error| io_error(&target, error))?;
        ensure_within_root(target_root, &target)?;
        if fs::symlink_metadata(&target).is_ok() {
            return Err(PreservedCopyExecutionError::DestinationOccupied(target));
        }

        let temporary = temporary_path(parent, target.file_name().unwrap_or_default());
        let result = self.copy_to_temporary(&source, &temporary, &expected, source_observation.metadata().permissions());
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }

        if fs::symlink_metadata(&target).is_ok() {
            let _ = fs::remove_file(&temporary);
            return Err(PreservedCopyExecutionError::DestinationOccupied(target));
        }
        if let Err(error) = fs::hard_link(&temporary, &target) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(&target, error));
        }
        if let Err(error) = fs::remove_file(&temporary) {
            return Err(io_error(&temporary, error));
        }
        verify_content(&target, &expected)
            .map_err(|error| PreservedCopyExecutionError::Verification(target.clone(), error.to_string()))?;
        source_observation
            .recheck(&source)
            .map_err(|_| PreservedCopyExecutionError::SourceChanged(source))
    }

    fn copy_to_temporary(
        &self,
        source: &Path,
        temporary: &Path,
        expected: &crate::ContentProof,
        permissions: Option<u32>,
    ) -> Result<(), PreservedCopyExecutionError> {
        let mut source_file = open_source(source)?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary)
            .map_err(|error| io_error(temporary, error))?;
        io::copy(&mut source_file, &mut destination)
            .map_err(|error| io_error(temporary, error))?;
        if let Some(permissions) = permissions {
            set_permissions(temporary, permissions)
                .map_err(|error| io_error(temporary, error))?;
        }
        destination
            .sync_all()
            .map_err(|error| io_error(temporary, error))?;
        verify_content(temporary, expected).map_err(|error| {
            PreservedCopyExecutionError::Verification(temporary.to_path_buf(), error.to_string())
        })?;
        Ok(())
    }

    fn root(&self, peer: PeerSide) -> &Path {
        match peer {
            PeerSide::PeerA => &self.peer_a_root,
            PeerSide::PeerB => &self.peer_b_root,
        }
    }
}

fn temporary_path(parent: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".syncplus-preserved-{}-{}", id, name.to_string_lossy()))
}

fn open_source(path: &Path) -> Result<File, PreservedCopyExecutionError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|error| PreservedCopyExecutionError::SourceUnavailable(path.to_path_buf(), error.to_string()))
}

fn set_permissions(path: &Path, permissions: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(permissions))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, permissions);
        Ok(())
    }
}

fn ensure_within_root(root: &Path, path: &Path) -> Result<(), PreservedCopyExecutionError> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| io_error(root, error))?;
    let existing_parent = path
        .parent()
        .ok_or_else(|| PreservedCopyExecutionError::UnsafePath(path.to_path_buf()))?;
    let canonical_parent = fs::canonicalize(existing_parent)
        .map_err(|error| io_error(existing_parent, error))?;
    if canonical_parent.starts_with(&canonical_root) {
        Ok(())
    } else {
        Err(PreservedCopyExecutionError::UnsafePath(path.to_path_buf()))
    }
}

fn io_error(path: &Path, error: io::Error) -> PreservedCopyExecutionError {
    PreservedCopyExecutionError::Io(path.to_path_buf(), error.to_string())
}

fn allocate_copy(
    inventory: &mut PreservedPathInventory,
    source_peer: PeerSide,
    target_peer: PeerSide,
    original_path: &Path,
    resolution: ConflictResolution,
) -> Result<PreservedCopyReportItem, PreservedCopyError> {
    let file_name = original_path
        .file_name()
        .ok_or_else(|| PreservedCopyError::MissingFileName {
            path: original_path.to_path_buf(),
        })?
        .to_str()
        .ok_or_else(|| PreservedCopyError::NonUtf8FileName {
            path: original_path.to_path_buf(),
        })?;
    let name_path = Path::new(file_name);
    let stem = name_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| PreservedCopyError::NonUtf8FileName {
            path: original_path.to_path_buf(),
        })?;
    let extension = name_path.extension().and_then(|value| value.to_str());
    let parent = original_path.parent().unwrap_or_else(|| Path::new(""));
    let peer_label = match source_peer {
        PeerSide::PeerA => "Peer A",
        PeerSide::PeerB => "Peer B",
    };

    let mut suffix = 0_u32;
    loop {
        let decorated = if suffix == 0 {
            format!("{stem} ({peer_label})")
        } else {
            format!("{stem} ({peer_label}) ({})", suffix_plus_one(suffix))
        };
        let generated_name = match extension {
            Some(extension) => format!("{decorated}.{extension}"),
            None => decorated,
        };
        let generated_path = parent.join(generated_name);

        if let Some(rule) = inventory.policy.validate_generated_path(&generated_path) {
            return Err(PreservedCopyError::InvalidGeneratedPath {
                path: generated_path,
                rule,
            });
        }
        if !inventory.contains(target_peer, &generated_path) {
            inventory.reserve(target_peer, &generated_path);
            return Ok(PreservedCopyReportItem {
                original_path: original_path.to_path_buf(),
                generated_path,
                source_peer,
                target_peer,
                resolution,
                review_state: PreservedCopyReviewState::ReviewLater,
            });
        }

        suffix = suffix.checked_add(1).ok_or_else(|| {
            PreservedCopyError::NoAvailableName {
                path: original_path.to_path_buf(),
                source_peer,
            }
        })?;
    }
}

fn suffix_plus_one(suffix: u32) -> u32 {
    suffix.saturating_add(1)
}

fn validate_relative_path(path: &Path) -> Result<(), PreservedCopyError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PreservedCopyError::UnsafeRelativePath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}
