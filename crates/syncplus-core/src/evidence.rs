use std::{
    collections::BTreeMap,
    fmt,
    fs,
    io,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    AuthorizationSnapshot, DeletionMethod, ItemType, MetadataRequirements, OneWaySource, Peer,
    PeerSide, PartialTransferPolicy, PlanActionKind, ProcessSpecError, ProcessSpecification,
    ProfileSnapshotId, ReconciliationFindingKind, ReconciliationReason, RetryPolicy, RunId,
    SourceDrainStatus, SourceInventorySnapshot, SyncMode, SyncOptions, SyncProfile,
    ValidatedSyncOptions, CompletionReconciliation, AnalysisOutcome, InventorySnapshotItem,
};

pub type ActionId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSnapshot {
    run_id: RunId,
    snapshot_id: ProfileSnapshotId,
    profile: SyncProfile,
    validated_options: ValidatedSyncOptions,
    authorizations: AuthorizationSnapshot,
}

impl RunSnapshot {
    pub fn from_profile(
        run_id: RunId,
        profile: &SyncProfile,
        authorizations: AuthorizationSnapshot,
    ) -> Result<Self, StorageError> {
        let specification =
            ProcessSpecification::from_profile(profile).map_err(StorageError::InvalidProfile)?;
        if authorizations.allow_unattended_permanent_removal()
            && (specification.options().deletion_method()
                != Some(DeletionMethod::PermanentRemoval)
                || !specification.options().safe_delete())
        {
            return Err(StorageError::InvalidSnapshot(
                "unattended permanent removal requires Safe Delete with Permanent Removal selected"
                    .to_owned(),
            ));
        }
        Ok(Self {
            run_id,
            snapshot_id: ProfileSnapshotId::new(run_id.value()),
            profile: profile.clone(),
            validated_options: specification.options(),
            authorizations,
        })
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub const fn snapshot_id(&self) -> ProfileSnapshotId {
        self.snapshot_id
    }

    pub fn profile(&self) -> &SyncProfile {
        &self.profile
    }

    pub const fn validated_options(&self) -> ValidatedSyncOptions {
        self.validated_options
    }

    pub const fn authorizations(&self) -> AuthorizationSnapshot {
        self.authorizations
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    pub const fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreActionState {
    item_type: ItemType,
    size: u64,
    modified_at_unix_nanos: Option<i64>,
    identity: Option<FileIdentity>,
    sha256: Option<[u8; 32]>,
}

impl PreActionState {
    pub fn new(
        item_type: ItemType,
        size: u64,
        modified_at_unix_nanos: Option<i64>,
        identity: Option<FileIdentity>,
        sha256: Option<[u8; 32]>,
    ) -> Self {
        Self {
            item_type,
            size,
            modified_at_unix_nanos,
            identity,
            sha256,
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

    pub const fn identity(&self) -> Option<FileIdentity> {
        self.identity
    }

    pub fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEvidence {
    observed_at_unix_nanos: i64,
    recovery_target: Option<PathBuf>,
    source_present: bool,
    destination_present: bool,
    recovery_present: bool,
    source_size: Option<u64>,
    destination_size: Option<u64>,
    source_sha256: Option<[u8; 32]>,
    destination_sha256: Option<[u8; 32]>,
}

impl RecoveryEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observed_at_unix_nanos: i64,
        recovery_target: Option<PathBuf>,
        source_present: bool,
        destination_present: bool,
        recovery_present: bool,
        source_size: Option<u64>,
        destination_size: Option<u64>,
        source_sha256: Option<[u8; 32]>,
        destination_sha256: Option<[u8; 32]>,
    ) -> Self {
        Self {
            observed_at_unix_nanos,
            recovery_target,
            source_present,
            destination_present,
            recovery_present,
            source_size,
            destination_size,
            source_sha256,
            destination_sha256,
        }
    }

    pub const fn observed_at_unix_nanos(&self) -> i64 {
        self.observed_at_unix_nanos
    }

    pub fn recovery_target(&self) -> Option<&Path> {
        self.recovery_target.as_deref()
    }

    pub const fn source_present(&self) -> bool {
        self.source_present
    }

    pub const fn destination_present(&self) -> bool {
        self.destination_present
    }

    pub const fn recovery_present(&self) -> bool {
        self.recovery_present
    }

    pub const fn source_size(&self) -> Option<u64> {
        self.source_size
    }

    pub const fn destination_size(&self) -> Option<u64> {
        self.destination_size
    }

    pub fn source_sha256(&self) -> Option<&[u8; 32]> {
        self.source_sha256.as_ref()
    }

    pub fn destination_sha256(&self) -> Option<&[u8; 32]> {
        self.destination_sha256.as_ref()
    }

    fn is_newer_than(&self, earlier: &Self) -> bool {
        self.observed_at_unix_nanos > earlier.observed_at_unix_nanos
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRecord {
    action_id: ActionId,
    relative_path: PathBuf,
    operation: PlanActionKind,
    affected_side: PeerSide,
    planned_bytes: Option<u64>,
    pre_action: PreActionState,
}

impl PlanRecord {
    pub fn new(
        action_id: ActionId,
        relative_path: PathBuf,
        operation: PlanActionKind,
        affected_side: PeerSide,
        planned_bytes: Option<u64>,
        pre_action: PreActionState,
    ) -> Self {
        Self {
            action_id,
            relative_path,
            operation,
            affected_side,
            planned_bytes,
            pre_action,
        }
    }

    pub const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn operation(&self) -> PlanActionKind {
        self.operation
    }

    pub const fn affected_side(&self) -> PeerSide {
        self.affected_side
    }

    pub const fn planned_bytes(&self) -> Option<u64> {
        self.planned_bytes
    }

    pub fn pre_action(&self) -> &PreActionState {
        &self.pre_action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionReason {
    TransferFailed,
    VerificationMismatch,
    SourceChanged,
    PermissionDenied,
    CancellationRequested,
    DeferredForReview,
    FilesystemUncertain,
    InterruptedBoundary,
    DestinationUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryResolution {
    Completed { evidence: RecoveryEvidence },
    Unresolved(ActionReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalResult {
    deletion_method: DeletionMethod,
    evidence: RecoveryEvidence,
}

impl RemovalResult {
    pub(crate) fn new(deletion_method: DeletionMethod, evidence: RecoveryEvidence) -> Self {
        Self {
            deletion_method,
            evidence,
        }
    }

    pub const fn deletion_method(&self) -> DeletionMethod {
        self.deletion_method
    }

    pub fn evidence(&self) -> &RecoveryEvidence {
        &self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEvent {
    Planned { action: PlanRecord },
    Started { action_id: ActionId },
    Progress {
        action_id: ActionId,
        completed_bytes: u64,
    },
    TransferVerified {
        action_id: ActionId,
        evidence: RecoveryEvidence,
        metadata_verified: bool,
    },
    ProofBoundary {
        action_id: ActionId,
        deletion_method: DeletionMethod,
        evidence: RecoveryEvidence,
        metadata_verified: bool,
    },
    RemovalStarted {
        action_id: ActionId,
        deletion_method: DeletionMethod,
    },
    RemovalCompleted {
        action_id: ActionId,
        result: RemovalResult,
    },
    Completed { action_id: ActionId },
    Failed {
        action_id: ActionId,
        reason: ActionReason,
    },
    Cancelled { action_id: ActionId },
    Interrupted { action_id: ActionId },
    Deferred { action_id: ActionId },
    Unresolved {
        action_id: ActionId,
        reason: ActionReason,
    },
    RecoveryReview {
        action_id: ActionId,
        reason: ActionReason,
        evidence: RecoveryEvidence,
    },
    RecoveryResolved {
        action_id: ActionId,
        resolution: RecoveryResolution,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    InProgress,
    Completed,
    Failed(ActionReason),
    Cancelled,
    Interrupted,
    Deferred,
    Unresolved(ActionReason),
    RecoveryReview(ActionReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionJournalEntry {
    plan: PlanRecord,
    last_phase: String,
    started: bool,
    progress_bytes: Vec<u64>,
    outcome: ActionOutcome,
    transfer_evidence: Option<RecoveryEvidence>,
    proof_boundary: Option<RecoveryEvidence>,
    removal_result: Option<RemovalResult>,
    recovery_evidence: Option<RecoveryEvidence>,
    recovery_resolution_evidence: Option<RecoveryEvidence>,
}

impl ActionJournalEntry {
    pub fn plan(&self) -> &PlanRecord {
        &self.plan
    }

    pub fn relative_path(&self) -> &Path {
        self.plan.relative_path()
    }

    pub const fn operation(&self) -> PlanActionKind {
        self.plan.operation()
    }

    pub const fn started(&self) -> bool {
        self.started
    }

    pub fn progress_bytes(&self) -> &[u64] {
        &self.progress_bytes
    }

    pub const fn outcome(&self) -> &ActionOutcome {
        &self.outcome
    }

    pub fn recovery_evidence(&self) -> Option<&RecoveryEvidence> {
        self.recovery_evidence.as_ref()
    }

    pub fn proof_boundary(&self) -> Option<&RecoveryEvidence> {
        self.proof_boundary.as_ref()
    }

    pub fn transfer_evidence(&self) -> Option<&RecoveryEvidence> {
        self.transfer_evidence.as_ref()
    }

    pub fn removal_result(&self) -> Option<&RemovalResult> {
        self.removal_result.as_ref()
    }

    pub fn recovery_resolution_evidence(&self) -> Option<&RecoveryEvidence> {
        self.recovery_resolution_evidence.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReportItem {
    journal: ActionJournalEntry,
}

impl RunReportItem {
    pub const fn action_id(&self) -> ActionId {
        self.journal.plan.action_id()
    }

    pub fn relative_path(&self) -> &Path {
        self.journal.plan.relative_path()
    }

    pub const fn operation(&self) -> PlanActionKind {
        self.journal.plan.operation()
    }

    pub fn outcome(&self) -> &ActionOutcome {
        &self.journal.outcome
    }

    pub fn progress_bytes(&self) -> u64 {
        self.journal.progress_bytes.last().copied().unwrap_or(0)
    }

    pub fn journal(&self) -> &ActionJournalEntry {
        &self.journal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunReportStatus {
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
    Blocked,
    CompletedWithReviewRequired,
    RecoveryReview,
    ReviewCleared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExecutionResult {
    NotStarted,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
    Blocked,
    RecoveryReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunLifecycle {
    Open,
    ReviewRequired,
    ReviewCleared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    run_id: RunId,
    snapshot: RunSnapshot,
    items: Vec<RunReportItem>,
    status: RunReportStatus,
    execution_result: RunExecutionResult,
    lifecycle: RunLifecycle,
    blocked_reason: Option<String>,
    reconciliation: Option<CompletionReconciliation>,
    reconciliation_required: bool,
}

impl RunReport {
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub fn snapshot(&self) -> &RunSnapshot {
        &self.snapshot
    }

    pub fn items(&self) -> &[RunReportItem] {
        &self.items
    }

    pub const fn status(&self) -> RunReportStatus {
        self.status
    }

    pub const fn execution_result(&self) -> RunExecutionResult {
        self.execution_result
    }

    pub const fn lifecycle(&self) -> RunLifecycle {
        self.lifecycle
    }

    pub fn blocked_reason(&self) -> Option<&str> {
        self.blocked_reason.as_deref()
    }

    pub fn reconciliation(&self) -> Option<&CompletionReconciliation> {
        self.reconciliation.as_ref()
    }

    pub fn can_mark_review_cleared(&self) -> bool {
        matches!(self.lifecycle, RunLifecycle::Open)
            && matches!(self.execution_result, RunExecutionResult::Succeeded)
            && (!self.reconciliation_required
                || self
                    .reconciliation
                    .as_ref()
                    .is_some_and(|reconciliation| !reconciliation.requires_review()))
    }
}

#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    InvalidProfile(ProcessSpecError),
    InvalidSnapshot(String),
    InvalidEvent(String),
    CorruptEvidence(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::Io(error) => write!(formatter, "storage filesystem error: {error}"),
            Self::InvalidProfile(error) => write!(formatter, "invalid profile: {error}"),
            Self::InvalidSnapshot(reason) => write!(formatter, "invalid run snapshot: {reason}"),
            Self::InvalidEvent(reason) => write!(formatter, "invalid journal event: {reason}"),
            Self::CorruptEvidence(reason) => write!(formatter, "corrupt run evidence: {reason}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct RunEvidenceStore {
    connection: Connection,
    #[cfg(test)]
    fail_event_phase: Option<&'static str>,
}

impl RunEvidenceStore {
    /// Resolve the one canonical live database for the current OS user.
    pub fn canonical_path() -> Result<PathBuf, StorageError> {
        let data_home = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".local/share"))
            })
            .ok_or_else(|| {
                StorageError::InvalidSnapshot(
                    "XDG_DATA_HOME or HOME is required for the canonical database".to_owned(),
                )
            })?;
        Ok(data_home.join("syncplus/syncplus.db"))
    }

    pub fn open_canonical() -> Result<Self, StorageError> {
        let path = Self::canonical_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let store = Self::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(store)
    }

    /// Open an explicitly supplied database path. Production callers should
    /// use `open_canonical`; this path form exists for controlled test and
    /// migration locations and never derives a path from a selected peer.
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::from_connection(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, StorageError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let mut version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 6 {
            return Err(StorageError::CorruptEvidence(format!(
                "unsupported evidence schema version {version}"
            )));
        }
        if version == 0 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
            "
            CREATE TABLE run_snapshots (
                run_id INTEGER PRIMARY KEY,
                snapshot_id INTEGER NOT NULL,
                profile_name TEXT NOT NULL,
                peer_a_name TEXT NOT NULL,
                peer_a_root BLOB NOT NULL,
                peer_b_name TEXT NOT NULL,
                peer_b_root BLOB NOT NULL,
                mode TEXT NOT NULL,
                source TEXT NOT NULL,
                safe_delete INTEGER NOT NULL,
                destination_cleanup INTEGER NOT NULL,
                deletion_method TEXT,
                allow_unattended_destructive INTEGER NOT NULL,
                allow_unattended_permanent_removal INTEGER NOT NULL
            );
            CREATE TABLE snapshot_exclusions (
                run_id INTEGER NOT NULL,
                ordinal INTEGER NOT NULL,
                pattern TEXT NOT NULL,
                PRIMARY KEY (run_id, ordinal),
                FOREIGN KEY (run_id) REFERENCES run_snapshots(run_id) ON DELETE CASCADE
            );
            CREATE TABLE action_events (
                run_id INTEGER NOT NULL,
                action_id INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                phase TEXT NOT NULL,
                relative_path BLOB,
                operation TEXT,
                affected_side TEXT,
                planned_bytes INTEGER,
                pre_item_type TEXT,
                pre_size INTEGER,
                pre_modified_at_unix_nanos INTEGER,
                pre_device INTEGER,
                pre_inode INTEGER,
                pre_sha256 BLOB,
                progress_bytes INTEGER,
                reason TEXT,
                PRIMARY KEY (run_id, action_id, sequence),
                FOREIGN KEY (run_id) REFERENCES run_snapshots(run_id) ON DELETE CASCADE
            );
            CREATE INDEX action_events_by_run
                ON action_events (run_id, action_id, sequence);
            ",
            )?;
            transaction.pragma_update(None, "user_version", 1)?;
            transaction.commit()?;
            version = 1;
        }
        if version == 1 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "
                ALTER TABLE run_snapshots
                    ADD COLUMN review_cleared INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE action_events ADD COLUMN recovery_observed_at_unix_nanos INTEGER;
                ALTER TABLE action_events ADD COLUMN recovery_target BLOB;
                ALTER TABLE action_events ADD COLUMN recovery_source_present INTEGER;
                ALTER TABLE action_events ADD COLUMN recovery_destination_present INTEGER;
                ALTER TABLE action_events ADD COLUMN recovery_present INTEGER;
                ALTER TABLE action_events ADD COLUMN recovery_source_size INTEGER;
                ALTER TABLE action_events ADD COLUMN recovery_destination_size INTEGER;
                ALTER TABLE action_events ADD COLUMN recovery_source_sha256 BLOB;
                ALTER TABLE action_events ADD COLUMN recovery_destination_sha256 BLOB;
                ALTER TABLE action_events ADD COLUMN resolution TEXT;
                ",
            )?;
            transaction.pragma_update(None, "user_version", 2)?;
            transaction.commit()?;
            version = 2;
        }
        if version == 2 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "
                ALTER TABLE action_events ADD COLUMN proof_destination_size INTEGER;
                ALTER TABLE action_events ADD COLUMN proof_destination_sha256 BLOB;
                ALTER TABLE action_events ADD COLUMN proof_metadata_verified INTEGER;
                ALTER TABLE action_events ADD COLUMN deletion_method TEXT;
                ",
            )?;
            transaction.pragma_update(None, "user_version", 3)?;
            transaction.commit()?;
            version = 3;
        }
        if version == 3 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "
                ALTER TABLE run_snapshots
                    ADD COLUMN metadata_file_type INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE run_snapshots
                    ADD COLUMN metadata_executable_permissions INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE run_snapshots
                    ADD COLUMN metadata_symlink_targets INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE run_snapshots
                    ADD COLUMN metadata_timestamps INTEGER NOT NULL DEFAULT 0;
                ",
            )?;
            transaction.pragma_update(None, "user_version", 4)?;
            transaction.commit()?;
            version = 4;
        }
        if version == 4 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "
                ALTER TABLE run_snapshots
                    ADD COLUMN partial_transfer_policy TEXT NOT NULL DEFAULT 'cleanup';
                ALTER TABLE run_snapshots
                    ADD COLUMN retry_max_attempts INTEGER NOT NULL DEFAULT 3;
                ALTER TABLE run_snapshots
                    ADD COLUMN retry_initial_delay_millis INTEGER NOT NULL DEFAULT 100;
                ",
            )?;
            transaction.pragma_update(None, "user_version", 5)?;
            transaction.commit()?;
            version = 5;
        }
        if version == 5 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "
                ALTER TABLE run_snapshots ADD COLUMN blocked_reason TEXT;
                ALTER TABLE run_snapshots
                    ADD COLUMN source_inventory_recorded INTEGER NOT NULL DEFAULT 0;
                CREATE TABLE source_inventory_items (
                    run_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    relative_path BLOB NOT NULL,
                    item_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    modified_at_unix_nanos INTEGER,
                    readonly INTEGER NOT NULL,
                    symlink_target BLOB,
                    content_fingerprint BLOB,
                    PRIMARY KEY (run_id, ordinal),
                    UNIQUE (run_id, relative_path),
                    FOREIGN KEY (run_id) REFERENCES run_snapshots(run_id) ON DELETE CASCADE
                );
                CREATE TABLE reconciliation_runs (
                    run_id INTEGER PRIMARY KEY,
                    source_drain_status TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES run_snapshots(run_id) ON DELETE CASCADE
                );
                CREATE TABLE reconciliation_findings (
                    run_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    relative_path BLOB NOT NULL,
                    kind TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    action_reason TEXT,
                    PRIMARY KEY (run_id, ordinal),
                    FOREIGN KEY (run_id) REFERENCES run_snapshots(run_id) ON DELETE CASCADE
                );
                ",
            )?;
            transaction.pragma_update(None, "user_version", 6)?;
            transaction.commit()?;
        }
        verify_integrity(&connection)?;
        Ok(Self {
            connection,
            #[cfg(test)]
            fail_event_phase: None,
        })
    }

    /// Persist the immutable snapshot before any filesystem action starts.
    pub fn begin_run(&mut self, snapshot: &RunSnapshot) -> Result<(), StorageError> {
        let transaction = self.connection.transaction()?;
        let profile = snapshot.profile();
        let options = snapshot.validated_options();
        let authorizations = snapshot.authorizations();
        transaction.execute(
            "INSERT INTO run_snapshots (
                run_id, snapshot_id, profile_name,
                peer_a_name, peer_a_root, peer_b_name, peer_b_root,
                mode, source, safe_delete, destination_cleanup, deletion_method,
                allow_unattended_destructive, allow_unattended_permanent_removal,
                metadata_file_type, metadata_executable_permissions,
                metadata_symlink_targets, metadata_timestamps,
                partial_transfer_policy, retry_max_attempts,
                retry_initial_delay_millis
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![
                snapshot.run_id().value(),
                snapshot.snapshot_id().value(),
                profile.name(),
                profile.peer_a().name(),
                path_to_blob(profile.peer_a().root()),
                profile.peer_b().name(),
                path_to_blob(profile.peer_b().root()),
                encode_mode(profile.mode()),
                encode_source(profile.source()),
                bool_to_int(options.safe_delete()),
                bool_to_int(options.destination_cleanup()),
                options.deletion_method().map(encode_deletion_method),
                bool_to_int(authorizations.allow_unattended_destructive()),
                bool_to_int(authorizations.allow_unattended_permanent_removal()),
                bool_to_int(options.metadata().file_type()),
                bool_to_int(options.metadata().executable_permissions()),
                bool_to_int(options.metadata().symlink_targets()),
                bool_to_int(options.metadata().timestamps()),
                encode_partial_transfer_policy(options.partial_transfer_policy()),
                options.retry_policy().max_attempts(),
                options.retry_policy().initial_delay().as_millis() as u64,
            ],
        )?;
        for (ordinal, pattern) in profile.exclusions().iter().enumerate() {
            transaction.execute(
                "INSERT INTO snapshot_exclusions (run_id, ordinal, pattern) VALUES (?1, ?2, ?3)",
                params![snapshot.run_id().value(), ordinal as i64, pattern],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Persist the frozen Source Inventory before any filesystem mutation.
    /// Inventory metadata and hashes are evidence, never file contents.
    pub fn record_source_inventory(
        &mut self,
        run_id: RunId,
        inventory: &SourceInventorySnapshot,
    ) -> Result<(), StorageError> {
        let transaction = self.connection.transaction()?;
        for (ordinal, item) in inventory.items().iter().enumerate() {
            transaction.execute(
                "INSERT INTO source_inventory_items (
                    run_id, ordinal, relative_path, item_type, outcome, size,
                    modified_at_unix_nanos, readonly, symlink_target, content_fingerprint
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    run_id.value(),
                    ordinal as i64,
                    path_to_blob(item.relative_path()),
                    encode_item_type(item.item_type()),
                    encode_analysis_outcome(item.outcome()),
                    item.size() as i64,
                    item.modified_at_unix_nanos(),
                    bool_to_int(item.is_readonly()),
                    item.symlink_target().map(path_to_blob),
                    item.content_fingerprint().map(|hash| hash.to_vec()),
                ],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE run_snapshots SET source_inventory_recorded = 1 WHERE run_id = ?1",
            params![run_id.value()],
        )?;
        if changed != 1 {
            return Err(StorageError::InvalidEvent(format!(
                "run {} does not exist",
                run_id.value()
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_source_inventory(
        &self,
        run_id: RunId,
    ) -> Result<SourceInventorySnapshot, StorageError> {
        let snapshot = self.load_snapshot(run_id)?;
        let (peer_name, root) = match snapshot.profile().source() {
            OneWaySource::PeerA => (
                snapshot.profile().peer_a().name().to_owned(),
                snapshot.profile().peer_a().root().to_path_buf(),
            ),
            OneWaySource::PeerB => (
                snapshot.profile().peer_b().name().to_owned(),
                snapshot.profile().peer_b().root().to_path_buf(),
            ),
        };
        let mut statement = self.connection.prepare(
            "SELECT relative_path, item_type, outcome, size,
                    modified_at_unix_nanos, readonly, symlink_target,
                    content_fingerprint
             FROM source_inventory_items WHERE run_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map(params![run_id.value()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let items = rows
            .into_iter()
            .map(
                |(
                    relative_path,
                    item_type,
                    outcome,
                    size,
                    modified_at_unix_nanos,
                    readonly,
                    symlink_target,
                    content_fingerprint,
                )| {
                    let size = u64::try_from(size).map_err(|_| {
                        StorageError::CorruptEvidence(
                            "source inventory contains a negative size".to_owned(),
                        )
                    })?;
                    Ok(InventorySnapshotItem::from_parts(
                        blob_to_path(&relative_path)?,
                        decode_item_type(&item_type)?,
                        decode_analysis_outcome(&outcome)?,
                        size,
                        modified_at_unix_nanos,
                        readonly,
                        symlink_target
                            .as_deref()
                            .map(blob_to_path)
                            .transpose()?,
                        decode_hash(content_fingerprint.as_deref())?,
                    ))
                },
            )
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok(SourceInventorySnapshot::from_parts(peer_name, root, items))
    }

    /// Persist the independent Completion Reconciliation result as durable
    /// report evidence. Re-running reconciliation replaces only this final
    /// derived record; the immutable inventory and action journal remain.
    pub fn record_reconciliation(
        &mut self,
        run_id: RunId,
        reconciliation: &CompletionReconciliation,
    ) -> Result<(), StorageError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT OR REPLACE INTO reconciliation_runs
                (run_id, source_drain_status) VALUES (?1, ?2)",
            params![
                run_id.value(),
                encode_source_drain_status(reconciliation.source_drain_status()),
            ],
        )?;
        transaction.execute(
            "DELETE FROM reconciliation_findings WHERE run_id = ?1",
            params![run_id.value()],
        )?;
        for (ordinal, finding) in reconciliation.findings().iter().enumerate() {
            let (reason, action_reason) = encode_reconciliation_reason(finding.reason());
            transaction.execute(
                "INSERT INTO reconciliation_findings (
                    run_id, ordinal, relative_path, kind, reason, action_reason
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run_id.value(),
                    ordinal as i64,
                    path_to_blob(finding.relative_path()),
                    encode_finding_kind(finding.kind()),
                    reason,
                    action_reason,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_reconciliation(
        &self,
        run_id: RunId,
    ) -> Result<Option<CompletionReconciliation>, StorageError> {
        let source_drain_status: Option<String> = self
            .connection
            .query_row(
                "SELECT source_drain_status FROM reconciliation_runs WHERE run_id = ?1",
                params![run_id.value()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(source_drain_status) = source_drain_status else {
            return Ok(None);
        };
        let mut statement = self.connection.prepare(
            "SELECT relative_path, kind, reason, action_reason
             FROM reconciliation_findings WHERE run_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map(params![run_id.value()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let findings = rows
            .into_iter()
            .map(|(relative_path, kind, reason, action_reason)| {
                let kind = decode_finding_kind(&kind)?;
                let parsed_reason = decode_reconciliation_reason(&reason, action_reason.as_deref())?;
                if parsed_reason.kind() != kind {
                    return Err(StorageError::CorruptEvidence(
                        "reconciliation finding kind and reason differ".to_owned(),
                    ));
                }
                Ok(crate::ReconciliationFinding::from_parts(
                    blob_to_path(&relative_path)?,
                    parsed_reason,
                ))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok(Some(CompletionReconciliation::from_parts(
            decode_source_drain_status(&source_drain_status)?,
            findings,
        )))
    }

    /// Record a fail-closed pre-mutation block in the run report.
    pub fn mark_blocked(&mut self, run_id: RunId, reason: &str) -> Result<(), StorageError> {
        let changed = self.connection.execute(
            "UPDATE run_snapshots SET blocked_reason = ?1 WHERE run_id = ?2",
            params![reason, run_id.value()],
        )?;
        if changed != 1 {
            return Err(StorageError::InvalidEvent(format!(
                "run {} does not exist",
                run_id.value()
            )));
        }
        Ok(())
    }

    pub fn next_run_id(&self) -> Result<RunId, StorageError> {
        let next: u64 = self.connection.query_row(
            "SELECT COALESCE(MAX(run_id), 0) + 1 FROM run_snapshots",
            [],
            |row| row.get(0),
        )?;
        Ok(RunId::new(next))
    }

    pub fn load_snapshot(&self, run_id: RunId) -> Result<RunSnapshot, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT snapshot_id, profile_name, peer_a_name, peer_a_root,
                        peer_b_name, peer_b_root, mode, source, safe_delete,
                        destination_cleanup, deletion_method,
                        allow_unattended_destructive, allow_unattended_permanent_removal,
                        metadata_file_type, metadata_executable_permissions,
                        metadata_symlink_targets, metadata_timestamps,
                        partial_transfer_policy, retry_max_attempts,
                        retry_initial_delay_millis
                 FROM run_snapshots WHERE run_id = ?1",
                params![run_id.value()],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, bool>(8)?,
                        row.get::<_, bool>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, bool>(11)?,
                        row.get::<_, bool>(12)?,
                        row.get::<_, bool>(13)?,
                        row.get::<_, bool>(14)?,
                        row.get::<_, bool>(15)?,
                        row.get::<_, bool>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, u8>(18)?,
                        row.get::<_, u64>(19)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            snapshot_id,
            profile_name,
            peer_a_name,
            peer_a_root,
            peer_b_name,
            peer_b_root,
            mode,
            source,
            safe_delete,
            destination_cleanup,
            deletion_method,
            allow_unattended_destructive,
            allow_unattended_permanent_removal,
            metadata_file_type,
            metadata_executable_permissions,
            metadata_symlink_targets,
            metadata_timestamps,
            partial_transfer_policy,
            retry_max_attempts,
            retry_initial_delay_millis,
        )) = row
        else {
            return Err(StorageError::InvalidEvent(format!(
                "run {} does not exist",
                run_id.value()
            )));
        };
        let exclusions = self
            .connection
            .prepare(
                "SELECT pattern FROM snapshot_exclusions
                 WHERE run_id = ?1 ORDER BY ordinal",
            )?
            .query_map(params![run_id.value()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let profile = SyncProfile::new(
            profile_name,
            Peer::new(peer_a_name, blob_to_path(&peer_a_root)?),
            Peer::new(peer_b_name, blob_to_path(&peer_b_root)?),
        )
        .with_source(decode_source(&source)?)
        .with_options(SyncOptions {
            safe_delete,
            destination_cleanup,
            deletion_method: deletion_method
                .as_deref()
                .map(decode_deletion_method)
                .transpose()?,
            metadata: MetadataRequirements::new(
                metadata_file_type,
                metadata_executable_permissions,
                metadata_symlink_targets,
                metadata_timestamps,
            ),
            partial_transfer_policy: decode_partial_transfer_policy(&partial_transfer_policy)?,
            retry_policy: RetryPolicy::new(
                retry_max_attempts,
                std::time::Duration::from_millis(retry_initial_delay_millis),
            ),
        })
        .with_exclusions(exclusions);
        let mut snapshot = RunSnapshot::from_profile(
            run_id,
            &profile,
            AuthorizationSnapshot::new(
                allow_unattended_destructive,
                allow_unattended_permanent_removal,
            ),
        )?;
        snapshot.snapshot_id = ProfileSnapshotId::new(snapshot_id);
        if mode != "one_way" {
            return Err(StorageError::CorruptEvidence(format!(
                "unsupported stored sync mode {mode}"
            )));
        }
        Ok(snapshot)
    }

    /// Append one action boundary in its own SQLite transaction. No method in
    /// this store mutates the filesystem; callers must reconcile filesystem
    /// uncertainty as a typed Recovery Review event.
    pub fn append_event(&mut self, run_id: RunId, event: JournalEvent) -> Result<(), StorageError> {
        #[cfg(test)]
        if self.fail_event_phase == Some(event_phase(&event)) {
            self.fail_event_phase = None;
            return Err(StorageError::InvalidEvent(
                "injected journal failure for safety-boundary testing".to_owned(),
            ));
        }
        let action_id = event_action_id(&event);
        let transaction = self.connection.transaction()?;
        let run_exists: Option<i64> = transaction
            .query_row(
                "SELECT run_id FROM run_snapshots WHERE run_id = ?1",
                params![run_id.value()],
                |row| row.get(0),
            )
            .optional()?;
        if run_exists.is_none() {
            return Err(StorageError::InvalidEvent(format!(
                "run {} does not exist",
                run_id.value()
            )));
        }

        let has_plan: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM action_events WHERE run_id = ?1 AND action_id = ?2 AND phase = 'planned')",
            params![run_id.value(), action_id],
            |row| row.get(0),
        )?;
        let current_phase: Option<String> = transaction
            .query_row(
                "SELECT phase FROM action_events
                 WHERE run_id = ?1 AND action_id = ?2
                 ORDER BY sequence DESC LIMIT 1",
                params![run_id.value(), action_id],
                |row| row.get(0),
            )
            .optional()?;
        let planned_operation: Option<String> = transaction
            .query_row(
                "SELECT operation FROM action_events
                 WHERE run_id = ?1 AND action_id = ?2 AND phase = 'planned'",
                params![run_id.value(), action_id],
                |row| row.get(0),
            )
            .optional()?;
        let configured_deletion_method: Option<String> = transaction
            .query_row(
                "SELECT deletion_method FROM run_snapshots WHERE run_id = ?1",
                params![run_id.value()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        validate_event(
            &event,
            has_plan,
            current_phase.as_deref(),
            planned_operation.as_deref(),
            configured_deletion_method.as_deref(),
        )?;
        validate_transfer_event_against_plan(&transaction, run_id, action_id, &event)?;
        validate_removal_result_against_proof(&transaction, run_id, action_id, &event)?;
        validate_action_order(&transaction, run_id, action_id, &event)?;
        validate_recovery_resolution(&transaction, run_id, action_id, &event)?;
        let sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), -1) + 1 FROM action_events
                 WHERE run_id = ?1 AND action_id = ?2",
                params![run_id.value(), action_id],
                |row| row.get::<_, i64>(0),
            )?;
        let fields = EventFields::from_event(&event);
        transaction.execute(
            "INSERT INTO action_events (
                run_id, action_id, sequence, phase, relative_path, operation,
                affected_side, planned_bytes, pre_item_type, pre_size,
                pre_modified_at_unix_nanos, pre_device, pre_inode, pre_sha256,
                progress_bytes, reason, recovery_observed_at_unix_nanos,
                recovery_target, recovery_source_present, recovery_destination_present,
                recovery_present, recovery_source_size, recovery_destination_size,
                recovery_source_sha256, recovery_destination_sha256, resolution,
                proof_destination_size, proof_destination_sha256,
                proof_metadata_verified, deletion_method
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30)",
            params![
                run_id.value(),
                action_id,
                sequence,
                fields.phase,
                fields.relative_path,
                fields.operation,
                fields.affected_side,
                fields.planned_bytes,
                fields.pre_item_type,
                fields.pre_size,
                fields.pre_modified_at_unix_nanos,
                fields.pre_device,
                fields.pre_inode,
                fields.pre_sha256,
                fields.progress_bytes,
                fields.reason,
                fields.recovery_observed_at_unix_nanos,
                fields.recovery_target,
                fields.recovery_source_present,
                fields.recovery_destination_present,
                fields.recovery_present,
                fields.recovery_source_size,
                fields.recovery_destination_size,
                fields.recovery_source_sha256,
                fields.recovery_destination_sha256,
                fields.resolution,
                fields.proof_destination_size,
                fields.proof_destination_sha256,
                fields.proof_metadata_verified,
                fields.deletion_method,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_event_phase_for_test(&mut self, phase: &'static str) {
        self.fail_event_phase = Some(phase);
    }

    pub fn load_journal(&self, run_id: RunId) -> Result<Vec<ActionJournalEntry>, StorageError> {
        let configured_deletion_method: Option<String> = self
            .connection
            .query_row(
                "SELECT deletion_method FROM run_snapshots WHERE run_id = ?1",
                params![run_id.value()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let mut statement = self.connection.prepare(
            "SELECT action_id, sequence, phase, relative_path, operation,
                    affected_side, planned_bytes, pre_item_type, pre_size,
                    pre_modified_at_unix_nanos, pre_device, pre_inode, pre_sha256,
                    progress_bytes, reason, recovery_observed_at_unix_nanos,
                    recovery_target, recovery_source_present, recovery_destination_present,
                    recovery_present, recovery_source_size, recovery_destination_size,
                    recovery_source_sha256, recovery_destination_sha256, resolution,
                    proof_destination_size, proof_destination_sha256,
                    proof_metadata_verified, deletion_method
             FROM action_events WHERE run_id = ?1 ORDER BY action_id, sequence",
        )?;
        let rows = statement
            .query_map(params![run_id.value()], |row| {
                Ok(StoredEvent {
                    action_id: row.get(0)?,
                    phase: row.get(2)?,
                    relative_path: row.get(3)?,
                    operation: row.get(4)?,
                    affected_side: row.get(5)?,
                    planned_bytes: row.get(6)?,
                    pre_item_type: row.get(7)?,
                    pre_size: row.get(8)?,
                    pre_modified_at_unix_nanos: row.get(9)?,
                    pre_device: row.get(10)?,
                    pre_inode: row.get(11)?,
                    pre_sha256: row.get(12)?,
                    progress_bytes: row.get(13)?,
                    reason: row.get(14)?,
                    recovery_observed_at_unix_nanos: row.get(15)?,
                    recovery_target: row.get(16)?,
                    recovery_source_present: row.get(17)?,
                    recovery_destination_present: row.get(18)?,
                    recovery_present: row.get(19)?,
                    recovery_source_size: row.get(20)?,
                    recovery_destination_size: row.get(21)?,
                    recovery_source_sha256: row.get(22)?,
                    recovery_destination_sha256: row.get(23)?,
                    resolution: row.get(24)?,
                    proof_destination_size: row.get(25)?,
                    proof_destination_sha256: row.get(26)?,
                    proof_metadata_verified: row.get(27)?,
                    deletion_method: row.get(28)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries = BTreeMap::new();
        for row in rows {
            apply_stored_event(&mut entries, row, configured_deletion_method.as_deref())?;
        }
        Ok(entries.into_values().collect())
    }

    pub fn load_report(&self, run_id: RunId) -> Result<RunReport, StorageError> {
        let snapshot = self.load_snapshot(run_id)?;
        let journal = self.load_journal(run_id)?;
        let review_cleared: bool = self.connection.query_row(
            "SELECT review_cleared FROM run_snapshots WHERE run_id = ?1",
            params![run_id.value()],
            |row| row.get(0),
        )?;
        let blocked_reason: Option<String> = self.connection.query_row(
            "SELECT blocked_reason FROM run_snapshots WHERE run_id = ?1",
            params![run_id.value()],
            |row| row.get(0),
        )?;
        let reconciliation = self.load_reconciliation(run_id)?;
        let inventory_recorded: bool = self.connection.query_row(
            "SELECT source_inventory_recorded FROM run_snapshots WHERE run_id = ?1",
            params![run_id.value()],
            |row| row.get(0),
        )?;
        let items: Vec<_> = journal
            .into_iter()
            .map(|journal| RunReportItem { journal })
            .collect();
        let status = report_status(
            &items,
            review_cleared,
            blocked_reason.is_some(),
            reconciliation.as_ref(),
            inventory_recorded,
        );
        let execution_result = execution_result(&items, blocked_reason.is_some(), reconciliation.is_some());
        let lifecycle = if review_cleared {
            RunLifecycle::ReviewCleared
        } else if blocked_reason.is_some()
            || reconciliation
                .as_ref()
                .is_some_and(CompletionReconciliation::requires_review)
        {
            RunLifecycle::ReviewRequired
        } else if items.iter().any(|item| {
            matches!(
                item.outcome(),
                ActionOutcome::Failed(_)
                    | ActionOutcome::Cancelled
                    | ActionOutcome::Interrupted
                    | ActionOutcome::Deferred
                    | ActionOutcome::Unresolved(_)
                    | ActionOutcome::RecoveryReview(_)
            )
        }) {
            RunLifecycle::ReviewRequired
        } else {
            RunLifecycle::Open
        };
        Ok(RunReport {
            run_id,
            snapshot,
            items,
            status,
            execution_result,
            lifecycle,
            blocked_reason,
            reconciliation,
            reconciliation_required: inventory_recorded,
        })
    }

    /// Record the user's explicit final acknowledgement after every action is
    /// settled. This never changes user files or erases the journal.
    pub fn mark_review_cleared(&mut self, run_id: RunId) -> Result<(), StorageError> {
        let report = self.load_report(run_id)?;
        if !report.can_mark_review_cleared() {
            return Err(StorageError::InvalidEvent(
                "Review-Cleared requires settled actions and a reconciliation with no findings"
                    .to_owned(),
            ));
        }
        self.connection.execute(
            "UPDATE run_snapshots SET review_cleared = 1 WHERE run_id = ?1",
            params![run_id.value()],
        )?;
        Ok(())
    }
}

fn verify_integrity(connection: &Connection) -> Result<(), StorageError> {
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if result != "ok" {
        return Err(StorageError::CorruptEvidence(format!(
            "SQLite integrity check failed: {result}"
        )));
    }
    Ok(())
}

struct EventFields {
    phase: &'static str,
    relative_path: Option<Vec<u8>>,
    operation: Option<&'static str>,
    affected_side: Option<&'static str>,
    planned_bytes: Option<i64>,
    pre_item_type: Option<&'static str>,
    pre_size: Option<i64>,
    pre_modified_at_unix_nanos: Option<i64>,
    pre_device: Option<u64>,
    pre_inode: Option<u64>,
    pre_sha256: Option<Vec<u8>>,
    progress_bytes: Option<i64>,
    reason: Option<&'static str>,
    recovery_observed_at_unix_nanos: Option<i64>,
    recovery_target: Option<Vec<u8>>,
    recovery_source_present: Option<i64>,
    recovery_destination_present: Option<i64>,
    recovery_present: Option<i64>,
    recovery_source_size: Option<i64>,
    recovery_destination_size: Option<i64>,
    recovery_source_sha256: Option<Vec<u8>>,
    recovery_destination_sha256: Option<Vec<u8>>,
    resolution: Option<&'static str>,
    proof_destination_size: Option<i64>,
    proof_destination_sha256: Option<Vec<u8>>,
    proof_metadata_verified: Option<i64>,
    deletion_method: Option<&'static str>,
}

impl EventFields {
    fn from_event(event: &JournalEvent) -> Self {
        let empty = || Self {
            phase: "",
            relative_path: None,
            operation: None,
            affected_side: None,
            planned_bytes: None,
            pre_item_type: None,
            pre_size: None,
            pre_modified_at_unix_nanos: None,
            pre_device: None,
            pre_inode: None,
            pre_sha256: None,
            progress_bytes: None,
            reason: None,
            recovery_observed_at_unix_nanos: None,
            recovery_target: None,
            recovery_source_present: None,
            recovery_destination_present: None,
            recovery_present: None,
            recovery_source_size: None,
            recovery_destination_size: None,
            recovery_source_sha256: None,
            recovery_destination_sha256: None,
            resolution: None,
            proof_destination_size: None,
            proof_destination_sha256: None,
            proof_metadata_verified: None,
            deletion_method: None,
        };
        match event {
            JournalEvent::Planned { action } => Self {
                phase: "planned",
                relative_path: Some(path_to_blob(&action.relative_path)),
                operation: Some(encode_operation(action.operation)),
                affected_side: Some(encode_side(action.affected_side)),
                planned_bytes: action.planned_bytes.map(|bytes| bytes as i64),
                pre_item_type: Some(encode_item_type(action.pre_action.item_type)),
                pre_size: Some(action.pre_action.size as i64),
                pre_modified_at_unix_nanos: action.pre_action.modified_at_unix_nanos,
                pre_device: action.pre_action.identity.as_ref().map(FileIdentity::device),
                pre_inode: action.pre_action.identity.as_ref().map(FileIdentity::inode),
                pre_sha256: action.pre_action.sha256.map(|hash| hash.to_vec()),
                progress_bytes: None,
                reason: None,
                recovery_observed_at_unix_nanos: None,
                recovery_target: None,
                recovery_source_present: None,
                recovery_destination_present: None,
                recovery_present: None,
                recovery_source_size: None,
                recovery_destination_size: None,
                recovery_source_sha256: None,
                recovery_destination_sha256: None,
                resolution: None,
                proof_destination_size: None,
                proof_destination_sha256: None,
                proof_metadata_verified: None,
                deletion_method: None,
            },
            JournalEvent::Started { .. } => {
                let mut fields = empty();
                fields.phase = "started";
                fields
            }
            JournalEvent::Progress {
                completed_bytes, ..
            } => {
                let mut fields = empty();
                fields.phase = "progress";
                fields.progress_bytes = Some(*completed_bytes as i64);
                fields
            }
            JournalEvent::TransferVerified {
                evidence,
                metadata_verified,
                ..
            } => {
                let mut fields = empty();
                fields.phase = "transfer_verified";
                fields.proof_destination_size = evidence.destination_size.map(|size| size as i64);
                fields.proof_destination_sha256 = evidence.destination_sha256.map(|hash| hash.to_vec());
                fields.proof_metadata_verified = Some(bool_to_int(*metadata_verified));
                set_recovery_fields(&mut fields, evidence);
                fields
            }
            JournalEvent::ProofBoundary {
                deletion_method,
                evidence,
                metadata_verified,
                ..
            } => {
                let mut fields = empty();
                fields.phase = "proof_boundary";
                fields.deletion_method = Some(encode_deletion_method(*deletion_method));
                fields.proof_destination_size = evidence.destination_size.map(|size| size as i64);
                fields.proof_destination_sha256 =
                    evidence.destination_sha256.map(|hash| hash.to_vec());
                fields.proof_metadata_verified = Some(bool_to_int(*metadata_verified));
                set_recovery_fields(&mut fields, evidence);
                fields
            }
            JournalEvent::RemovalStarted {
                deletion_method, ..
            } => {
                let mut fields = empty();
                fields.phase = "removal_started";
                fields.deletion_method = Some(encode_deletion_method(*deletion_method));
                fields
            }
            JournalEvent::RemovalCompleted { result, .. } => {
                let mut fields = empty();
                fields.phase = "removal_completed";
                fields.deletion_method = Some(encode_deletion_method(result.deletion_method()));
                set_recovery_fields(&mut fields, result.evidence());
                fields
            }
            JournalEvent::Completed { .. } => {
                let mut fields = empty();
                fields.phase = "completed";
                fields
            }
            JournalEvent::Failed { reason, .. } => terminal_fields("failed", *reason),
            JournalEvent::Cancelled { .. } => {
                let mut fields = empty();
                fields.phase = "cancelled";
                fields
            }
            JournalEvent::Interrupted { .. } => {
                let mut fields = empty();
                fields.phase = "interrupted";
                fields
            }
            JournalEvent::Deferred { .. } => {
                let mut fields = empty();
                fields.phase = "deferred";
                fields.reason = Some(encode_reason(ActionReason::DeferredForReview));
                fields
            }
            JournalEvent::Unresolved { reason, .. } => terminal_fields("unresolved", *reason),
            JournalEvent::RecoveryReview { reason, .. } => {
                let JournalEvent::RecoveryReview { evidence, .. } = event else {
                    unreachable!()
                };
                let mut fields = terminal_fields("recovery_review", *reason);
                set_recovery_fields(&mut fields, evidence);
                fields
            }
            JournalEvent::RecoveryResolved { resolution, .. } => {
                let mut fields = empty();
                fields.phase = "recovery_resolved";
                fields.resolution = Some(encode_resolution(resolution));
                if let RecoveryResolution::Completed { evidence } = resolution {
                    set_recovery_fields(&mut fields, evidence);
                }
                fields
            }
        }
    }
}

fn set_recovery_fields(fields: &mut EventFields, evidence: &RecoveryEvidence) {
    fields.recovery_observed_at_unix_nanos = Some(evidence.observed_at_unix_nanos);
    fields.recovery_target = evidence
        .recovery_target
        .as_ref()
        .map(|path| path_to_blob(path));
    fields.recovery_source_present = Some(bool_to_int(evidence.source_present));
    fields.recovery_destination_present = Some(bool_to_int(evidence.destination_present));
    fields.recovery_present = Some(bool_to_int(evidence.recovery_present));
    fields.recovery_source_size = evidence.source_size.map(|size| size as i64);
    fields.recovery_destination_size = evidence.destination_size.map(|size| size as i64);
    fields.recovery_source_sha256 = evidence.source_sha256.map(|hash| hash.to_vec());
    fields.recovery_destination_sha256 = evidence.destination_sha256.map(|hash| hash.to_vec());
}

fn terminal_fields(phase: &'static str, reason: ActionReason) -> EventFields {
    EventFields {
        phase,
        relative_path: None,
        operation: None,
        affected_side: None,
        planned_bytes: None,
        pre_item_type: None,
        pre_size: None,
        pre_modified_at_unix_nanos: None,
        pre_device: None,
        pre_inode: None,
        pre_sha256: None,
        progress_bytes: None,
        reason: Some(encode_reason(reason)),
        recovery_observed_at_unix_nanos: None,
        recovery_target: None,
        recovery_source_present: None,
        recovery_destination_present: None,
        recovery_present: None,
        recovery_source_size: None,
        recovery_destination_size: None,
        recovery_source_sha256: None,
        recovery_destination_sha256: None,
        resolution: None,
        proof_destination_size: None,
        proof_destination_sha256: None,
        proof_metadata_verified: None,
        deletion_method: None,
    }
}

struct StoredEvent {
    action_id: ActionId,
    phase: String,
    relative_path: Option<Vec<u8>>,
    operation: Option<String>,
    affected_side: Option<String>,
    planned_bytes: Option<u64>,
    pre_item_type: Option<String>,
    pre_size: Option<u64>,
    pre_modified_at_unix_nanos: Option<i64>,
    pre_device: Option<u64>,
    pre_inode: Option<u64>,
    pre_sha256: Option<Vec<u8>>,
    progress_bytes: Option<u64>,
    reason: Option<String>,
    recovery_observed_at_unix_nanos: Option<i64>,
    recovery_target: Option<Vec<u8>>,
    recovery_source_present: Option<bool>,
    recovery_destination_present: Option<bool>,
    recovery_present: Option<bool>,
    recovery_source_size: Option<u64>,
    recovery_destination_size: Option<u64>,
    recovery_source_sha256: Option<Vec<u8>>,
    recovery_destination_sha256: Option<Vec<u8>>,
    resolution: Option<String>,
    proof_destination_size: Option<u64>,
    proof_destination_sha256: Option<Vec<u8>>,
    proof_metadata_verified: Option<bool>,
    deletion_method: Option<String>,
}

fn apply_stored_event(
    entries: &mut BTreeMap<ActionId, ActionJournalEntry>,
    row: StoredEvent,
    configured_deletion_method: Option<&str>,
) -> Result<(), StorageError> {
    if row.phase == "planned" {
        let relative_path = blob_to_path(
            row.relative_path
                .as_deref()
                .ok_or_else(|| StorageError::CorruptEvidence("planned action has no path".to_owned()))?,
        )?;
        let operation = decode_operation(row.operation.as_deref().ok_or_else(|| {
            StorageError::CorruptEvidence("planned action has no operation".to_owned())
        })?)?;
        let affected_side = decode_side(row.affected_side.as_deref().ok_or_else(|| {
            StorageError::CorruptEvidence("planned action has no affected side".to_owned())
        })?)?;
        let item_type = decode_item_type(row.pre_item_type.as_deref().ok_or_else(|| {
            StorageError::CorruptEvidence("planned action has no item type".to_owned())
        })?)?;
        let size = row
            .pre_size
            .ok_or_else(|| StorageError::CorruptEvidence("planned action has no size".to_owned()))?;
        let sha256 = row.pre_sha256.map(|bytes| {
            let mut hash = [0u8; 32];
            if bytes.len() == hash.len() {
                hash.copy_from_slice(&bytes);
                Ok(hash)
            } else {
                Err(StorageError::CorruptEvidence(
                    "stored SHA-256 digest has the wrong length".to_owned(),
                ))
            }
        });
        let sha256 = sha256.transpose()?;
        if entries.contains_key(&row.action_id) {
            return Err(StorageError::CorruptEvidence(
                "action has more than one planned boundary".to_owned(),
            ));
        }
        entries.insert(
            row.action_id,
            ActionJournalEntry {
                plan: PlanRecord::new(
                    row.action_id,
                    relative_path,
                    operation,
                    affected_side,
                    row.planned_bytes,
                    PreActionState::new(
                        item_type,
                        size,
                        row.pre_modified_at_unix_nanos,
                        match (row.pre_device, row.pre_inode) {
                            (Some(device), Some(inode)) => Some(FileIdentity::new(device, inode)),
                            (None, None) => None,
                            _ => {
                                return Err(StorageError::CorruptEvidence(
                                    "stored file identity is incomplete".to_owned(),
                                ))
                            }
                        },
                        sha256,
                    ),
                ),
                last_phase: "planned".to_owned(),
                started: false,
                progress_bytes: Vec::new(),
                outcome: ActionOutcome::InProgress,
                transfer_evidence: None,
                proof_boundary: None,
                removal_result: None,
                recovery_evidence: None,
                recovery_resolution_evidence: None,
            },
        );
        return Ok(());
    }

    let entry = entries.get_mut(&row.action_id).ok_or_else(|| {
        StorageError::CorruptEvidence("non-planned boundary has no planned action".to_owned())
    })?;
    validate_replayed_transition(entry, &row.phase)?;
    match row.phase.as_str() {
        "started" => entry.started = true,
        "progress" => entry
            .progress_bytes
            .push(row.progress_bytes.ok_or_else(|| {
                StorageError::CorruptEvidence("progress boundary has no byte count".to_owned())
            })?),
        "transfer_verified" => {
            if entry.plan.operation() != PlanActionKind::RemoveSourceAfterVerification
                || row.proof_metadata_verified != Some(true)
            {
                return Err(StorageError::CorruptEvidence(
                    "verified transfer boundary is only valid for Safe Delete with metadata proof"
                        .to_owned(),
                ));
            }
            let evidence = decode_recovery_evidence(&row)?;
            validate_transfer_evidence(entry, &evidence)?;
            entry.transfer_evidence = Some(evidence);
            entry.outcome = ActionOutcome::InProgress;
        }
        "proof_boundary" => {
            if entry.plan.operation() == PlanActionKind::RemoveSourceAfterVerification
                && entry.transfer_evidence.is_none()
            {
                return Err(StorageError::CorruptEvidence(
                    "Safe Delete proof boundary has no verified transfer boundary".to_owned(),
                ));
            }
            let method = row.deletion_method.as_deref().ok_or_else(|| {
                StorageError::CorruptEvidence("proof boundary has no deletion method".to_owned())
            })?;
            let deletion_method = decode_deletion_method(method)?;
            validate_replayed_deletion_method(entry, deletion_method, configured_deletion_method)?;
            if row.proof_metadata_verified != Some(true)
                || row.proof_destination_size.is_none()
                || row.proof_destination_sha256.is_none()
            {
                return Err(StorageError::CorruptEvidence(
                    "proof boundary is missing metadata or destination content evidence"
                        .to_owned(),
                ));
            }
            let evidence = decode_recovery_evidence(&row)?;
            let proof_destination_size = row.proof_destination_size.ok_or_else(|| {
                StorageError::CorruptEvidence("proof boundary has no destination size".to_owned())
            })?;
            let proof_destination_sha256 =
                decode_hash(row.proof_destination_sha256.as_deref())?.ok_or_else(|| {
                    StorageError::CorruptEvidence(
                        "proof boundary has no destination SHA-256".to_owned(),
                    )
                })?;
            if !evidence.source_present()
                || !evidence.destination_present()
                || evidence.recovery_present()
                || evidence.recovery_target().is_some()
                || evidence.source_size().is_none()
                || evidence.source_sha256().is_none()
                || evidence.destination_size() != Some(proof_destination_size)
                || evidence.destination_sha256() != Some(&proof_destination_sha256)
            {
                return Err(StorageError::CorruptEvidence(
                    "proof boundary has incomplete source or destination evidence".to_owned(),
                ));
            }
            entry.proof_boundary = Some(evidence);
            entry.outcome = ActionOutcome::RecoveryReview(ActionReason::InterruptedBoundary);
        }
        "removal_started" => {
            let method = row.deletion_method.as_deref().ok_or_else(|| {
                StorageError::CorruptEvidence("removal start has no deletion method".to_owned())
            })?;
            let deletion_method = decode_deletion_method(method)?;
            validate_replayed_deletion_method(entry, deletion_method, configured_deletion_method)?;
            entry.outcome = ActionOutcome::RecoveryReview(ActionReason::InterruptedBoundary);
        }
        "removal_completed" => {
            let method = row.deletion_method.as_deref().ok_or_else(|| {
                StorageError::CorruptEvidence(
                    "removal result has no deletion method".to_owned(),
                )
            })?;
            let evidence = decode_recovery_evidence(&row)?;
            let deletion_method = decode_deletion_method(method)?;
            validate_replayed_deletion_method(entry, deletion_method, configured_deletion_method)?;
            validate_removal_evidence(deletion_method, &evidence)?;
            if let Some(proof) = entry.proof_boundary.as_ref()
                && (proof.destination_size() != evidence.destination_size()
                    || proof.destination_sha256() != evidence.destination_sha256())
            {
                return Err(StorageError::CorruptEvidence(
                    "removal result does not match the persisted proof boundary".to_owned(),
                ));
            }
            entry.removal_result = Some(RemovalResult::new(deletion_method, evidence));
            entry.outcome = ActionOutcome::Completed;
        }
        "completed" => {
            if entry.plan.operation() == PlanActionKind::RemoveSourceAfterVerification {
                return Err(StorageError::CorruptEvidence(
                    "Safe Delete action has generic completion without a removal result"
                        .to_owned(),
                ));
            }
            entry.outcome = ActionOutcome::Completed;
        }
        "failed" => {
            entry.outcome = ActionOutcome::Failed(decode_reason(row.reason.as_deref().ok_or_else(
                || StorageError::CorruptEvidence("failed boundary has no reason".to_owned()),
            )?)?);
        }
        "cancelled" => entry.outcome = ActionOutcome::Cancelled,
        "interrupted" => entry.outcome = ActionOutcome::Interrupted,
        "deferred" => entry.outcome = ActionOutcome::Deferred,
        "unresolved" => {
            entry.outcome = ActionOutcome::Unresolved(decode_reason(
                row.reason.as_deref().ok_or_else(|| {
                    StorageError::CorruptEvidence("unresolved boundary has no reason".to_owned())
                })?,
            )?);
        }
        "recovery_review" => {
            entry.recovery_evidence = Some(decode_recovery_evidence(&row)?);
            entry.outcome = ActionOutcome::RecoveryReview(decode_reason(
                row.reason.as_deref().ok_or_else(|| {
                    StorageError::CorruptEvidence(
                        "recovery review boundary has no reason".to_owned(),
                    )
                })?,
            )?);
        }
        "recovery_resolved" => match decode_resolution(
            row.resolution.as_deref().ok_or_else(|| {
                StorageError::CorruptEvidence("recovery resolution has no outcome".to_owned())
            })?,
            &row,
        )? {
            RecoveryResolution::Completed { evidence } => {
                if entry.plan.operation() == PlanActionKind::RemoveSourceAfterVerification {
                    return Err(StorageError::CorruptEvidence(
                        "Safe Delete action has an unverified recovery completion".to_owned(),
                    ));
                }
                if let Some(review) = entry.recovery_evidence.as_ref() {
                    if !evidence.is_newer_than(review) {
                        return Err(StorageError::CorruptEvidence(
                            "recovery resolution evidence is not newer than its review"
                                .to_owned(),
                        ));
                    }
                }
                entry.recovery_resolution_evidence = Some(evidence);
                entry.outcome = ActionOutcome::Completed;
            }
            RecoveryResolution::Unresolved(reason) => {
                entry.outcome = ActionOutcome::Unresolved(reason)
            }
        },
        phase => {
            return Err(StorageError::CorruptEvidence(format!(
                "unknown journal phase {phase}"
            )))
        }
    }
    entry.last_phase = row.phase;
    Ok(())
}

fn validate_replayed_transition(
    entry: &ActionJournalEntry,
    next_phase: &str,
) -> Result<(), StorageError> {
    let allowed = match next_phase {
        "started" => entry.last_phase == "planned",
        "progress" => matches!(entry.last_phase.as_str(), "started" | "progress"),
        "transfer_verified" => {
            entry.plan.operation() == PlanActionKind::RemoveSourceAfterVerification
                && matches!(entry.last_phase.as_str(), "started" | "progress")
                && entry.transfer_evidence.is_none()
        }
        "proof_boundary" => {
            (entry.plan.operation() != PlanActionKind::RemoveSourceAfterVerification
                && matches!(entry.last_phase.as_str(), "started" | "progress")
                || entry.plan.operation() == PlanActionKind::RemoveSourceAfterVerification
                    && entry.last_phase == "transfer_verified"
                    && entry.transfer_evidence.is_some())
                && entry.proof_boundary.is_none()
        }
        "removal_started" => {
            entry.last_phase == "proof_boundary" && entry.proof_boundary.is_some()
        }
        "removal_completed" => {
            entry.last_phase == "removal_started"
                && entry.proof_boundary.is_some()
                && entry.removal_result.is_none()
        }
        "recovery_review" => {
            matches!(
                entry.last_phase.as_str(),
                "started" | "progress" | "proof_boundary" | "removal_started"
                    | "transfer_verified"
            ) && entry.recovery_evidence.is_none()
        }
        "recovery_resolved" => {
            entry.last_phase == "recovery_review"
                && entry.recovery_evidence.is_some()
                && entry.recovery_resolution_evidence.is_none()
        }
        "cancelled" | "interrupted" => {
            entry.last_phase == "planned"
                || matches!(entry.last_phase.as_str(), "started" | "progress")
        }
        "completed" | "failed" | "deferred" | "unresolved" => matches!(
            entry.last_phase.as_str(),
            "started" | "progress" | "transfer_verified" | "proof_boundary" | "removal_started"
        ),
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(StorageError::CorruptEvidence(format!(
            "{next_phase} cannot follow {} during journal replay",
            entry.last_phase
        )))
    }
}

fn validate_removal_evidence(
    deletion_method: DeletionMethod,
    evidence: &RecoveryEvidence,
) -> Result<(), StorageError> {
    let valid_recovery = match deletion_method {
        DeletionMethod::Trash => evidence.recovery_present() && evidence.recovery_target().is_some(),
        DeletionMethod::PermanentRemoval => {
            !evidence.recovery_present() && evidence.recovery_target().is_none()
        }
    };
    if evidence.source_present()
        || !evidence.destination_present()
        || evidence.destination_size().is_none()
        || evidence.destination_sha256().is_none()
        || !valid_recovery
    {
        return Err(StorageError::CorruptEvidence(
            "removal result does not prove source absence and the selected recovery outcome"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_transfer_evidence(
    entry: &ActionJournalEntry,
    evidence: &RecoveryEvidence,
) -> Result<(), StorageError> {
    if !evidence.source_present()
        || !evidence.destination_present()
        || evidence.recovery_present()
        || evidence.recovery_target().is_some()
        || evidence.source_size() != Some(entry.plan.pre_action().size())
        || evidence.source_sha256() != entry.plan.pre_action().sha256()
        || evidence.destination_size().is_none()
        || evidence.destination_sha256().is_none()
    {
        return Err(StorageError::CorruptEvidence(
            "verified transfer boundary does not match the frozen source proof".to_owned(),
        ));
    }
    Ok(())
}

fn validate_replayed_deletion_method(
    entry: &ActionJournalEntry,
    deletion_method: DeletionMethod,
    configured_deletion_method: Option<&str>,
) -> Result<(), StorageError> {
    if entry.plan.operation() != PlanActionKind::RemoveSourceAfterVerification
        || configured_deletion_method != Some(encode_deletion_method(deletion_method))
    {
        return Err(StorageError::CorruptEvidence(
            "replayed removal boundary does not match the frozen Safe Delete method".to_owned(),
        ));
    }
    Ok(())
}

fn decode_recovery_evidence(row: &StoredEvent) -> Result<RecoveryEvidence, StorageError> {
    let observed_at_unix_nanos = row.recovery_observed_at_unix_nanos.ok_or_else(|| {
        StorageError::CorruptEvidence("recovery review has no observation time".to_owned())
    })?;
    let source_present = row.recovery_source_present.ok_or_else(|| {
        StorageError::CorruptEvidence("recovery review has no source presence evidence".to_owned())
    })?;
    let destination_present = row.recovery_destination_present.ok_or_else(|| {
        StorageError::CorruptEvidence(
            "recovery review has no destination presence evidence".to_owned(),
        )
    })?;
    let recovery_present = row.recovery_present.ok_or_else(|| {
        StorageError::CorruptEvidence("recovery review has no recovery presence evidence".to_owned())
    })?;
    Ok(RecoveryEvidence::new(
        observed_at_unix_nanos,
        row.recovery_target
            .as_deref()
            .map(blob_to_path)
            .transpose()?,
        source_present,
        destination_present,
        recovery_present,
        row.recovery_source_size,
        row.recovery_destination_size,
        decode_hash(row.recovery_source_sha256.as_deref())?,
        decode_hash(row.recovery_destination_sha256.as_deref())?,
    ))
}

fn decode_hash(bytes: Option<&[u8]>) -> Result<Option<[u8; 32]>, StorageError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let mut hash = [0u8; 32];
    if bytes.len() != hash.len() {
        return Err(StorageError::CorruptEvidence(
            "stored recovery SHA-256 digest has the wrong length".to_owned(),
        ));
    }
    hash.copy_from_slice(bytes);
    Ok(Some(hash))
}

fn validate_event(
    event: &JournalEvent,
    has_plan: bool,
    current_phase: Option<&str>,
    planned_operation: Option<&str>,
    configured_deletion_method: Option<&str>,
) -> Result<(), StorageError> {
    if let JournalEvent::TransferVerified {
        evidence,
        metadata_verified,
        ..
    } = event
    {
        if planned_operation != Some("remove_source_after_verification")
            || !metadata_verified
            || !evidence.source_present()
            || !evidence.destination_present()
            || evidence.recovery_present()
            || evidence.recovery_target().is_some()
            || evidence.source_size().is_none()
            || evidence.source_sha256().is_none()
            || evidence.destination_size().is_none()
            || evidence.destination_sha256().is_none()
            || !matches!(current_phase, Some("started" | "progress"))
        {
            return Err(StorageError::InvalidEvent(
                "verified transfer boundary is incomplete or out of order".to_owned(),
            ));
        }
    }
    if let JournalEvent::ProofBoundary {
        evidence,
        metadata_verified,
        ..
    } = event
    {
        if !metadata_verified
            || !evidence.source_present()
            || !evidence.destination_present()
            || evidence.recovery_present()
            || evidence.recovery_target().is_some()
            || evidence.destination_size().is_none()
            || evidence.destination_sha256().is_none()
            || evidence.source_size().is_none()
            || evidence.source_sha256().is_none()
        {
            return Err(StorageError::InvalidEvent(
                "proof boundary is missing independent destination or metadata evidence".to_owned(),
            ));
        }
        if planned_operation == Some("remove_source_after_verification")
            && current_phase != Some("transfer_verified")
        {
            return Err(StorageError::InvalidEvent(
                "Safe Delete proof boundary requires a verified transfer boundary".to_owned(),
            ));
        }
    }
    if matches!(event, JournalEvent::Completed { .. })
        && planned_operation == Some("remove_source_after_verification")
    {
        return Err(StorageError::InvalidEvent(
            "source-removal actions must settle through RemovalCompleted".to_owned(),
        ));
    }
    if matches!(
        event,
        JournalEvent::RecoveryResolved {
            resolution: RecoveryResolution::Completed { .. },
            ..
        }
    ) && planned_operation
        == Some("remove_source_after_verification")
    {
        return Err(StorageError::InvalidEvent(
            "Safe Delete recovery cannot be marked completed without a RemovalCompleted result"
                .to_owned(),
        ));
    }
    let event_method = match event {
        JournalEvent::ProofBoundary {
            deletion_method, ..
        }
        | JournalEvent::RemovalStarted {
            deletion_method, ..
        } => Some(*deletion_method),
        JournalEvent::RemovalCompleted { result, .. } => Some(result.deletion_method()),
        JournalEvent::Planned { .. }
        | JournalEvent::Started { .. }
        | JournalEvent::Progress { .. }
        | JournalEvent::TransferVerified { .. }
        | JournalEvent::Completed { .. }
        | JournalEvent::Failed { .. }
        | JournalEvent::Cancelled { .. }
        | JournalEvent::Interrupted { .. }
        | JournalEvent::Deferred { .. }
        | JournalEvent::Unresolved { .. }
        | JournalEvent::RecoveryReview { .. }
        | JournalEvent::RecoveryResolved { .. } => None,
    };
    if let Some(event_method) = event_method {
        if planned_operation != Some("remove_source_after_verification")
            || configured_deletion_method != Some(encode_deletion_method(event_method))
        {
            return Err(StorageError::InvalidEvent(
                "removal boundary does not match the frozen Safe Delete method".to_owned(),
            ));
        }
    }
    if let JournalEvent::RemovalCompleted { result, .. } = event {
        let evidence = result.evidence();
        let valid_recovery = match result.deletion_method() {
            DeletionMethod::Trash => {
                evidence.recovery_present() && evidence.recovery_target().is_some()
            }
            DeletionMethod::PermanentRemoval => {
                !evidence.recovery_present() && evidence.recovery_target().is_none()
            }
        };
        if evidence.source_present()
            || !evidence.destination_present()
            || evidence.destination_size().is_none()
            || evidence.destination_sha256().is_none()
            || !valid_recovery
        {
            return Err(StorageError::InvalidEvent(
                "removal result does not prove source absence and the selected recovery outcome"
                    .to_owned(),
            ));
        }
    }
    let phase = match event {
        JournalEvent::Planned { .. } => "planned",
        JournalEvent::Started { .. } => "started",
        JournalEvent::Progress { .. } => "progress",
        JournalEvent::TransferVerified { .. } => "transfer_verified",
        JournalEvent::ProofBoundary { .. } => "proof_boundary",
        JournalEvent::RemovalStarted { .. } => "removal_started",
        JournalEvent::RemovalCompleted { .. } => "removal_completed",
        JournalEvent::Completed { .. } => "completed",
        JournalEvent::Failed { .. } => "failed",
        JournalEvent::Cancelled { .. } => "cancelled",
        JournalEvent::Interrupted { .. } => "interrupted",
        JournalEvent::Deferred { .. } => "deferred",
        JournalEvent::Unresolved { .. } => "unresolved",
        JournalEvent::RecoveryReview { .. } => "recovery_review",
        JournalEvent::RecoveryResolved { .. } => "recovery_resolved",
    };
    if phase == "planned" {
        if has_plan {
            return Err(StorageError::InvalidEvent(
                "an action can have only one planned boundary".to_owned(),
            ));
        }
        if current_phase.is_some() {
            return Err(StorageError::InvalidEvent(
                "planned must be the first action boundary".to_owned(),
            ));
        }
        return Ok(());
    }
    if !has_plan {
        return Err(StorageError::InvalidEvent(
            "an action must be planned before its next boundary".to_owned(),
        ));
    }
    if matches!(
        current_phase,
        Some(
            "completed"
                | "failed"
                | "cancelled"
                | "interrupted"
                | "deferred"
                | "unresolved"
                | "removal_completed"
        )
    ) {
        return Err(StorageError::InvalidEvent(
            "a settled action cannot receive another boundary".to_owned(),
        ));
    }
    match phase {
        "started" if current_phase == Some("planned") => Ok(()),
        "progress" if matches!(current_phase, Some("started" | "progress")) => Ok(()),
        "transfer_verified" if matches!(current_phase, Some("started" | "progress")) => Ok(()),
        "proof_boundary" if matches!(current_phase, Some("transfer_verified")) => Ok(()),
        "removal_started" if current_phase == Some("proof_boundary") => Ok(()),
        "removal_completed" if current_phase == Some("removal_started") => Ok(()),
        "recovery_resolved" if current_phase == Some("recovery_review") => Ok(()),
        "completed" | "failed" | "deferred" | "unresolved"
            if matches!(
                current_phase,
                Some(
                    "started"
                        | "progress"
                        | "transfer_verified"
                        | "proof_boundary"
                        | "removal_started",
                )
            ) =>
        {
            Ok(())
        }
        "cancelled" | "interrupted"
            if matches!(
                current_phase,
                Some(
                    "planned" | "started" | "progress",
                )
            ) =>
        {
            Ok(())
        }
        "recovery_review"
            if matches!(
                current_phase,
                Some(
                    "started"
                        | "progress"
                        | "transfer_verified"
                        | "proof_boundary"
                        | "removal_started",
                )
            ) =>
        {
            Ok(())
        }
        _ => Err(StorageError::InvalidEvent(format!(
            "{phase} cannot follow {current_phase:?}"
        ))),
    }
}

fn validate_action_order(
    transaction: &rusqlite::Transaction<'_>,
    run_id: RunId,
    action_id: ActionId,
    event: &JournalEvent,
) -> Result<(), StorageError> {
    // These boundaries only say that no mutation was started for the action.
    // They must remain recordable for the rest of the plan when an earlier
    // action enters Recovery Review and blocks further mutating work.
    if matches!(event, JournalEvent::Cancelled { .. } | JournalEvent::Interrupted { .. }) {
        return Ok(());
    }
    if !event_advances_action(event) {
        return Ok(());
    }

    let mut statement = transaction.prepare(
        "SELECT action_id,
                (SELECT phase FROM action_events earlier
                 WHERE earlier.run_id = events.run_id
                   AND earlier.action_id = events.action_id
                 ORDER BY earlier.sequence DESC LIMIT 1)
         FROM action_events events
         WHERE events.run_id = ?1 AND events.action_id < ?2
         GROUP BY events.action_id",
    )?;
    let prior_actions = statement
        .query_map(params![run_id.value(), action_id], |row| {
            Ok((row.get::<_, ActionId>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if let Some((prior_action_id, phase)) = prior_actions
        .into_iter()
        .find(|(_, phase)| !is_settled_phase(phase))
    {
        return Err(StorageError::InvalidEvent(format!(
            "action {action_id} cannot settle before prior action {prior_action_id} ({phase})"
        )));
    }
    Ok(())
}

fn validate_recovery_resolution(
    transaction: &rusqlite::Transaction<'_>,
    run_id: RunId,
    action_id: ActionId,
    event: &JournalEvent,
) -> Result<(), StorageError> {
    let JournalEvent::RecoveryResolved {
        resolution: RecoveryResolution::Completed { evidence },
        ..
    } = event
    else {
        return Ok(());
    };

    let review_observed_at: Option<i64> = transaction
        .query_row(
            "SELECT recovery_observed_at_unix_nanos
             FROM action_events
             WHERE run_id = ?1 AND action_id = ?2 AND phase = 'recovery_review'
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.value(), action_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(review_observed_at) = review_observed_at else {
        return Err(StorageError::InvalidEvent(
            "completed recovery resolution requires a persisted Recovery Review".to_owned(),
        ));
    };
    if evidence.observed_at_unix_nanos <= review_observed_at {
        return Err(StorageError::InvalidEvent(
            "completed recovery resolution requires newer filesystem inspection evidence"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_removal_result_against_proof(
    transaction: &rusqlite::Transaction<'_>,
    run_id: RunId,
    action_id: ActionId,
    event: &JournalEvent,
) -> Result<(), StorageError> {
    let JournalEvent::RemovalCompleted { result, .. } = event else {
        return Ok(());
    };
    let proof: Option<(Option<i64>, Option<Vec<u8>>)> = transaction
        .query_row(
            "SELECT proof_destination_size, proof_destination_sha256
             FROM action_events
             WHERE run_id = ?1 AND action_id = ?2 AND phase = 'proof_boundary'
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.value(), action_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((proof_size, proof_sha256)) = proof else {
        return Err(StorageError::InvalidEvent(
            "removal result requires a persisted proof boundary".to_owned(),
        ));
    };
    let proof_size = proof_size
        .and_then(|size| u64::try_from(size).ok())
        .ok_or_else(|| StorageError::InvalidEvent("proof boundary has no destination size".to_owned()))?;
    let proof_sha256 = decode_hash(proof_sha256.as_deref())?.ok_or_else(|| {
        StorageError::InvalidEvent("proof boundary has no destination SHA-256".to_owned())
    })?;
    if result.evidence().destination_size() != Some(proof_size)
        || result.evidence().destination_sha256() != Some(&proof_sha256)
    {
        return Err(StorageError::InvalidEvent(
            "removal result does not match the persisted proof boundary".to_owned(),
        ));
    }
    Ok(())
}

fn validate_transfer_event_against_plan(
    transaction: &rusqlite::Transaction<'_>,
    run_id: RunId,
    action_id: ActionId,
    event: &JournalEvent,
) -> Result<(), StorageError> {
    let JournalEvent::TransferVerified { evidence, .. } = event else {
        return Ok(());
    };
    let planned: Option<(Option<i64>, Option<Vec<u8>>)> = transaction
        .query_row(
            "SELECT pre_size, pre_sha256
             FROM action_events
             WHERE run_id = ?1 AND action_id = ?2 AND phase = 'planned'",
            params![run_id.value(), action_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((size, sha256)) = planned else {
        return Err(StorageError::InvalidEvent(
            "verified transfer boundary requires a planned action".to_owned(),
        ));
    };
    let size = size
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| StorageError::InvalidEvent("planned action has no source size".to_owned()))?;
    let sha256 = decode_hash(sha256.as_deref())?.ok_or_else(|| {
        StorageError::InvalidEvent("planned action has no source SHA-256".to_owned())
    })?;
    if evidence.source_size() != Some(size) || evidence.source_sha256() != Some(&sha256) {
        return Err(StorageError::InvalidEvent(
            "verified transfer boundary does not match the planned source".to_owned(),
        ));
    }
    Ok(())
}

fn event_advances_action(event: &JournalEvent) -> bool {
    !matches!(event, JournalEvent::Planned { .. })
}

fn is_settled_phase(phase: &str) -> bool {
    matches!(
        phase,
        "completed"
            | "failed"
            | "cancelled"
            | "interrupted"
            | "deferred"
            | "unresolved"
            | "removal_completed"
            | "recovery_resolved"
    )
}

fn report_status(
    items: &[RunReportItem],
    review_cleared: bool,
    blocked: bool,
    reconciliation: Option<&CompletionReconciliation>,
    inventory_recorded: bool,
) -> RunReportStatus {
    if blocked {
        return RunReportStatus::Blocked;
    }
    if items.iter().any(|item| matches!(item.outcome(), ActionOutcome::InProgress))
        || (items.is_empty() && inventory_recorded && reconciliation.is_none())
    {
        return RunReportStatus::InProgress;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::RecoveryReview(_)))
    {
        return RunReportStatus::RecoveryReview;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Failed(_)))
    {
        return RunReportStatus::Failed;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Interrupted))
    {
        return RunReportStatus::Interrupted;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Cancelled))
    {
        return RunReportStatus::Cancelled;
    }
    if items.iter().any(|item| {
        matches!(
            item.outcome(),
            ActionOutcome::Deferred | ActionOutcome::Unresolved(_)
        )
    }) || reconciliation.is_some_and(CompletionReconciliation::requires_review)
        || (inventory_recorded && reconciliation.is_none())
    {
        return RunReportStatus::CompletedWithReviewRequired;
    }
    if review_cleared {
        RunReportStatus::ReviewCleared
    } else {
        RunReportStatus::Completed
    }
}

fn execution_result(
    items: &[RunReportItem],
    blocked: bool,
    reconciliation_recorded: bool,
) -> RunExecutionResult {
    if blocked {
        return RunExecutionResult::Blocked;
    }
    if items.is_empty() && !reconciliation_recorded {
        return RunExecutionResult::NotStarted;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::InProgress))
    {
        return RunExecutionResult::InProgress;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::RecoveryReview(_)))
    {
        return RunExecutionResult::RecoveryReview;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Failed(_)))
    {
        return RunExecutionResult::Failed;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Interrupted))
    {
        return RunExecutionResult::Interrupted;
    }
    if items
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Cancelled))
    {
        return RunExecutionResult::Cancelled;
    }
    RunExecutionResult::Succeeded
}

#[cfg(test)]
fn event_phase(event: &JournalEvent) -> &'static str {
    match event {
        JournalEvent::Planned { .. } => "planned",
        JournalEvent::Started { .. } => "started",
        JournalEvent::Progress { .. } => "progress",
        JournalEvent::TransferVerified { .. } => "transfer_verified",
        JournalEvent::ProofBoundary { .. } => "proof_boundary",
        JournalEvent::RemovalStarted { .. } => "removal_started",
        JournalEvent::RemovalCompleted { .. } => "removal_completed",
        JournalEvent::Completed { .. } => "completed",
        JournalEvent::Failed { .. } => "failed",
        JournalEvent::Cancelled { .. } => "cancelled",
        JournalEvent::Interrupted { .. } => "interrupted",
        JournalEvent::Deferred { .. } => "deferred",
        JournalEvent::Unresolved { .. } => "unresolved",
        JournalEvent::RecoveryReview { .. } => "recovery_review",
        JournalEvent::RecoveryResolved { .. } => "recovery_resolved",
    }
}

fn event_action_id(event: &JournalEvent) -> ActionId {
    match event {
        JournalEvent::Planned { action } => action.action_id,
        JournalEvent::Started { action_id }
        | JournalEvent::Progress { action_id, .. }
        | JournalEvent::TransferVerified { action_id, .. }
        | JournalEvent::ProofBoundary { action_id, .. }
        | JournalEvent::RemovalStarted { action_id, .. }
        | JournalEvent::RemovalCompleted { action_id, .. }
        | JournalEvent::Completed { action_id }
        | JournalEvent::Failed { action_id, .. }
        | JournalEvent::Cancelled { action_id }
        | JournalEvent::Interrupted { action_id }
        | JournalEvent::Deferred { action_id }
        | JournalEvent::Unresolved { action_id, .. }
        | JournalEvent::RecoveryReview { action_id, .. }
        | JournalEvent::RecoveryResolved { action_id, .. } => *action_id,
    }
}

fn encode_mode(mode: SyncMode) -> &'static str {
    match mode {
        SyncMode::OneWay => "one_way",
    }
}

fn encode_source(source: OneWaySource) -> &'static str {
    match source {
        OneWaySource::PeerA => "peer_a",
        OneWaySource::PeerB => "peer_b",
    }
}

fn decode_source(source: &str) -> Result<OneWaySource, StorageError> {
    match source {
        "peer_a" => Ok(OneWaySource::PeerA),
        "peer_b" => Ok(OneWaySource::PeerB),
        value => Err(StorageError::CorruptEvidence(format!("unknown source {value}"))),
    }
}

fn encode_deletion_method(method: DeletionMethod) -> &'static str {
    match method {
        DeletionMethod::Trash => "trash",
        DeletionMethod::PermanentRemoval => "permanent_removal",
    }
}

fn encode_partial_transfer_policy(policy: PartialTransferPolicy) -> &'static str {
    match policy {
        PartialTransferPolicy::Cleanup => "cleanup",
        PartialTransferPolicy::KeepPartialForResume => "keep_partial_for_resume",
    }
}

fn decode_partial_transfer_policy(value: &str) -> Result<PartialTransferPolicy, StorageError> {
    match value {
        "cleanup" => Ok(PartialTransferPolicy::Cleanup),
        "keep_partial_for_resume" => Ok(PartialTransferPolicy::KeepPartialForResume),
        _ => Err(StorageError::CorruptEvidence(format!(
            "unsupported partial transfer policy {value}"
        ))),
    }
}

fn decode_deletion_method(method: &str) -> Result<DeletionMethod, StorageError> {
    match method {
        "trash" => Ok(DeletionMethod::Trash),
        "permanent_removal" => Ok(DeletionMethod::PermanentRemoval),
        value => Err(StorageError::CorruptEvidence(format!(
            "unknown deletion method {value}"
        ))),
    }
}

fn encode_operation(operation: PlanActionKind) -> &'static str {
    match operation {
        PlanActionKind::CopyToDestination => "copy_to_destination",
        PlanActionKind::OverwriteDestination => "overwrite_destination",
        PlanActionKind::RemoveDestination => "remove_destination",
        PlanActionKind::RemoveSourceAfterVerification => "remove_source_after_verification",
    }
}

fn decode_operation(operation: &str) -> Result<PlanActionKind, StorageError> {
    match operation {
        "copy_to_destination" => Ok(PlanActionKind::CopyToDestination),
        "overwrite_destination" => Ok(PlanActionKind::OverwriteDestination),
        "remove_destination" => Ok(PlanActionKind::RemoveDestination),
        "remove_source_after_verification" => Ok(PlanActionKind::RemoveSourceAfterVerification),
        value => Err(StorageError::CorruptEvidence(format!("unknown operation {value}"))),
    }
}

fn encode_side(side: PeerSide) -> &'static str {
    match side {
        PeerSide::PeerA => "peer_a",
        PeerSide::PeerB => "peer_b",
    }
}

fn decode_side(side: &str) -> Result<PeerSide, StorageError> {
    match side {
        "peer_a" => Ok(PeerSide::PeerA),
        "peer_b" => Ok(PeerSide::PeerB),
        value => Err(StorageError::CorruptEvidence(format!("unknown peer side {value}"))),
    }
}

fn encode_item_type(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::RegularFile => "regular_file",
        ItemType::Directory => "directory",
        ItemType::Symlink => "symlink",
        ItemType::Unsupported => "unsupported",
    }
}

fn decode_item_type(item_type: &str) -> Result<ItemType, StorageError> {
    match item_type {
        "regular_file" => Ok(ItemType::RegularFile),
        "directory" => Ok(ItemType::Directory),
        "symlink" => Ok(ItemType::Symlink),
        "unsupported" => Ok(ItemType::Unsupported),
        value => Err(StorageError::CorruptEvidence(format!("unknown item type {value}"))),
    }
}

fn encode_analysis_outcome(outcome: AnalysisOutcome) -> &'static str {
    match outcome {
        AnalysisOutcome::Included => "included",
        AnalysisOutcome::Excluded => "excluded",
        AnalysisOutcome::Unsupported => "unsupported",
    }
}

fn decode_analysis_outcome(outcome: &str) -> Result<AnalysisOutcome, StorageError> {
    match outcome {
        "included" => Ok(AnalysisOutcome::Included),
        "excluded" => Ok(AnalysisOutcome::Excluded),
        "unsupported" => Ok(AnalysisOutcome::Unsupported),
        value => Err(StorageError::CorruptEvidence(format!(
            "unknown analysis outcome {value}"
        ))),
    }
}

fn encode_source_drain_status(status: SourceDrainStatus) -> &'static str {
    match status {
        SourceDrainStatus::NotApplicable => "not_applicable",
        SourceDrainStatus::Drained => "drained",
        SourceDrainStatus::NotEmpty => "not_empty",
    }
}

fn decode_source_drain_status(status: &str) -> Result<SourceDrainStatus, StorageError> {
    match status {
        "not_applicable" => Ok(SourceDrainStatus::NotApplicable),
        "drained" => Ok(SourceDrainStatus::Drained),
        "not_empty" => Ok(SourceDrainStatus::NotEmpty),
        value => Err(StorageError::CorruptEvidence(format!(
            "unknown Source Drain status {value}"
        ))),
    }
}

fn encode_finding_kind(kind: ReconciliationFindingKind) -> &'static str {
    match kind {
        ReconciliationFindingKind::Unexplained => "unexplained",
        ReconciliationFindingKind::Excluded => "excluded",
        ReconciliationFindingKind::NewlyAppeared => "newly_appeared",
        ReconciliationFindingKind::Changed => "changed",
        ReconciliationFindingKind::Failed => "failed",
        ReconciliationFindingKind::Unavailable => "unavailable",
        ReconciliationFindingKind::Unverifiable => "unverifiable",
    }
}

fn decode_finding_kind(kind: &str) -> Result<ReconciliationFindingKind, StorageError> {
    match kind {
        "unexplained" => Ok(ReconciliationFindingKind::Unexplained),
        "excluded" => Ok(ReconciliationFindingKind::Excluded),
        "newly_appeared" => Ok(ReconciliationFindingKind::NewlyAppeared),
        "changed" => Ok(ReconciliationFindingKind::Changed),
        "failed" => Ok(ReconciliationFindingKind::Failed),
        "unavailable" => Ok(ReconciliationFindingKind::Unavailable),
        "unverifiable" => Ok(ReconciliationFindingKind::Unverifiable),
        value => Err(StorageError::CorruptEvidence(format!(
            "unknown reconciliation finding kind {value}"
        ))),
    }
}

fn encode_reconciliation_reason(reason: &ReconciliationReason) -> (&'static str, Option<&'static str>) {
    match reason {
        ReconciliationReason::Unexplained => ("unexplained", None),
        ReconciliationReason::Excluded => ("excluded", None),
        ReconciliationReason::NewlyAppeared => ("newly_appeared", None),
        ReconciliationReason::Changed => ("changed", None),
        ReconciliationReason::Failed(action_reason) => ("failed", Some(encode_reason(*action_reason))),
        ReconciliationReason::Unavailable => ("unavailable", None),
        ReconciliationReason::Unverifiable => ("unverifiable", None),
    }
}

fn decode_reconciliation_reason(
    reason: &str,
    action_reason: Option<&str>,
) -> Result<ReconciliationReason, StorageError> {
    match reason {
        "unexplained" => Ok(ReconciliationReason::Unexplained),
        "excluded" => Ok(ReconciliationReason::Excluded),
        "newly_appeared" => Ok(ReconciliationReason::NewlyAppeared),
        "changed" => Ok(ReconciliationReason::Changed),
        "failed" => Ok(ReconciliationReason::Failed(decode_reason(
            action_reason.ok_or_else(|| {
                StorageError::CorruptEvidence(
                    "failed reconciliation finding has no action reason".to_owned(),
                )
            })?,
        )?)),
        "unavailable" => Ok(ReconciliationReason::Unavailable),
        "unverifiable" => Ok(ReconciliationReason::Unverifiable),
        value => Err(StorageError::CorruptEvidence(format!(
            "unknown reconciliation reason {value}"
        ))),
    }
}

fn encode_reason(reason: ActionReason) -> &'static str {
    match reason {
        ActionReason::TransferFailed => "transfer_failed",
        ActionReason::VerificationMismatch => "verification_mismatch",
        ActionReason::SourceChanged => "source_changed",
        ActionReason::PermissionDenied => "permission_denied",
        ActionReason::CancellationRequested => "cancellation_requested",
        ActionReason::DeferredForReview => "deferred_for_review",
        ActionReason::FilesystemUncertain => "filesystem_uncertain",
        ActionReason::InterruptedBoundary => "interrupted_boundary",
        ActionReason::DestinationUnavailable => "destination_unavailable",
    }
}

fn encode_resolution(resolution: &RecoveryResolution) -> &'static str {
    match resolution {
        RecoveryResolution::Completed { .. } => "completed",
        RecoveryResolution::Unresolved(ActionReason::TransferFailed) => "unresolved:transfer_failed",
        RecoveryResolution::Unresolved(ActionReason::VerificationMismatch) => {
            "unresolved:verification_mismatch"
        }
        RecoveryResolution::Unresolved(ActionReason::SourceChanged) => "unresolved:source_changed",
        RecoveryResolution::Unresolved(ActionReason::PermissionDenied) => {
            "unresolved:permission_denied"
        }
        RecoveryResolution::Unresolved(ActionReason::CancellationRequested) => {
            "unresolved:cancellation_requested"
        }
        RecoveryResolution::Unresolved(ActionReason::DeferredForReview) => {
            "unresolved:deferred_for_review"
        }
        RecoveryResolution::Unresolved(ActionReason::FilesystemUncertain) => {
            "unresolved:filesystem_uncertain"
        }
        RecoveryResolution::Unresolved(ActionReason::InterruptedBoundary) => {
            "unresolved:interrupted_boundary"
        }
        RecoveryResolution::Unresolved(ActionReason::DestinationUnavailable) => {
            "unresolved:destination_unavailable"
        }
    }
}

fn decode_resolution(
    resolution: &str,
    row: &StoredEvent,
) -> Result<RecoveryResolution, StorageError> {
    if resolution == "completed" {
        return Ok(RecoveryResolution::Completed {
            evidence: decode_recovery_evidence(row)?,
        });
    }
    let reason = resolution.strip_prefix("unresolved:").ok_or_else(|| {
        StorageError::CorruptEvidence(format!("unknown recovery resolution {resolution}"))
    })?;
    Ok(RecoveryResolution::Unresolved(decode_reason(reason)?))
}

fn decode_reason(reason: &str) -> Result<ActionReason, StorageError> {
    match reason {
        "transfer_failed" => Ok(ActionReason::TransferFailed),
        "verification_mismatch" => Ok(ActionReason::VerificationMismatch),
        "source_changed" => Ok(ActionReason::SourceChanged),
        "permission_denied" => Ok(ActionReason::PermissionDenied),
        "cancellation_requested" => Ok(ActionReason::CancellationRequested),
        "deferred_for_review" => Ok(ActionReason::DeferredForReview),
        "filesystem_uncertain" => Ok(ActionReason::FilesystemUncertain),
        "interrupted_boundary" => Ok(ActionReason::InterruptedBoundary),
        "destination_unavailable" => Ok(ActionReason::DestinationUnavailable),
        value => Err(StorageError::CorruptEvidence(format!("unknown action reason {value}"))),
    }
}

fn bool_to_int(value: bool) -> i64 {
    i64::from(value)
}

fn path_to_blob(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

fn blob_to_path(bytes: &[u8]) -> Result<PathBuf, StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes.to_vec())
            .map(PathBuf::from)
            .map_err(|_| StorageError::CorruptEvidence("stored path is not valid text".to_owned()))
    }
}
