use std::{
    fmt,
    path::Path,
    path::PathBuf,
    time::Duration,
};

use crate::{ProcessSpecError, ProcessSpecification, ValidatedSyncOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RunId(u64);

impl RunId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileSnapshotId(u64);

impl ProfileSnapshotId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    name: String,
    root: PathBuf,
}

impl Peer {
    pub fn new(name: impl Into<String>, root: PathBuf) -> Self {
        Self {
            name: name.into(),
            root,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    OneWay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneWaySource {
    PeerA,
    PeerB,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionMethod {
    Trash,
    PermanentRemoval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialTransferPolicy {
    Cleanup,
    KeepPartialForResume,
}

impl Default for PartialTransferPolicy {
    fn default() -> Self {
        Self::Cleanup
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u8,
    initial_delay: Duration,
}

impl RetryPolicy {
    pub const fn new(max_attempts: u8, initial_delay: Duration) -> Self {
        Self {
            max_attempts,
            initial_delay,
        }
    }

    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }

    pub const fn initial_delay(self) -> Duration {
        self.initial_delay
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new(3, Duration::from_millis(100))
    }
}

/// Metadata that a transfer must preserve and verify before it can enter a
/// Safe Delete proof boundary. The default is the essential V1 contract;
/// timestamps are opt-in because they require an explicit preservation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataRequirements {
    file_type: bool,
    executable_permissions: bool,
    symlink_targets: bool,
    timestamps: bool,
}

impl MetadataRequirements {
    pub const fn new(
        file_type: bool,
        executable_permissions: bool,
        symlink_targets: bool,
        timestamps: bool,
    ) -> Self {
        Self {
            file_type,
            executable_permissions,
            symlink_targets,
            timestamps,
        }
    }

    pub const fn file_type(self) -> bool {
        self.file_type
    }

    pub const fn executable_permissions(self) -> bool {
        self.executable_permissions
    }

    pub const fn symlink_targets(self) -> bool {
        self.symlink_targets
    }

    pub const fn timestamps(self) -> bool {
        self.timestamps
    }
}

impl Default for MetadataRequirements {
    fn default() -> Self {
        Self::new(true, true, true, false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOptions {
    pub safe_delete: bool,
    pub destination_cleanup: bool,
    pub deletion_method: Option<DeletionMethod>,
    pub metadata: MetadataRequirements,
    pub partial_transfer_policy: PartialTransferPolicy,
    pub retry_policy: RetryPolicy,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            safe_delete: false,
            destination_cleanup: false,
            deletion_method: None,
            metadata: MetadataRequirements::default(),
            partial_transfer_policy: PartialTransferPolicy::Cleanup,
            retry_policy: RetryPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthorizationSnapshot {
    allow_unattended_destructive: bool,
    allow_unattended_permanent_removal: bool,
}

impl AuthorizationSnapshot {
    pub const fn new(
        allow_unattended_destructive: bool,
        allow_unattended_permanent_removal: bool,
    ) -> Self {
        Self {
            allow_unattended_destructive,
            allow_unattended_permanent_removal,
        }
    }

    pub const fn allow_unattended_destructive(self) -> bool {
        self.allow_unattended_destructive
    }

    pub const fn allow_unattended_permanent_removal(self) -> bool {
        self.allow_unattended_permanent_removal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncProfile {
    name: String,
    peer_a: Peer,
    peer_b: Peer,
    mode: SyncMode,
    source: OneWaySource,
    options: SyncOptions,
    exclusions: Vec<String>,
}

impl SyncProfile {
    pub fn new(name: impl Into<String>, peer_a: Peer, peer_b: Peer) -> Self {
        Self {
            name: name.into(),
            peer_a,
            peer_b,
            mode: SyncMode::OneWay,
            source: OneWaySource::PeerA,
            options: SyncOptions::default(),
            exclusions: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn peer_a(&self) -> &Peer {
        &self.peer_a
    }

    pub fn peer_b(&self) -> &Peer {
        &self.peer_b
    }

    pub const fn mode(&self) -> SyncMode {
        self.mode
    }

    pub const fn source(&self) -> OneWaySource {
        self.source
    }

    pub const fn options(&self) -> SyncOptions {
        self.options
    }

    pub const fn with_source(mut self, source: OneWaySource) -> Self {
        self.source = source;
        self
    }

    pub const fn with_options(mut self, options: SyncOptions) -> Self {
        self.options = options;
        self
    }

    pub fn exclusions(&self) -> &[String] {
        &self.exclusions
    }

    pub fn with_exclusion(mut self, exclusion: impl Into<String>) -> Self {
        self.exclusions.push(exclusion.into());
        self
    }

    pub fn with_exclusions<I, S>(mut self, exclusions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclusions
            .extend(exclusions.into_iter().map(Into::into));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSnapshot {
    id: ProfileSnapshotId,
    profile: SyncProfile,
    validated_options: ValidatedSyncOptions,
    authorizations: AuthorizationSnapshot,
}

impl ProfileSnapshot {
    fn new_with_authorizations(
        id: ProfileSnapshotId,
        profile: &SyncProfile,
        authorizations: AuthorizationSnapshot,
    ) -> Result<Self, ProcessSpecError> {
        let validated_options = ProcessSpecification::from_profile(profile)?.options();
        Ok(Self {
            id,
            profile: profile.clone(),
            validated_options,
            authorizations,
        })
    }

    pub const fn id(&self) -> ProfileSnapshotId {
        self.id
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
pub enum ActiveRunState {
    IdleEdit,
    Prechecking,
    Analyzing,
    PlanReview,
    ExecutionConfirmation,
    Executing,
    CompletionReconciliation,
    ReviewResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    Completed,
    CompletedWithReviewRequired,
    Failed,
    Cancelled,
    Blocked,
    RecoveryReview,
    ReviewCleared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Active(ActiveRunState),
    PendingReview,
    Terminal(TerminalOutcome),
}

impl RunState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEvent {
    BeginPrecheck,
    PrecheckPassed,
    AnalysisCompleted,
    PlanReviewed,
    ExecutionConfirmed,
    ExecutionCompleted,
    ReconciliationCompleted { requires_review: bool },
    OpenReview,
    BeginResolutionRun,
    ReviewCleared,
    Blocked,
    Failed,
    Cancelled,
    RecoveryReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyViolation {
    PrecheckRequired,
    FreshAnalysisRequired,
    ExecutionConfirmationRequired,
    UnresolvedReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    InvalidTransition { state: RunState, event: RunEvent },
    SafetyViolation(SafetyViolation),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { state, event } => {
                write!(formatter, "invalid transition from {state:?} using {event:?}")
            }
            Self::SafetyViolation(violation) => write!(formatter, "safety violation: {violation:?}"),
        }
    }
}

impl std::error::Error for CoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRun {
    id: RunId,
    snapshot: ProfileSnapshot,
    state: RunState,
}

impl SyncRun {
    pub fn new(id: RunId, profile: &SyncProfile) -> Result<Self, ProcessSpecError> {
        Self::new_with_authorizations(id, profile, AuthorizationSnapshot::default())
    }

    pub fn new_with_authorizations(
        id: RunId,
        profile: &SyncProfile,
        authorizations: AuthorizationSnapshot,
    ) -> Result<Self, ProcessSpecError> {
        Ok(Self {
            id,
            snapshot: ProfileSnapshot::new_with_authorizations(
                ProfileSnapshotId::new(id.value()),
                profile,
                authorizations,
            )?,
            state: RunState::Active(ActiveRunState::IdleEdit),
        })
    }

    pub const fn id(&self) -> RunId {
        self.id
    }

    pub const fn snapshot_id(&self) -> ProfileSnapshotId {
        self.snapshot.id()
    }

    pub fn snapshot(&self) -> &ProfileSnapshot {
        &self.snapshot
    }

    pub const fn state(&self) -> RunState {
        self.state
    }

    pub const fn outcome(&self) -> Option<TerminalOutcome> {
        match self.state {
            RunState::PendingReview => Some(TerminalOutcome::CompletedWithReviewRequired),
            RunState::Terminal(outcome) => Some(outcome),
            RunState::Active(_) => None,
        }
    }

    pub fn transition(self, event: RunEvent) -> Result<Self, CoreError> {
        let next_state = next_state(self.state, event).ok_or(CoreError::InvalidTransition {
            state: self.state,
            event,
        })?;

        Ok(Self {
            state: next_state,
            ..self
        })
    }
}

fn next_state(state: RunState, event: RunEvent) -> Option<RunState> {
    if matches!(
        event,
        RunEvent::Blocked | RunEvent::Failed | RunEvent::Cancelled | RunEvent::RecoveryReview
    ) {
        return match state {
            RunState::Active(_) | RunState::PendingReview => Some(RunState::Terminal(match event {
                RunEvent::Blocked => TerminalOutcome::Blocked,
                RunEvent::Failed => TerminalOutcome::Failed,
                RunEvent::Cancelled => TerminalOutcome::Cancelled,
                RunEvent::RecoveryReview => TerminalOutcome::RecoveryReview,
                _ => unreachable!("the event was checked above"),
            })),
            RunState::Terminal(_) => None,
        };
    }

    match (state, event) {
        (RunState::Active(ActiveRunState::IdleEdit), RunEvent::BeginPrecheck) => {
            Some(RunState::Active(ActiveRunState::Prechecking))
        }
        (RunState::Active(ActiveRunState::Prechecking), RunEvent::PrecheckPassed) => {
            Some(RunState::Active(ActiveRunState::Analyzing))
        }
        (RunState::Active(ActiveRunState::Analyzing), RunEvent::AnalysisCompleted) => {
            Some(RunState::Active(ActiveRunState::PlanReview))
        }
        (RunState::Active(ActiveRunState::PlanReview), RunEvent::PlanReviewed) => {
            Some(RunState::Active(ActiveRunState::ExecutionConfirmation))
        }
        (
            RunState::Active(ActiveRunState::ExecutionConfirmation),
            RunEvent::ExecutionConfirmed,
        ) => Some(RunState::Active(ActiveRunState::Executing)),
        (RunState::Active(ActiveRunState::Executing), RunEvent::ExecutionCompleted) => {
            Some(RunState::Active(ActiveRunState::CompletionReconciliation))
        }
        (
            RunState::Active(ActiveRunState::CompletionReconciliation),
            RunEvent::ReconciliationCompleted {
                requires_review: false,
            },
        ) => Some(RunState::Terminal(TerminalOutcome::Completed)),
        (
            RunState::Active(ActiveRunState::CompletionReconciliation),
            RunEvent::ReconciliationCompleted {
                requires_review: true,
            },
        ) => Some(RunState::PendingReview),
        (RunState::PendingReview, RunEvent::OpenReview) => {
            Some(RunState::Active(ActiveRunState::ReviewResolution))
        }
        (RunState::Active(ActiveRunState::ReviewResolution), RunEvent::BeginResolutionRun) => {
            Some(RunState::Active(ActiveRunState::Analyzing))
        }
        (RunState::Active(ActiveRunState::ReviewResolution), RunEvent::ReviewCleared) => {
            Some(RunState::Terminal(TerminalOutcome::ReviewCleared))
        }
        _ => None,
    }
}
