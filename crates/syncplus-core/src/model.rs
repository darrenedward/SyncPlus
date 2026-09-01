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
    endpoint: PeerEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEndpoint {
    Local { root: PathBuf },
    Ssh(SshPeer),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuthentication {
    Key,
    Agent,
    InteractivePassword,
    SavedPassword(SavedSecretReference),
}

impl Default for SshAuthentication {
    fn default() -> Self {
        Self::Key
    }
}

/// A nonsecret identifier for a password stored in the desktop OS keyring.
/// The password itself is never part of a profile or run snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SavedSecretReference {
    id: String,
}

impl SavedSecretReference {
    const MAX_LENGTH: usize = 128;

    pub fn new(id: impl Into<String>) -> Result<Self, SecretReferenceError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SecretReferenceError::Empty);
        }
        if id.len() > Self::MAX_LENGTH {
            return Err(SecretReferenceError::TooLong);
        }
        if !id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
        {
            return Err(SecretReferenceError::Invalid);
        }
        Ok(Self { id })
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretReferenceError {
    Empty,
    Invalid,
    TooLong,
}

impl fmt::Display for SecretReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "saved secret reference must not be empty",
            Self::Invalid => "saved secret reference contains unsupported characters",
            Self::TooLong => "saved secret reference is too long",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SecretReferenceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPeer {
    server: String,
    username: String,
    port: u16,
    identity: Option<PathBuf>,
    authentication: SshAuthentication,
    remote_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshPeerError {
    EmptyServer,
    InvalidServer,
    EmptyUsername,
    InvalidUsername,
    InvalidPort,
    EmptyIdentity,
    NulInIdentity,
    MissingIdentityForKey,
    EmptyRemotePath,
    NulInRemotePath,
}

impl SshPeer {
    pub fn new(
        server: impl Into<String>,
        username: impl Into<String>,
        port: u16,
        identity: Option<PathBuf>,
        authentication: SshAuthentication,
        remote_path: impl Into<String>,
    ) -> Result<Self, SshPeerError> {
        let server = server.into();
        if server.is_empty() {
            return Err(SshPeerError::EmptyServer);
        }
        if !is_valid_ssh_server(&server) {
            return Err(SshPeerError::InvalidServer);
        }

        let username = username.into();
        if username.is_empty() {
            return Err(SshPeerError::EmptyUsername);
        }
        if !is_valid_ssh_username(&username) {
            return Err(SshPeerError::InvalidUsername);
        }

        if port == 0 {
            return Err(SshPeerError::InvalidPort);
        }

        if let Some(identity) = &identity {
            if identity.as_os_str().is_empty() {
                return Err(SshPeerError::EmptyIdentity);
            }
            if path_contains_nul(identity) {
                return Err(SshPeerError::NulInIdentity);
            }
        }

        if matches!(&authentication, SshAuthentication::Key) && identity.is_none() {
            return Err(SshPeerError::MissingIdentityForKey);
        }

        let remote_path = remote_path.into();
        if remote_path.is_empty() {
            return Err(SshPeerError::EmptyRemotePath);
        }
        if remote_path.contains('\0') {
            return Err(SshPeerError::NulInRemotePath);
        }

        Ok(Self {
            server,
            username,
            port,
            identity,
            authentication,
            remote_path: PathBuf::from(remote_path),
        })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn identity(&self) -> Option<&Path> {
        self.identity.as_deref()
    }

    pub fn authentication(&self) -> SshAuthentication {
        self.authentication.clone()
    }

    pub fn remote_path(&self) -> &Path {
        &self.remote_path
    }
}

impl Peer {
    pub fn new(name: impl Into<String>, root: PathBuf) -> Self {
        Self {
            name: name.into(),
            endpoint: PeerEndpoint::Local { root },
        }
    }

    pub fn ssh(
        name: impl Into<String>,
        server: impl Into<String>,
        username: impl Into<String>,
        port: u16,
        identity: Option<PathBuf>,
        authentication: SshAuthentication,
        remote_path: impl Into<String>,
    ) -> Result<Self, SshPeerError> {
        Ok(Self {
            name: name.into(),
            endpoint: PeerEndpoint::Ssh(SshPeer::new(
                server,
                username,
                port,
                identity,
                authentication,
                remote_path,
            )?),
        })
    }

    pub fn from_ssh(name: impl Into<String>, ssh: SshPeer) -> Self {
        Self {
            name: name.into(),
            endpoint: PeerEndpoint::Ssh(ssh),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn root(&self) -> &Path {
        match &self.endpoint {
            PeerEndpoint::Local { root } => root,
            PeerEndpoint::Ssh(ssh) => ssh.remote_path(),
        }
    }

    pub fn endpoint(&self) -> &PeerEndpoint {
        &self.endpoint
    }

    pub fn is_ssh(&self) -> bool {
        matches!(self.endpoint, PeerEndpoint::Ssh(_))
    }

    /// Compare endpoint identity without considering display names or
    /// credentials. Credentials select how an endpoint is accessed; they do
    /// not make the same local folder or remote location a different pair.
    pub fn same_endpoint(&self, other: &Self) -> bool {
        match (self.endpoint(), other.endpoint()) {
            (PeerEndpoint::Local { root: left }, PeerEndpoint::Local { root: right }) => {
                left == right
            }
            (PeerEndpoint::Ssh(left), PeerEndpoint::Ssh(right)) => {
                left.server() == right.server()
                    && left.username() == right.username()
                    && left.port() == right.port()
                    && left.remote_path() == right.remote_path()
            }
            _ => false,
        }
    }

    pub fn ssh_peer(&self) -> Option<&SshPeer> {
        match &self.endpoint {
            PeerEndpoint::Local { .. } => None,
            PeerEndpoint::Ssh(ssh) => Some(ssh),
        }
    }
}

impl fmt::Display for SshPeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyServer => "SSH server must not be empty",
            Self::InvalidServer => "SSH server contains unsupported characters",
            Self::EmptyUsername => "SSH username must not be empty",
            Self::InvalidUsername => "SSH username contains unsupported characters",
            Self::InvalidPort => "SSH port must be between 1 and 65535",
            Self::EmptyIdentity => "SSH identity path must not be empty",
            Self::NulInIdentity => "SSH identity path contains NUL",
            Self::MissingIdentityForKey => {
                "SSH key authentication requires a selected identity file"
            }
            Self::EmptyRemotePath => "SSH remote path must not be empty",
            Self::NulInRemotePath => "SSH remote path contains NUL",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SshPeerError {}

fn is_valid_ssh_server(server: &str) -> bool {
    if server.starts_with('[') || server.ends_with(']') {
        let Some(address) = server.strip_prefix('[').and_then(|value| value.strip_suffix(']'))
        else {
            return false;
        };
        return !address.is_empty()
            && address.chars().all(|character| {
                character.is_ascii_hexdigit()
                    || character.is_ascii_alphanumeric()
                    || matches!(character, ':' | '%' | '.' | '-')
            });
    }

    server.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
    })
}

fn is_valid_ssh_username(username: &str) -> bool {
    username.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
    })
}

#[cfg(unix)]
fn path_contains_nul(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().contains(&0)
}

#[cfg(not(unix))]
fn path_contains_nul(path: &Path) -> bool {
    path.to_string_lossy().contains('\0')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    OneWay,
    Mirror,
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
    specialist: SpecialistMetadataRequirements,
}

/// Optional metadata whose preservation is deliberately Advanced-only. These
/// are named capabilities rather than an escape hatch for arbitrary rsync
/// arguments. All are disabled by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpecialistMetadataRequirements {
    ownership: bool,
    access_control_lists: bool,
    extended_attributes: bool,
}

impl SpecialistMetadataRequirements {
    pub const fn new(ownership: bool, access_control_lists: bool, extended_attributes: bool) -> Self {
        Self { ownership, access_control_lists, extended_attributes }
    }

    pub const fn ownership(self) -> bool { self.ownership }
    pub const fn access_control_lists(self) -> bool { self.access_control_lists }
    pub const fn extended_attributes(self) -> bool { self.extended_attributes }
    pub const fn any(self) -> bool {
        self.ownership || self.access_control_lists || self.extended_attributes
    }
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
            specialist: SpecialistMetadataRequirements::new(false, false, false),
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

    pub const fn with_specialist_metadata(mut self, specialist: SpecialistMetadataRequirements) -> Self {
        self.specialist = specialist;
        self
    }

    pub const fn specialist_metadata(self) -> SpecialistMetadataRequirements { self.specialist }
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

    pub const fn with_mode(mut self, mode: SyncMode) -> Self {
        self.mode = mode;
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
    Interrupted,
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
    Interrupted,
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
        RunEvent::Blocked
            | RunEvent::Failed
            | RunEvent::Cancelled
            | RunEvent::Interrupted
            | RunEvent::RecoveryReview
    ) {
        return match state {
            RunState::Active(_) | RunState::PendingReview => Some(RunState::Terminal(match event {
                RunEvent::Blocked => TerminalOutcome::Blocked,
                RunEvent::Failed => TerminalOutcome::Failed,
                RunEvent::Cancelled => TerminalOutcome::Cancelled,
                RunEvent::Interrupted => TerminalOutcome::Interrupted,
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
