use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use unicode_normalization::UnicodeNormalization;

use crate::{
    DeletionMethod, Peer, PeerScope, PeerScopeLock, PeerScopeLockRegistry, ProcessSpecError,
    ProcessSpecification, ScopeLockConflict, ScopeLockOwner, SyncProfile, ValidatedSyncOptions,
    VolumeIdentity, VolumeIdentityError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessSnapshot {
    readable: bool,
    writable: bool,
    removable: bool,
}

impl AccessSnapshot {
    pub const fn new(readable: bool, writable: bool, removable: bool) -> Self {
        Self {
            readable,
            writable,
            removable,
        }
    }

    pub const fn readable(self) -> bool {
        self.readable
    }

    pub const fn writable(self) -> bool {
        self.writable
    }

    pub const fn removable(self) -> bool {
        self.removable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecheckError {
    path: PathBuf,
    operation: String,
    detail: String,
}

impl PrecheckError {
    pub fn new(path: impl Into<PathBuf>, operation: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            operation: operation.into(),
            detail: detail.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for PrecheckError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} for {:?}: {}", self.operation, self.path, self.detail)
    }
}

impl std::error::Error for PrecheckError {}

/// Read-only probes used by the precheck. Implementations must never create,
/// alter, remove, or rename user files.
pub trait PrecheckProbe {
    fn source_access(&self, path: &Path) -> Result<AccessSnapshot, PrecheckError>;

    fn destination_access(&self, path: &Path) -> Result<AccessSnapshot, PrecheckError>;

    fn available_space(&self, path: &Path) -> Result<u64, PrecheckError>;

    /// Whether a peer root is available for this run. A destination may be
    /// absent when its parent is available and writable, because the transfer
    /// workflow can create it without changing the source.
    fn peer_available(&self, _path: &Path, _destination: bool) -> Result<bool, PrecheckError> {
        Ok(true)
    }

    /// Detect both lexical scope overlap and aliases known to the local
    /// filesystem. Implementations must not mutate either peer.
    fn scopes_overlap(&self, source: &Path, destination: &Path) -> Result<bool, PrecheckError> {
        Ok(PeerScope::new(source).overlaps(&PeerScope::new(destination)))
    }

    fn required_space(
        &self,
        source: &Path,
        destination: &Path,
        options: ValidatedSyncOptions,
        exclusions: &[String],
    ) -> Result<u64, PrecheckError>;

    /// Return the stable local volume identity for a peer when the operating
    /// system provides one. Implementations must not follow a symlink at the
    /// selected peer root or mutate the filesystem.
    fn volume_identity(&self, path: &Path) -> Result<Option<VolumeIdentity>, PrecheckError>;

    /// Whether resuming a run with no recorded volume identity is unsafe for
    /// this peer implementation.
    fn requires_volume_identity(&self) -> bool;

    fn item_permission_issues(
        &self,
        _source: &Path,
        _destination: &Path,
        _exclusions: &[String],
        _options: ValidatedSyncOptions,
    ) -> Result<Vec<PermissionIssue>, PrecheckError> {
        Ok(Vec::new())
    }

    fn naming_conflicts(
        &self,
        source: &Path,
        destination: &Path,
        exclusions: &[String],
    ) -> Result<Vec<NamingConflict>, PrecheckError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecheckBlockerKind {
    PeerUnavailable,
    SourceUnreadable,
    DestinationNotWritable,
    RequiredPermission,
    InsufficientSpace,
    PeerScopeOverlap,
    DestinationNamingConflict,
    VolumeIdentityMismatch,
    VolumeIdentityUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecheckBlocker {
    kind: PrecheckBlockerKind,
    path: PathBuf,
    requirement: String,
    reason: String,
    remediation: String,
}

impl PrecheckBlocker {
    fn new(
        kind: PrecheckBlockerKind,
        path: impl Into<PathBuf>,
        requirement: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let requirement = requirement.into();
        Self {
            kind,
            path: path.into(),
            reason: requirement.clone(),
            requirement,
            remediation: remediation.into(),
        }
    }

    fn with_reason(
        kind: PrecheckBlockerKind,
        path: impl Into<PathBuf>,
        requirement: impl Into<String>,
        reason: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            requirement: requirement.into(),
            reason: reason.into(),
            remediation: remediation.into(),
        }
    }

    pub const fn kind(&self) -> PrecheckBlockerKind {
        self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn requirement(&self) -> &str {
        &self.requirement
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecheckBlocked {
    blockers: Vec<PrecheckBlocker>,
    source_volume_identity: Option<VolumeIdentity>,
    destination_volume_identity: Option<VolumeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionIssue {
    path: PathBuf,
    requirement: String,
    reason: String,
    remediation: String,
}

impl PermissionIssue {
    pub fn new(
        path: impl Into<PathBuf>,
        requirement: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let requirement = requirement.into();
        Self {
            path: path.into(),
            reason: requirement.clone(),
            requirement,
            remediation: remediation.into(),
        }
    }

    pub fn with_reason(
        path: impl Into<PathBuf>,
        requirement: impl Into<String>,
        reason: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            requirement: requirement.into(),
            reason: reason.into(),
            remediation: remediation.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn requirement(&self) -> &str {
        &self.requirement
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

impl PrecheckBlocked {
    pub fn blockers(&self) -> &[PrecheckBlocker] {
        &self.blockers
    }

    pub const fn source_volume_identity(&self) -> Option<VolumeIdentity> {
        self.source_volume_identity
    }

    pub const fn destination_volume_identity(&self) -> Option<VolumeIdentity> {
        self.destination_volume_identity
    }

    pub fn is_replacement_only(&self) -> bool {
        self.source_volume_identity.is_some()
            && self.destination_volume_identity.is_some()
            && !self.blockers.is_empty()
            && self
                .blockers
                .iter()
                .all(|blocker| blocker.kind == PrecheckBlockerKind::VolumeIdentityMismatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRiskLevel {
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRiskWarning {
    source: PathBuf,
    level: PathRiskLevel,
    explanation: String,
}

impl PathRiskWarning {
    fn high(source: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            level: PathRiskLevel::High,
            explanation: String::from(
                "Safe Delete will drain the selected source after each item is independently verified; confirm that this broad or system-sensitive path is intentional",
            ),
        }
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub const fn level(&self) -> PathRiskLevel {
        self.level
    }

    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    pub const fn requires_stronger_confirmation(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamingRule {
    CaseInsensitiveCollision,
    UnicodeNormalizationCollision,
    ReservedName,
    InvalidCharacter,
    ComponentTooLong,
    PathTooLong,
    TrailingDotOrSpace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamingConflict {
    source_path: PathBuf,
    destination_path: PathBuf,
    related_path: Option<PathBuf>,
    rule: NamingRule,
}

impl NamingConflict {
    pub fn new(
        source_path: impl Into<PathBuf>,
        destination_path: impl Into<PathBuf>,
        related_path: Option<PathBuf>,
        rule: NamingRule,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            destination_path: destination_path.into(),
            related_path,
            rule,
        }
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn destination_path(&self) -> &Path {
        &self.destination_path
    }

    pub fn related_path(&self) -> Option<&Path> {
        self.related_path.as_deref()
    }

    pub const fn rule(&self) -> NamingRule {
        self.rule
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecheckResult {
    source: PathBuf,
    destination: PathBuf,
    source_volume_identity: Option<VolumeIdentity>,
    destination_volume_identity: Option<VolumeIdentity>,
    blockers: Vec<PrecheckBlocker>,
    warnings: Vec<PathRiskWarning>,
}

impl PrecheckResult {
    fn new(source: &Path, destination: &Path) -> Self {
        Self {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            source_volume_identity: None,
            destination_volume_identity: None,
            blockers: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    pub const fn source_volume_identity(&self) -> Option<VolumeIdentity> {
        self.source_volume_identity
    }

    pub const fn destination_volume_identity(&self) -> Option<VolumeIdentity> {
        self.destination_volume_identity
    }

    pub fn blockers(&self) -> &[PrecheckBlocker] {
        &self.blockers
    }

    pub fn warnings(&self) -> &[PathRiskWarning] {
        &self.warnings
    }

    pub fn requires_stronger_confirmation(&self) -> bool {
        self.warnings
            .iter()
            .any(PathRiskWarning::requires_stronger_confirmation)
    }

    pub fn is_confirmation_sufficient(&self, stronger_confirmation: bool) -> bool {
        self.can_execute()
            && (!self.requires_stronger_confirmation() || stronger_confirmation)
    }

    pub fn can_execute(&self) -> bool {
        self.blockers.is_empty()
    }

    pub fn require_passed(&self) -> Result<(), PrecheckBlocked> {
        if self.can_execute() {
            Ok(())
        } else {
            Err(PrecheckBlocked {
                blockers: self.blockers.clone(),
                source_volume_identity: self.source_volume_identity,
                destination_volume_identity: self.destination_volume_identity,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPermit {
    source: PathBuf,
    destination: PathBuf,
    lock_token: u64,
}

impl ExecutionPermit {
    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecheckErrorKind {
    InvalidSpecification(ProcessSpecError),
    Probe(PrecheckError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecheckFailure {
    InvalidSpecification(ProcessSpecError),
    Probe(PrecheckError),
    Blocked(PrecheckBlocked),
    ScopeLocked(ScopeLockConflict),
}

impl std::fmt::Display for PrecheckFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSpecification(error) => write!(formatter, "invalid profile: {error}"),
            Self::Probe(error) => write!(formatter, "precheck probe failed: {error}"),
            Self::Blocked(blocked) => {
                write!(formatter, "precheck blocked: ")?;
                for (index, blocker) in blocked.blockers.iter().enumerate() {
                    if index > 0 {
                        write!(formatter, "; ")?;
                    }
                    write!(
                        formatter,
                        "{:?} at {:?}: {} — {} ({})",
                        blocker.kind,
                        blocker.path,
                        blocker.requirement,
                        blocker.reason,
                        blocker.remediation
                    )?;
                }
                Ok(())
            }
            Self::ScopeLocked(conflict) => write!(
                formatter,
                "scope {:?} overlaps active scope {:?}: {}",
                conflict.requested().path(),
                conflict.held().path(),
                conflict.remediation()
            ),
        }
    }
}

impl std::error::Error for PrecheckFailure {}

#[derive(Debug)]
pub struct PrecheckLease {
    result: PrecheckResult,
    permit: ExecutionPermit,
    _scope_lock: PeerScopeLock,
}

impl PrecheckLease {
    pub fn result(&self) -> &PrecheckResult {
        &self.result
    }

    pub fn permit(&self) -> &ExecutionPermit {
        debug_assert_eq!(self._scope_lock.token(), self.permit.lock_token);
        &self.permit
    }
}

pub struct RunPrecheck;

impl RunPrecheck {
    pub fn check<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
    ) -> Result<PrecheckResult, PrecheckErrorKind> {
        Self::check_with_expected_volumes(profile, probe, None, None)
    }

    pub fn check_with_expected_volumes<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
    ) -> Result<PrecheckResult, PrecheckErrorKind> {
        Self::check_with_volume_expectations(
            profile,
            probe,
            expected_source,
            expected_destination,
            false,
            false,
        )
    }

    pub fn check_for_resume<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
    ) -> Result<PrecheckResult, PrecheckErrorKind> {
        Self::check_for_resume_with_replacement(
            profile,
            probe,
            expected_source,
            expected_destination,
            false,
        )
    }

    pub fn check_for_resume_with_replacement<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
        allow_replacement: bool,
    ) -> Result<PrecheckResult, PrecheckErrorKind> {
        Self::check_with_volume_expectations(
            profile,
            probe,
            expected_source,
            expected_destination,
            true,
            allow_replacement,
        )
    }

    fn check_with_volume_expectations<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
        require_recorded_identity: bool,
        allow_replacement: bool,
    ) -> Result<PrecheckResult, PrecheckErrorKind> {
        let specification =
            ProcessSpecification::from_profile(profile).map_err(PrecheckErrorKind::InvalidSpecification)?;
        let (source_peer, destination_peer) = selected_peers(profile);
        let source = source_peer.root();
        let destination = destination_peer.root();
        let mut result = PrecheckResult::new(source, destination);

        result.source_volume_identity = probe
            .volume_identity(source)
            .map_err(PrecheckErrorKind::Probe)?;
        result.destination_volume_identity = probe
            .volume_identity(destination)
            .map_err(PrecheckErrorKind::Probe)?;

        let source_volume_identity = result.source_volume_identity;
        let destination_volume_identity = result.destination_volume_identity;
        append_volume_identity_blocker(
            &mut result,
            source,
            "source",
            expected_source,
            source_volume_identity,
            allow_replacement,
        );
        append_volume_identity_blocker(
            &mut result,
            destination,
            "destination",
            expected_destination,
            destination_volume_identity,
            allow_replacement,
        );

        if require_recorded_identity && probe.requires_volume_identity() {
            append_missing_recorded_identity_blocker(
                &mut result,
                source,
                "source",
                expected_source,
                source_volume_identity,
            );
            append_missing_recorded_identity_blocker(
                &mut result,
                destination,
                "destination",
                expected_destination,
                destination_volume_identity,
            );
        }

        if (expected_source.is_some() && source_volume_identity.is_none())
            || (expected_destination.is_some() && destination_volume_identity.is_none())
        {
            return Ok(result);
        }

        let source_available = probe
            .peer_available(source, false)
            .map_err(PrecheckErrorKind::Probe)?;
        if !source_available {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::PeerUnavailable,
                source,
                "the source peer must be available and be a directory",
                "the selected source path is missing, unavailable, or not a directory",
                "connect or mount the source peer and select an available directory, then run the precheck again",
            ));
        }

        let destination_available = probe
            .peer_available(destination, true)
            .map_err(PrecheckErrorKind::Probe)?;
        if !destination_available {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::PeerUnavailable,
                destination,
                "the destination peer must be available or have an available parent directory",
                "the destination path and its parent are unavailable",
                "connect or mount the destination peer and choose an available directory, then run the precheck again",
            ));
        }
        if !source_available || !destination_available {
            return Ok(result);
        }

        let source_scope = PeerScope::new(source);
        let destination_scope = PeerScope::new(destination);
        if probe
            .scopes_overlap(source, destination)
            .map_err(PrecheckErrorKind::Probe)?
        {
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::PeerScopeOverlap,
                source,
                "the source and destination scopes must be distinct and non-overlapping",
                format!(
                    "choose separate source and destination paths; {:?} overlaps {:?}",
                    source_scope.path(),
                    destination_scope.path()
                ),
            ));
            return Ok(result);
        }

        let source_access = probe
            .source_access(source)
            .map_err(PrecheckErrorKind::Probe)?;
        if !source_access.readable() {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::SourceUnreadable,
                source,
                "the selected source must be readable",
                "the source root could not be read with the current user's effective access",
                "grant the current user read and directory-traverse access, then run the precheck again",
            ));
        }

        let destination_access = probe
            .destination_access(destination)
            .map_err(PrecheckErrorKind::Probe)?;
        if !destination_access.writable() {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::DestinationNotWritable,
                destination,
                "the selected destination must be writable",
                "the destination root or its creation parent is not writable with the current user's effective access",
                "grant the current user write and directory-traverse access, then run the precheck again",
            ));
        }

        let options = specification.options();
        if options.safe_delete() && !source_access.removable() {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::RequiredPermission,
                source,
                "Safe Delete requires permission to remove verified source items",
                "the current user cannot remove an item from the source scope",
                "grant removal access on the source's containing directory or choose a different approved source",
            ));
        }
        if options.destination_cleanup() && !destination_access.removable() {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::RequiredPermission,
                destination,
                "Destination Cleanup requires permission to remove destination items",
                "the current user cannot remove an item from the destination scope",
                "grant removal access on the destination's containing directory or disable Destination Cleanup",
            ));
        }

        let required = probe
            .required_space(source, destination, options, profile.exclusions())
            .map_err(PrecheckErrorKind::Probe)?;
        let available = probe
            .available_space(destination)
            .map_err(PrecheckErrorKind::Probe)?;
        if available < required {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::InsufficientSpace,
                destination,
                format!("the destination needs at least {required} bytes of available space"),
                format!("the destination has only {available} bytes available"),
                format!("free space on the destination and retry; the precheck found only {available} bytes available"),
            ));
        }

        let permission_issues = probe
            .item_permission_issues(source, destination, profile.exclusions(), options)
            .map_err(PrecheckErrorKind::Probe)?;
        for issue in &permission_issues {
            result.blockers.push(PrecheckBlocker::with_reason(
                PrecheckBlockerKind::RequiredPermission,
                issue.path(),
                issue.requirement(),
                issue.reason(),
                issue.remediation(),
            ));
        }

        if source_access.readable()
            && destination_access.readable()
            && permission_issues.is_empty()
        {
            let naming_conflicts = probe
                .naming_conflicts(source, destination, profile.exclusions())
                .map_err(PrecheckErrorKind::Probe)?;
            for conflict in naming_conflicts {
                let related = conflict
                    .related_path()
                    .map(|path| format!("; it conflicts with {path:?}"))
                    .unwrap_or_default();
                result.blockers.push(PrecheckBlocker::with_reason(
                    PrecheckBlockerKind::DestinationNamingConflict,
                    conflict.source_path(),
                    format!(
                        "destination naming rule {:?} cannot represent {:?} safely{}",
                        conflict.rule(),
                        conflict.destination_path(),
                        related
                    ),
                    format!(
                        "the destination filesystem rejected or would collide with the source item's name under {:?}",
                        conflict.rule()
                    ),
                    "rename or exclude the conflicting item, or choose a destination with compatible naming rules",
                ));
            }
        }

        if options.safe_delete() {
            if let Some(warning) = path_risk_warning(source) {
                result.warnings.push(warning);
            }
        }

        Ok(result)
    }

    pub fn check_and_lock<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        registry: &PeerScopeLockRegistry,
        owner: ScopeLockOwner,
    ) -> Result<PrecheckLease, PrecheckFailure> {
        Self::check_and_lock_with_expected_volumes(profile, probe, registry, owner, None, None)
    }

    pub fn check_and_lock_with_expected_volumes<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        registry: &PeerScopeLockRegistry,
        owner: ScopeLockOwner,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
    ) -> Result<PrecheckLease, PrecheckFailure> {
        Self::check_and_lock_with_volume_expectations(
            profile,
            probe,
            registry,
            owner,
            expected_source,
            expected_destination,
            false,
            false,
        )
    }

    pub fn check_and_lock_for_resume<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        registry: &PeerScopeLockRegistry,
        owner: ScopeLockOwner,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
    ) -> Result<PrecheckLease, PrecheckFailure> {
        Self::check_and_lock_for_resume_with_replacement(
            profile,
            probe,
            registry,
            owner,
            expected_source,
            expected_destination,
            false,
        )
    }

    pub fn check_and_lock_for_resume_with_replacement<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        registry: &PeerScopeLockRegistry,
        owner: ScopeLockOwner,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
        allow_replacement: bool,
    ) -> Result<PrecheckLease, PrecheckFailure> {
        Self::check_and_lock_with_volume_expectations(
            profile,
            probe,
            registry,
            owner,
            expected_source,
            expected_destination,
            true,
            allow_replacement,
        )
    }

    fn check_and_lock_with_volume_expectations<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
        registry: &PeerScopeLockRegistry,
        owner: ScopeLockOwner,
        expected_source: Option<VolumeIdentity>,
        expected_destination: Option<VolumeIdentity>,
        require_recorded_identity: bool,
        allow_replacement: bool,
    ) -> Result<PrecheckLease, PrecheckFailure> {
        let result = if require_recorded_identity {
            Self::check_for_resume_with_replacement(
                profile,
                probe,
                expected_source,
                expected_destination,
                allow_replacement,
            )
        } else {
            Self::check_with_expected_volumes(
                profile,
                probe,
                expected_source,
                expected_destination,
            )
        }
        .map_err(|error| match error {
            PrecheckErrorKind::InvalidSpecification(error) => {
                PrecheckFailure::InvalidSpecification(error)
            }
            PrecheckErrorKind::Probe(error) => PrecheckFailure::Probe(error),
        })?;
        result.require_passed().map_err(PrecheckFailure::Blocked)?;
        let lock = registry
            .acquire(
                owner,
                [PeerScope::new(result.source()), PeerScope::new(result.destination())],
            )
            .map_err(|error| match error {
                crate::ScopeLockError::Conflict(conflict) => PrecheckFailure::ScopeLocked(conflict),
                crate::ScopeLockError::EmptyScopes => unreachable!("precheck always supplies both scopes"),
            })?;
        let permit = ExecutionPermit {
            source: result.source.clone(),
            destination: result.destination.clone(),
            lock_token: lock.token(),
        };
        Ok(PrecheckLease {
            result,
            permit,
            _scope_lock: lock,
        })
    }
}

fn append_volume_identity_blocker(
    result: &mut PrecheckResult,
    path: &Path,
    peer_label: &str,
    expected: Option<VolumeIdentity>,
    observed: Option<VolumeIdentity>,
    allow_replacement: bool,
) {
    let Some(expected) = expected else {
        return;
    };
    if observed == Some(expected) || (allow_replacement && observed.is_some()) {
        return;
    }
    let observed_text = observed
        .map(|identity| identity.to_string())
        .unwrap_or_else(|| "no volume identity was detected".to_owned());
    result.blockers.push(PrecheckBlocker::new(
        PrecheckBlockerKind::VolumeIdentityMismatch,
        path,
        format!(
            "the {peer_label} must be on {expected}; the current peer reports {observed_text}"
        ),
        "reconnect the recorded volume or explicitly review the replacement before resuming",
    ));
}

fn append_missing_recorded_identity_blocker(
    result: &mut PrecheckResult,
    path: &Path,
    peer_label: &str,
    expected: Option<VolumeIdentity>,
    observed: Option<VolumeIdentity>,
) {
    if expected.is_some() {
        return;
    }
    let observed_text = observed
        .map(|identity| identity.to_string())
        .unwrap_or_else(|| "no volume identity was detected".to_owned());
    result.blockers.push(PrecheckBlocker::new(
        PrecheckBlockerKind::VolumeIdentityUnavailable,
        path,
        format!(
            "no recorded volume identity is available for the {peer_label}; the current peer reports {observed_text}"
        ),
        "start a new Sync Run after the peer is available so its volume identity can be recorded",
    ));
}

fn selected_peers(profile: &SyncProfile) -> (&Peer, &Peer) {
    match profile.source() {
        crate::OneWaySource::PeerA => (profile.peer_a(), profile.peer_b()),
        crate::OneWaySource::PeerB => (profile.peer_b(), profile.peer_a()),
    }
}

fn path_risk_warning(source: &Path) -> Option<PathRiskWarning> {
    let normalized = PeerScope::new(source);
    let sensitive = [
        "/",
        "/home",
        "/root",
        "/etc",
        "/usr",
        "/var",
        "/boot",
        "/bin",
        "/sbin",
        "/lib",
        "/dev",
        "/proc",
        "/sys",
    ];
    sensitive
        .iter()
        .map(|path| PeerScope::new(path))
        .any(|scope| normalized.path() == scope.path())
        .then(|| PathRiskWarning::high(normalized.path()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPrecheckProbe {
    naming_policy: DestinationNamingPolicy,
}

impl LocalPrecheckProbe {
    pub fn new(naming_policy: DestinationNamingPolicy) -> Self {
        Self { naming_policy }
    }
}

impl Default for LocalPrecheckProbe {
    fn default() -> Self {
        Self::new(DestinationNamingPolicy::default())
    }
}

impl PrecheckProbe for LocalPrecheckProbe {
    fn source_access(&self, path: &Path) -> Result<AccessSnapshot, PrecheckError> {
        Ok(local_access(path, false))
    }

    fn destination_access(&self, path: &Path) -> Result<AccessSnapshot, PrecheckError> {
        Ok(local_access(path, true))
    }

    fn available_space(&self, path: &Path) -> Result<u64, PrecheckError> {
        available_space(path)
    }

    fn peer_available(&self, path: &Path, destination: bool) -> Result<bool, PrecheckError> {
        Ok(if path.exists() {
            path.is_dir()
        } else {
            destination && path.parent().is_some_and(Path::is_dir)
        })
    }

    fn scopes_overlap(&self, source: &Path, destination: &Path) -> Result<bool, PrecheckError> {
        let source_scope = canonical_scope(source)?;
        let destination_scope = canonical_scope(destination)?;
        Ok(PeerScope::new(source_scope).overlaps(&PeerScope::new(destination_scope)))
    }

    fn required_space(
        &self,
        source: &Path,
        destination: &Path,
        options: ValidatedSyncOptions,
        exclusions: &[String],
    ) -> Result<u64, PrecheckError> {
        let transfer_bytes = directory_size(source, exclusions).unwrap_or_default();
        if options.deletion_method() == Some(DeletionMethod::Trash)
            && !same_filesystem(source, destination)
        {
            Ok(transfer_bytes.saturating_mul(2))
        } else {
            Ok(transfer_bytes)
        }
    }

    fn volume_identity(&self, path: &Path) -> Result<Option<VolumeIdentity>, PrecheckError> {
        match VolumeIdentity::capture(path) {
            Ok(identity) => Ok(Some(identity)),
            Err(VolumeIdentityError::Unavailable(_)) => Ok(None),
            Err(error) => Err(PrecheckError::new(
                path,
                "inspect local volume identity",
                error.to_string(),
            )),
        }
    }

    fn requires_volume_identity(&self) -> bool {
        true
    }

    fn item_permission_issues(
        &self,
        source: &Path,
        destination: &Path,
        exclusions: &[String],
        options: ValidatedSyncOptions,
    ) -> Result<Vec<PermissionIssue>, PrecheckError> {
        let mut issues = Vec::new();
        let source_entries = if local_access(source, false).readable() {
            match collect_entries(source, exclusions) {
                Ok(entries) => entries,
                Err(error) => {
                    issues.push(PermissionIssue::with_reason(
                        error.path(),
                        "each included source item must be readable",
                        error.detail(),
                        "grant the current user read access to this item and retry the precheck",
                    ));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        for relative in source_entries {
            let path = source.join(&relative);
            let access = local_access(&path, false);
            if !access.readable() {
                issues.push(PermissionIssue::with_reason(
                    &path,
                    "each included source item must be readable",
                    "the source item cannot be opened with the current user's effective access",
                    "grant the current user read access to this item and retry the precheck",
                ));
            }
            if options.safe_delete() && !access.removable() {
                issues.push(PermissionIssue::with_reason(
                    &path,
                    "Safe Delete requires removal access for each included source item",
                    "the source item's containing directory does not allow removal with the current user's effective access",
                    "grant removal access on the item's containing directory or exclude the item",
                ));
            }
        }
        if destination.exists() {
            let destination_entries = match collect_entries(destination, &[]) {
                Ok(entries) => entries,
                Err(error) => {
                    issues.push(PermissionIssue::with_reason(
                        error.path(),
                        "destination items that may be inspected or replaced must be readable",
                        error.detail(),
                        "grant the current user read access to this destination item or resolve the conflict explicitly",
                    ));
                    Vec::new()
                }
            };
            for relative in destination_entries {
                let path = destination.join(&relative);
                let access = local_access(&path, true);
                if !access.writable() {
                    issues.push(PermissionIssue::with_reason(
                        &path,
                        "destination items that may be replaced must be writable",
                        "the existing destination item cannot be changed with the current user's effective access",
                        "grant the current user write access to this destination item or remove the conflict explicitly",
                    ));
                }
                if options.destination_cleanup() && !access.removable() {
                    issues.push(PermissionIssue::with_reason(
                        &path,
                        "Destination Cleanup requires removal access for each destination item",
                        "the destination item cannot be removed with the current user's effective access",
                        "grant removal access on the item's containing directory or disable Destination Cleanup",
                    ));
                }
            }
        }
        Ok(issues)
    }

    fn naming_conflicts(
        &self,
        source: &Path,
        destination: &Path,
        exclusions: &[String],
    ) -> Result<Vec<NamingConflict>, PrecheckError> {
        self.naming_policy
            .find_conflicts(source, destination, exclusions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationNamingPolicy {
    auto_detect: bool,
    case_insensitive: bool,
    unicode_normalization: bool,
    max_component_bytes: Option<usize>,
    max_path_bytes: Option<usize>,
    reserved_names: Vec<String>,
    invalid_characters: Vec<char>,
    reject_control_characters: bool,
    reject_trailing_dot_or_space: bool,
}

impl Default for DestinationNamingPolicy {
    fn default() -> Self {
        Self {
            auto_detect: true,
            case_insensitive: false,
            unicode_normalization: false,
            max_component_bytes: None,
            max_path_bytes: None,
            reserved_names: Vec::new(),
            invalid_characters: Vec::new(),
            reject_control_characters: false,
            reject_trailing_dot_or_space: false,
        }
    }
}

impl DestinationNamingPolicy {
    pub fn case_insensitive() -> Self {
        Self {
            auto_detect: false,
            case_insensitive: true,
            ..Self::default()
        }
    }

    pub fn windows_compatible() -> Self {
        Self {
            auto_detect: false,
            case_insensitive: true,
            unicode_normalization: true,
            max_component_bytes: Some(255),
            max_path_bytes: Some(260),
            reserved_names: windows_reserved_names().into_iter().map(String::from).collect(),
            invalid_characters: ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
                .into_iter()
                .collect(),
            reject_control_characters: true,
            reject_trailing_dot_or_space: true,
        }
    }

    pub fn with_unicode_normalization(mut self, enabled: bool) -> Self {
        self.auto_detect = false;
        self.unicode_normalization = enabled;
        self
    }

    pub fn with_max_component_bytes(mut self, maximum: usize) -> Self {
        self.auto_detect = false;
        self.max_component_bytes = Some(maximum);
        self
    }

    pub fn with_max_path_bytes(mut self, maximum: usize) -> Self {
        self.auto_detect = false;
        self.max_path_bytes = Some(maximum);
        self
    }

    pub fn with_reserved_name(mut self, name: impl Into<String>) -> Self {
        self.auto_detect = false;
        self.reserved_names.push(name.into());
        self
    }

    pub fn with_invalid_character(mut self, character: char) -> Self {
        self.auto_detect = false;
        self.invalid_characters.push(character);
        self
    }

    fn find_conflicts(
        &self,
        source: &Path,
        destination: &Path,
        exclusions: &[String],
    ) -> Result<Vec<NamingConflict>, PrecheckError> {
        let policy = if self.auto_detect {
            self.detect_for_destination(destination)
        } else {
            self.clone()
        };
        let source_entries = collect_entries(source, exclusions)?;
        let destination_entries = if destination.exists() {
            collect_entries(destination, &[])?
        } else {
            Vec::new()
        };
        let mut conflicts = Vec::new();
        let mut source_keys: BTreeMap<String, (PathBuf, PathBuf)> = BTreeMap::new();

        for relative in &source_entries {
            if let Some(conflict) = policy.validate_relative(relative, destination.join(relative)) {
                conflicts.push(conflict);
            }
            let key = policy.key(relative);
            if let Some((existing_relative, existing_destination)) = source_keys.get(&key) {
                let rule = if policy.unicode_normalization
                    && normalize_text(&relative.to_string_lossy(), false, true)
                        == normalize_text(&existing_relative.to_string_lossy(), false, true)
                {
                    NamingRule::UnicodeNormalizationCollision
                } else {
                    NamingRule::CaseInsensitiveCollision
                };
                conflicts.push(NamingConflict::new(
                    relative,
                    destination.join(relative),
                    Some(existing_destination.clone()),
                    rule,
                ));
            } else {
                source_keys.insert(key, (relative.clone(), destination.join(relative)));
            }
        }

        for relative in destination_entries {
            let key = policy.key(&relative);
            if let Some((source_relative, expected_destination)) = source_keys.get(&key) {
                if relative != *source_relative {
                    conflicts.push(NamingConflict::new(
                        source_relative,
                        expected_destination,
                        Some(destination.join(relative)),
                        NamingRule::CaseInsensitiveCollision,
                    ));
                }
            }
        }

        Ok(conflicts)
    }

    fn detect_for_destination(&self, destination: &Path) -> Self {
        let mut policy = self.clone();
        policy.auto_detect = false;
        policy.max_component_bytes.get_or_insert(255);
        policy.max_path_bytes.get_or_insert(if cfg!(windows) { 260 } else { 4096 });
        policy.unicode_normalization = cfg!(target_os = "macos");

        #[cfg(unix)]
        if restricted_filesystem(destination) {
            policy = Self::windows_compatible();
        }

        #[cfg(windows)]
        {
            policy = Self::windows_compatible();
        }

        policy
    }

    fn validate_relative(&self, relative: &Path, destination: PathBuf) -> Option<NamingConflict> {
        if self
            .max_path_bytes
            .is_some_and(|maximum| path_byte_length(&destination) > maximum)
        {
            return Some(NamingConflict::new(
                relative,
                destination,
                None,
                NamingRule::PathTooLong,
            ));
        }
        for component in relative.components() {
            let name = component.as_os_str().to_string_lossy();
            if self
                .max_component_bytes
                .is_some_and(|maximum| name.len() > maximum)
            {
                return Some(NamingConflict::new(
                    relative,
                    destination,
                    None,
                    NamingRule::ComponentTooLong,
                ));
            }
            if self.invalid_characters.iter().any(|character| name.contains(*character)) {
                return Some(NamingConflict::new(
                    relative,
                    destination,
                    None,
                    NamingRule::InvalidCharacter,
                ));
            }
            if self.reject_control_characters && name.chars().any(char::is_control) {
                return Some(NamingConflict::new(
                    relative,
                    destination,
                    None,
                    NamingRule::InvalidCharacter,
                ));
            }
            if self.reject_trailing_dot_or_space && name.ends_with(['.', ' ']) {
                return Some(NamingConflict::new(
                    relative,
                    destination,
                    None,
                    NamingRule::TrailingDotOrSpace,
                ));
            }
            if self
                .reserved_names
                .iter()
                .any(|reserved| self.reserved_name_key(reserved) == self.reserved_name_key(&name))
            {
                return Some(NamingConflict::new(
                    relative,
                    destination,
                    None,
                    NamingRule::ReservedName,
                ));
            }
        }
        None
    }

    fn key(&self, path: &Path) -> String {
        path.components()
            .map(|component| self.key_component(&component.as_os_str().to_string_lossy()))
            .collect::<Vec<_>>()
            .join("/")
    }

    fn key_component(&self, value: &str) -> String {
        normalize_text(value, self.case_insensitive, self.unicode_normalization)
    }

    fn reserved_name_key(&self, value: &str) -> String {
        let base = value.trim_end_matches(['.', ' ']).split('.').next().unwrap_or_default();
        self.key_component(base)
    }
}

fn normalize_text(value: &str, case_insensitive: bool, unicode_normalization: bool) -> String {
    let normalized = if unicode_normalization {
        value.nfkc().collect::<String>()
    } else {
        value.to_owned()
    };
    if case_insensitive {
        normalized.to_lowercase()
    } else {
        normalized
    }
}

fn path_byte_length(path: &Path) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().len()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().len()
    }
}

fn windows_reserved_names() -> [&'static str; 22] {
    [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
        "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
        "LPT8", "LPT9",
    ]
}

fn collect_entries(root: &Path, exclusions: &[String]) -> Result<Vec<PathBuf>, PrecheckError> {
    let mut entries = Vec::new();
    collect_entries_recursive(root, Path::new(""), exclusions, &mut entries)?;
    Ok(entries)
}

fn collect_entries_recursive(
    root: &Path,
    relative: &Path,
    exclusions: &[String],
    entries: &mut Vec<PathBuf>,
) -> Result<(), PrecheckError> {
    let directory = if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    let read_dir = fs::read_dir(&directory).map_err(|error| {
        PrecheckError::new(&directory, "read directory", error.to_string())
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            PrecheckError::new(&directory, "read directory entry", error.to_string())
        })?;
        let child = if relative.as_os_str().is_empty() {
            PathBuf::from(entry.file_name())
        } else {
            relative.join(entry.file_name())
        };
        if is_excluded(&child, entry.file_type().map_err(|error| {
            PrecheckError::new(&child, "inspect directory entry", error.to_string())
        })?.is_dir(), exclusions) {
            continue;
        }
        entries.push(child.clone());
        if entry.file_type().map_err(|error| {
            PrecheckError::new(&child, "inspect directory entry", error.to_string())
        })?.is_dir() {
            collect_entries_recursive(root, &child, exclusions, entries)?;
        }
    }
    Ok(())
}

fn is_excluded(path: &Path, is_directory: bool, exclusions: &[String]) -> bool {
    let path = path.to_string_lossy();
    exclusions.iter().any(|pattern| {
        let directory_pattern = pattern.ends_with('/');
        let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
        if directory_pattern && !is_directory {
            return false;
        }
        wildcard_matches(pattern, &path)
            || path
                .split('/')
                .any(|component| wildcard_matches(pattern, component))
    })
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<_> = pattern.chars().collect();
    let value: Vec<_> = value.chars().collect();
    let mut table = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    table[0][0] = true;
    for (index, character) in pattern.iter().enumerate() {
        if *character == '*' {
            table[index + 1][0] = table[index][0];
        }
        for value_index in 0..value.len() {
            table[index + 1][value_index + 1] = if *character == '*' {
                table[index][value_index + 1] || table[index + 1][value_index]
            } else {
                table[index][value_index] && *character == value[value_index]
            };
        }
    }
    table[pattern.len()][value.len()]
}

fn local_access(path: &Path, destination: bool) -> AccessSnapshot {
    let target = probe_target(path);
    let readable = if path.is_dir() {
        fs::read_dir(path).is_ok()
    } else {
        File::open(path).is_ok()
    };
    let writable = has_access(&target, AccessMode::Write);
    let removable = path
        .parent()
        .is_some_and(|parent| has_access(parent, AccessMode::WriteExec));
    AccessSnapshot::new(
        readable,
        if destination { writable } else { false },
        removable,
    )
}

fn directory_size(path: &Path, exclusions: &[String]) -> Result<u64, PrecheckError> {
    directory_size_recursive(path, Path::new(""), exclusions)
}

fn directory_size_recursive(
    path: &Path,
    relative: &Path,
    exclusions: &[String],
) -> Result<u64, PrecheckError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| PrecheckError::new(path, "inspect source", error.to_string()))?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    let mut size = 0u64;
    for entry in fs::read_dir(path)
        .map_err(|error| PrecheckError::new(path, "read source", error.to_string()))?
    {
        let entry = entry.map_err(|error| PrecheckError::new(path, "read source", error.to_string()))?;
        let child_relative = if relative.as_os_str().is_empty() {
            PathBuf::from(entry.file_name())
        } else {
            relative.join(entry.file_name())
        };
        let file_type = entry
            .file_type()
            .map_err(|error| PrecheckError::new(&child_relative, "inspect source", error.to_string()))?;
        if is_excluded(&child_relative, file_type.is_dir(), exclusions) {
            continue;
        }
        size = size.saturating_add(directory_size_recursive(
            &entry.path(),
            &child_relative,
            exclusions,
        )?);
    }
    Ok(size)
}

fn same_filesystem(left: &Path, right: &Path) -> bool {
    matches!((device_id(left), device_id(right)), (Some(left), Some(right)) if left == right)
}

#[cfg(unix)]
fn filesystem_type(path: &Path) -> Option<i64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let target = probe_target(path);
    let path = CString::new(target.as_os_str().as_bytes()).ok()?;
    let mut statistics = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is a valid NUL-terminated path and `statistics` is
    // writable storage for the operating-system result.
    let result = unsafe { libc::statfs(path.as_ptr(), statistics.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: statfs initialized the structure after returning success.
    Some(unsafe { statistics.assume_init() }.f_type as i64)
}

#[cfg(unix)]
fn restricted_filesystem(path: &Path) -> bool {
    const EXFAT_MAGIC: i64 = 0x2011_bab0;
    const NTFS_MAGIC: i64 = 0x5346_544e;
    const MSDOS_MAGIC: i64 = 0x4d44;

    if matches!(filesystem_type(path), Some(EXFAT_MAGIC | NTFS_MAGIC | MSDOS_MAGIC)) {
        return true;
    }

    let target = probe_target(path);
    let Ok(mounts) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mounts.lines().any(|line| {
        let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
            return false;
        };
        let Some(mount_point) = mount_fields.split_whitespace().nth(4) else {
            return false;
        };
        let Some(filesystem) = filesystem_fields.split_whitespace().next() else {
            return false;
        };
        if !matches!(filesystem, "fuseblk" | "vfat" | "msdos" | "exfat" | "ntfs" | "ntfs3") {
            return false;
        }
        let mount_point = decode_mountinfo_path(mount_point);
        target == mount_point || target.starts_with(&mount_point)
    })
}

#[cfg(unix)]
fn decode_mountinfo_path(value: &str) -> PathBuf {
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escape: String = characters.by_ref().take(3).collect();
            match escape.as_str() {
                "040" => decoded.push(' '),
                "011" => decoded.push('\t'),
                "134" => decoded.push('\\'),
                _ => {
                    decoded.push('\\');
                    decoded.push_str(&escape);
                }
            }
        } else {
            decoded.push(character);
        }
    }
    PathBuf::from(decoded)
}

fn device_id(path: &Path) -> Option<u64> {
    let target = probe_target(path);
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let path = CString::new(target.as_os_str().as_bytes()).ok()?;
        let mut statistics = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `path` is a valid NUL-terminated path and `statistics` is
        // writable storage for the operating-system result.
        let result = unsafe { libc::stat(path.as_ptr(), statistics.as_mut_ptr()) };
        if result != 0 {
            return None;
        }
        // SAFETY: stat initialized the structure after returning success.
        Some(unsafe { statistics.assume_init() }.st_dev as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        None
    }
}

fn available_space(path: &Path) -> Result<u64, PrecheckError> {
    let target = probe_target(path);
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let bytes = target.as_os_str().as_bytes();
        let path = CString::new(bytes).map_err(|_| PrecheckError::new(target.clone(), "inspect filesystem space", "path contains NUL"))?;
        let mut statistics = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `path` is a valid NUL-terminated path and `statistics` points
        // to writable storage for the operating-system result.
        let result = unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) };
        if result != 0 {
            return Err(PrecheckError::new(
                target,
                "inspect filesystem space",
                io::Error::last_os_error().to_string(),
            ));
        }
        // SAFETY: statvfs initialized the structure after returning success.
        let statistics = unsafe { statistics.assume_init() };
        return Ok((statistics.f_bavail as u64).saturating_mul(statistics.f_frsize as u64));
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Err(PrecheckError::new(".", "inspect filesystem space", "filesystem space probing is unsupported"))
    }
}

#[derive(Clone, Copy)]
enum AccessMode {
    Write,
    WriteExec,
}

fn probe_target(path: &Path) -> PathBuf {
    if path.exists() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    }
}

fn canonical_scope(path: &Path) -> Result<PathBuf, PrecheckError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| PrecheckError::new(path, "resolve peer scope", error.to_string()))?
            .join(path)
    };
    let mut unresolved = Vec::new();
    let mut current = absolute.clone();
    loop {
        if current.exists() {
            let mut resolved = fs::canonicalize(&current).map_err(|error| {
                PrecheckError::new(&current, "resolve peer scope", error.to_string())
            })?;
            for component in unresolved.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        let Some(name) = current.file_name() else {
            return Err(PrecheckError::new(
                path,
                "resolve peer scope",
                "no existing ancestor is available",
            ));
        };
        unresolved.push(name.to_owned());
        current = current.parent().ok_or_else(|| {
            PrecheckError::new(path, "resolve peer scope", "no existing ancestor is available")
        })?.to_path_buf();
    }
}

fn has_access(path: &Path, mode: AccessMode) -> bool {
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let flags = match mode {
            AccessMode::Write => libc::W_OK,
            AccessMode::WriteExec => libc::W_OK | libc::X_OK,
        };
        // SAFETY: `path` is a valid NUL-terminated path and access performs no
        // filesystem mutation.
        unsafe { libc::access(path.as_ptr(), flags) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::metadata(path)
            .map(|metadata| !metadata.permissions().readonly())
            .unwrap_or(false)
    }
}
