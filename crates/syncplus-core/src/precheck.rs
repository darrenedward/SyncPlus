use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use unicode_normalization::UnicodeNormalization;

use crate::{
    Peer, PeerScope, PeerScopeLock, PeerScopeLockRegistry, ProcessSpecError, ProcessSpecification,
    ScopeLockConflict, ScopeLockOwner, SyncProfile, ValidatedSyncOptions,
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

    fn required_space(
        &self,
        source: &Path,
        options: ValidatedSyncOptions,
    ) -> Result<u64, PrecheckError>;

    fn naming_conflicts(
        &self,
        source: &Path,
        destination: &Path,
        exclusions: &[String],
    ) -> Result<Vec<NamingConflict>, PrecheckError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecheckBlockerKind {
    SourceUnreadable,
    DestinationNotWritable,
    RequiredPermission,
    InsufficientSpace,
    PeerScopeOverlap,
    DestinationNamingConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecheckBlocker {
    kind: PrecheckBlockerKind,
    path: PathBuf,
    requirement: String,
    remediation: String,
}

impl PrecheckBlocker {
    fn new(
        kind: PrecheckBlockerKind,
        path: impl Into<PathBuf>,
        requirement: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            requirement: requirement.into(),
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

    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecheckBlocked {
    blockers: Vec<PrecheckBlocker>,
}

impl PrecheckBlocked {
    pub fn blockers(&self) -> &[PrecheckBlocker] {
        &self.blockers
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamingRule {
    CaseInsensitiveCollision,
    UnicodeNormalizationCollision,
    ReservedName,
    InvalidCharacter,
    ComponentTooLong,
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
    blockers: Vec<PrecheckBlocker>,
    warnings: Vec<PathRiskWarning>,
}

impl PrecheckResult {
    fn new(source: &Path, destination: &Path) -> Self {
        Self {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
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

    pub fn blockers(&self) -> &[PrecheckBlocker] {
        &self.blockers
    }

    pub fn warnings(&self) -> &[PathRiskWarning] {
        &self.warnings
    }

    pub fn can_execute(&self) -> bool {
        self.blockers.is_empty()
    }

    pub fn execution_permit(&self) -> Result<ExecutionPermit, PrecheckBlocked> {
        if self.can_execute() {
            Ok(ExecutionPermit {
                source: self.source.clone(),
                destination: self.destination.clone(),
            })
        } else {
            Err(PrecheckBlocked {
                blockers: self.blockers.clone(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPermit {
    source: PathBuf,
    destination: PathBuf,
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
                write!(formatter, "precheck blocked by {} issue(s)", blocked.blockers.len())
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
        &self.permit
    }
}

pub struct RunPrecheck;

impl RunPrecheck {
    pub fn check<P: PrecheckProbe>(
        profile: &SyncProfile,
        probe: &P,
    ) -> Result<PrecheckResult, PrecheckErrorKind> {
        let specification =
            ProcessSpecification::from_profile(profile).map_err(PrecheckErrorKind::InvalidSpecification)?;
        let (source_peer, destination_peer) = selected_peers(profile);
        let source = source_peer.root();
        let destination = destination_peer.root();
        let mut result = PrecheckResult::new(source, destination);

        let source_scope = PeerScope::new(source);
        let destination_scope = PeerScope::new(destination);
        if source_scope.overlaps(&destination_scope) {
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
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::SourceUnreadable,
                source,
                "the selected source must be readable",
                "grant the current user read and directory-traverse access, then run the precheck again",
            ));
        }

        let destination_access = probe
            .destination_access(destination)
            .map_err(PrecheckErrorKind::Probe)?;
        if !destination_access.writable() {
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::DestinationNotWritable,
                destination,
                "the selected destination must be writable",
                "grant the current user write and directory-traverse access, then run the precheck again",
            ));
        }

        let options = specification.options();
        if options.safe_delete() && !source_access.removable() {
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::RequiredPermission,
                source,
                "Safe Delete requires permission to remove verified source items",
                "grant removal access on the source's containing directory or choose a different approved source",
            ));
        }
        if options.destination_cleanup() && !destination_access.removable() {
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::RequiredPermission,
                destination,
                "Destination Cleanup requires permission to remove destination items",
                "grant removal access on the destination's containing directory or disable Destination Cleanup",
            ));
        }

        let required = probe
            .required_space(source, options)
            .map_err(PrecheckErrorKind::Probe)?;
        let available = probe
            .available_space(destination)
            .map_err(PrecheckErrorKind::Probe)?;
        if available < required {
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::InsufficientSpace,
                destination,
                format!("the destination needs at least {required} bytes of available space"),
                format!("free space on the destination and retry; the precheck found only {available} bytes available"),
            ));
        }

        let naming_conflicts = probe
            .naming_conflicts(source, destination, profile.exclusions())
            .map_err(PrecheckErrorKind::Probe)?;
        for conflict in naming_conflicts {
            let related = conflict
                .related_path()
                .map(|path| format!("; it conflicts with {path:?}"))
                .unwrap_or_default();
            result.blockers.push(PrecheckBlocker::new(
                PrecheckBlockerKind::DestinationNamingConflict,
                conflict.source_path(),
                format!(
                    "destination naming rule {:?} cannot represent {:?} safely{}",
                    conflict.rule(),
                    conflict.destination_path(),
                    related
                ),
                "rename or exclude the conflicting item, or choose a destination with compatible naming rules",
            ));
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
        let result = Self::check(profile, probe).map_err(|error| match error {
            PrecheckErrorKind::InvalidSpecification(error) => {
                PrecheckFailure::InvalidSpecification(error)
            }
            PrecheckErrorKind::Probe(error) => PrecheckFailure::Probe(error),
        })?;
        let permit = result
            .execution_permit()
            .map_err(PrecheckFailure::Blocked)?;
        let lock = registry
            .acquire(
                owner,
                [PeerScope::new(result.source()), PeerScope::new(result.destination())],
            )
            .map_err(|error| match error {
                crate::ScopeLockError::Conflict(conflict) => PrecheckFailure::ScopeLocked(conflict),
                crate::ScopeLockError::EmptyScopes => unreachable!("precheck always supplies both scopes"),
            })?;
        Ok(PrecheckLease {
            result,
            permit,
            _scope_lock: lock,
        })
    }
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

    fn required_space(
        &self,
        source: &Path,
        _options: ValidatedSyncOptions,
    ) -> Result<u64, PrecheckError> {
        directory_size(source)
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
    case_insensitive: bool,
    unicode_normalization: bool,
    max_component_bytes: Option<usize>,
    reserved_names: Vec<String>,
    invalid_characters: Vec<char>,
}

impl Default for DestinationNamingPolicy {
    fn default() -> Self {
        Self {
            case_insensitive: false,
            unicode_normalization: false,
            max_component_bytes: None,
            reserved_names: Vec::new(),
            invalid_characters: Vec::new(),
        }
    }
}

impl DestinationNamingPolicy {
    pub fn case_insensitive() -> Self {
        Self {
            case_insensitive: true,
            ..Self::default()
        }
    }

    pub fn with_unicode_normalization(mut self, enabled: bool) -> Self {
        self.unicode_normalization = enabled;
        self
    }

    pub fn with_max_component_bytes(mut self, maximum: usize) -> Self {
        self.max_component_bytes = Some(maximum);
        self
    }

    pub fn with_reserved_name(mut self, name: impl Into<String>) -> Self {
        self.reserved_names.push(name.into());
        self
    }

    pub fn with_invalid_character(mut self, character: char) -> Self {
        self.invalid_characters.push(character);
        self
    }

    fn find_conflicts(
        &self,
        source: &Path,
        destination: &Path,
        exclusions: &[String],
    ) -> Result<Vec<NamingConflict>, PrecheckError> {
        let source_entries = collect_entries(source, exclusions)?;
        let destination_entries = if destination.exists() {
            collect_entries(destination, &[])?
        } else {
            Vec::new()
        };
        let mut conflicts = Vec::new();
        let mut source_keys: BTreeMap<String, (PathBuf, PathBuf)> = BTreeMap::new();

        for relative in &source_entries {
            if let Some(conflict) = self.validate_relative(relative, destination.join(relative)) {
                conflicts.push(conflict);
            }
            let key = self.key(relative);
            if let Some((existing_relative, existing_destination)) = source_keys.get(&key) {
                let rule = if self.unicode_normalization
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
            let key = self.key(&relative);
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

    fn validate_relative(&self, relative: &Path, destination: PathBuf) -> Option<NamingConflict> {
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
            if self
                .reserved_names
                .iter()
                .any(|reserved| self.key_component(reserved) == self.key_component(&name))
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
    let target = if path.exists() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };
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

fn directory_size(path: &Path) -> Result<u64, PrecheckError> {
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
        size = size.saturating_add(directory_size(&entry.path())?);
    }
    Ok(size)
}

fn available_space(path: &Path) -> Result<u64, PrecheckError> {
    let target = if path.exists() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };
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
