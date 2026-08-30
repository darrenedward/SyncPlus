use std::{
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    DeletionMethod, OneWaySource, PeerSide, PlanAction, PlanActionKind, SyncMode, SyncOptions,
    SyncProfile,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RsyncFlag {
    Archive,
    ItemizeChanges,
    Compress,
    DestinationCleanup,
    EndOfOptions,
}

impl RsyncFlag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "--archive",
            Self::ItemizeChanges => "--itemize-changes",
            Self::Compress => "--compress",
            Self::DestinationCleanup => "--delete",
            Self::EndOfOptions => "--",
        }
    }
}

impl TryFrom<&str> for RsyncFlag {
    type Error = ProcessSpecError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "--archive" => Ok(Self::Archive),
            "--itemize-changes" => Ok(Self::ItemizeChanges),
            "--compress" => Ok(Self::Compress),
            "--" => Ok(Self::EndOfOptions),
            "--delete" | "--delete-after" | "--delete-before" | "--delete-during" => {
                Err(ProcessSpecError::ArbitraryArgument {
                    value: value.to_owned(),
                })
            }
            _ => Err(ProcessSpecError::UnknownArgument {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessArgument {
    Flag(RsyncFlag),
    ExclusionPattern(String),
    PeerPath(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentBinding {
    name: String,
}

impl EnvironmentBinding {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInvocation {
    program: OsString,
    arguments: Vec<OsString>,
    secret_bindings: Vec<EnvironmentBinding>,
}

impl ProcessInvocation {
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub fn secret_bindings(&self) -> &[EnvironmentBinding] {
        &self.secret_bindings
    }

    pub fn preview(&self) -> String {
        let mut parts = Vec::with_capacity(1 + self.arguments.len() + self.secret_bindings.len());
        parts.extend(
            self.secret_bindings
                .iter()
                .map(|binding| format!("{}=<redacted>", binding.name)),
        );
        parts.push(shell_quote(&self.program));
        parts.extend(self.arguments.iter().map(|argument| shell_quote(argument)));
        parts.join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessSpecError {
    UnknownArgument { value: String },
    ArbitraryArgument { value: String },
    InvalidOptionCombination { reason: &'static str },
    EmptyPeerPath { peer: String },
    NulInPeerPath { peer: String },
    InvalidExclusionPattern { reason: &'static str },
    InvalidSecretBinding { value: String },
    UnsupportedSyncMode,
    ActionNotAllowed { kind: PlanActionKind },
    ActionSourceMismatch,
    InvalidTransferPath { path: PathBuf },
}

impl fmt::Display for ProcessSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument { value } => {
                write!(formatter, "unknown rsync argument: {value}")
            }
            Self::ArbitraryArgument { value } => {
                write!(formatter, "arbitrary rsync argument is not allowed: {value}")
            }
            Self::InvalidOptionCombination { reason } => {
                write!(formatter, "invalid sync option combination: {reason}")
            }
            Self::EmptyPeerPath { peer } => write!(formatter, "peer {peer} has an empty path"),
            Self::NulInPeerPath { peer } => write!(formatter, "peer {peer} path contains NUL"),
            Self::InvalidExclusionPattern { reason } => {
                write!(formatter, "invalid exclusion pattern: {reason}")
            }
            Self::InvalidSecretBinding { value } => {
                write!(formatter, "invalid secret binding name: {value}")
            }
            Self::UnsupportedSyncMode => write!(formatter, "unsupported synchronization mode"),
            Self::ActionNotAllowed { kind } => {
                write!(formatter, "plan action is not a file transfer: {kind:?}")
            }
            Self::ActionSourceMismatch => {
                formatter.write_str("plan action belongs to a different source peer")
            }
            Self::InvalidTransferPath { path } => {
                write!(formatter, "transfer path is not a normalized relative item path: {path:?}")
            }
        }
    }
}

impl std::error::Error for ProcessSpecError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedSyncOptions {
    safe_delete: bool,
    destination_cleanup: bool,
    deletion_method: Option<DeletionMethod>,
}

impl ValidatedSyncOptions {
    pub const fn safe_delete(self) -> bool {
        self.safe_delete
    }

    pub const fn destination_cleanup(self) -> bool {
        self.destination_cleanup
    }

    pub const fn deletion_method(self) -> Option<DeletionMethod> {
        self.deletion_method
    }
}

impl SyncOptions {
    pub fn validate(self) -> Result<ValidatedSyncOptions, ProcessSpecError> {
        if self.safe_delete && self.deletion_method.is_none() {
            return Err(ProcessSpecError::InvalidOptionCombination {
                reason: "Safe Delete requires an explicit deletion method",
            });
        }

        if self.deletion_method.is_some() && !self.safe_delete && !self.destination_cleanup {
            return Err(ProcessSpecError::InvalidOptionCombination {
                reason: "a deletion method requires an explicit destructive action",
            });
        }

        Ok(ValidatedSyncOptions {
            safe_delete: self.safe_delete,
            destination_cleanup: self.destination_cleanup,
            deletion_method: self.deletion_method,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpecification {
    arguments: Vec<ProcessArgument>,
    options: ValidatedSyncOptions,
    source: OneWaySource,
    source_root: PathBuf,
    destination_root: PathBuf,
    secret_bindings: Vec<EnvironmentBinding>,
}

impl ProcessSpecification {
    pub fn from_profile(profile: &SyncProfile) -> Result<Self, ProcessSpecError> {
        if profile.mode() != SyncMode::OneWay {
            return Err(ProcessSpecError::UnsupportedSyncMode);
        }

        let options = profile.options().validate()?;
        let (source, destination) = match profile.source() {
            OneWaySource::PeerA => (profile.peer_a(), profile.peer_b()),
            OneWaySource::PeerB => (profile.peer_b(), profile.peer_a()),
        };

        validate_peer_path(source.name(), source.root())?;
        validate_peer_path(destination.name(), destination.root())?;

        let mut arguments = vec![
            ProcessArgument::Flag(RsyncFlag::Archive),
            ProcessArgument::Flag(RsyncFlag::ItemizeChanges),
        ];

        if options.destination_cleanup() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::DestinationCleanup));
        }

        for exclusion in profile.exclusions() {
            validate_exclusion_pattern(exclusion)?;
            arguments.push(ProcessArgument::ExclusionPattern(exclusion.clone()));
        }

        arguments.extend([
            ProcessArgument::Flag(RsyncFlag::EndOfOptions),
            ProcessArgument::PeerPath(source.root().to_path_buf()),
            ProcessArgument::PeerPath(destination.root().to_path_buf()),
        ]);

        Ok(Self {
            arguments,
            options,
            source: profile.source(),
            source_root: source.root().to_path_buf(),
            destination_root: destination.root().to_path_buf(),
            secret_bindings: Vec::new(),
        })
    }

    pub fn arguments(&self) -> &[ProcessArgument] {
        &self.arguments
    }

    pub const fn options(&self) -> ValidatedSyncOptions {
        self.options
    }

    pub const fn source(&self) -> OneWaySource {
        self.source
    }

    pub fn exclusions(&self) -> impl Iterator<Item = &str> {
        self.arguments.iter().filter_map(|argument| match argument {
            ProcessArgument::ExclusionPattern(pattern) => Some(pattern.as_str()),
            ProcessArgument::Flag(_) | ProcessArgument::PeerPath(_) => None,
        })
    }

    pub fn with_secret_binding(
        mut self,
        name: impl Into<String>,
    ) -> Result<Self, ProcessSpecError> {
        let name = name.into();
        if !is_valid_secret_binding_name(&name) {
            return Err(ProcessSpecError::InvalidSecretBinding { value: name });
        }

        if !self.secret_bindings.iter().any(|binding| binding.name == name) {
            self.secret_bindings.push(EnvironmentBinding { name });
        }

        Ok(self)
    }

    pub fn invocation(&self) -> ProcessInvocation {
        ProcessInvocation {
            program: OsString::from("rsync"),
            arguments: self
                .arguments
                .iter()
                .map(ProcessArgument::to_os_string)
                .collect(),
            secret_bindings: self.secret_bindings.clone(),
        }
    }

    /// Builds the controlled per-item invocation used by the execution seam.
    /// Destination cleanup is intentionally excluded: a temporary item
    /// transfer must never turn into a tree-wide deletion command.
    pub(crate) fn item_invocation(
        &self,
        source: &Path,
        temporary_destination: &Path,
    ) -> Result<ProcessInvocation, ProcessSpecError> {
        validate_peer_path("item source", source)?;
        validate_peer_path("temporary destination", temporary_destination)?;
        Ok(ProcessInvocation {
            program: OsString::from("rsync"),
            arguments: vec![
                ProcessArgument::Flag(RsyncFlag::Archive).to_os_string(),
                ProcessArgument::Flag(RsyncFlag::ItemizeChanges).to_os_string(),
                ProcessArgument::Flag(RsyncFlag::EndOfOptions).to_os_string(),
                ProcessArgument::PeerPath(source.to_path_buf()).to_os_string(),
                ProcessArgument::PeerPath(temporary_destination.to_path_buf()).to_os_string(),
            ],
            secret_bindings: Vec::new(),
        })
    }

    pub(crate) fn transfer_paths(
        &self,
        action: &PlanAction,
    ) -> Result<(PathBuf, PathBuf), ProcessSpecError> {
        if !matches!(
            action.kind(),
            PlanActionKind::CopyToDestination | PlanActionKind::OverwriteDestination
        ) {
            return Err(ProcessSpecError::ActionNotAllowed {
                kind: action.kind(),
            });
        }
        if action.source_side() != PeerSide::from(self.source) {
            return Err(ProcessSpecError::ActionSourceMismatch);
        }
        validate_relative_transfer_path(action.relative_path())?;
        Ok((
            self.source_root.join(action.relative_path()),
            self.destination_root.join(action.relative_path()),
        ))
    }

    pub fn preview(&self) -> String {
        self.invocation().preview()
    }
}

impl ProcessArgument {
    fn to_os_string(&self) -> OsString {
        match self {
            Self::Flag(flag) => OsString::from(flag.as_str()),
            Self::ExclusionPattern(pattern) => {
                let mut argument = OsString::from("--exclude=");
                argument.push(pattern);
                argument
            }
            Self::PeerPath(path) => path.as_os_str().to_os_string(),
        }
    }
}

fn validate_peer_path(peer: &str, path: &Path) -> Result<(), ProcessSpecError> {
    if path.as_os_str().is_empty() {
        return Err(ProcessSpecError::EmptyPeerPath {
            peer: peer.to_owned(),
        });
    }

    if path_contains_nul(path) {
        return Err(ProcessSpecError::NulInPeerPath {
            peer: peer.to_owned(),
        });
    }

    Ok(())
}

fn validate_exclusion_pattern(pattern: &str) -> Result<(), ProcessSpecError> {
    if pattern.is_empty() {
        return Err(ProcessSpecError::InvalidExclusionPattern {
            reason: "the pattern must not be empty",
        });
    }

    if pattern.contains('\0') {
        return Err(ProcessSpecError::InvalidExclusionPattern {
            reason: "the pattern contains NUL",
        });
    }

    Ok(())
}

fn validate_relative_transfer_path(path: &Path) -> Result<(), ProcessSpecError> {
    use std::path::Component;

    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProcessSpecError::InvalidTransferPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
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

fn is_valid_secret_binding_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn shell_quote(value: &OsStr) -> String {
    let mut quoted = String::from("'");

    for character in value.to_string_lossy().chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '\'' => quoted.push_str("'\\''"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            character if character.is_control() => {
                quoted.push_str(&format!("\\u{{{:x}}}", character as u32));
            }
            character => quoted.push(character),
        }
    }

    quoted.push('\'');
    quoted
}

#[cfg(test)]
pub(crate) fn test_process_invocation(program: &str, arguments: &[&str]) -> ProcessInvocation {
    ProcessInvocation {
        program: OsString::from(program),
        arguments: arguments.iter().map(OsString::from).collect(),
        secret_bindings: Vec::new(),
    }
}
