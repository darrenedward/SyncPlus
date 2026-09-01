use std::{
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    DeletionMethod, MetadataRequirements, OneWaySource, PartialTransferPolicy, PeerSide,
    Peer, PlanAction, PlanActionKind, RetryPolicy, SshPeer, SyncMode, SyncOptions, SyncProfile,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RsyncFlag {
    Archive,
    ItemizeChanges,
    ProtectArgs,
    Compress,
    DestinationCleanup,
    EndOfOptions,
    Acls,
    Xattrs,
}

impl RsyncFlag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "--archive",
            Self::ItemizeChanges => "--itemize-changes",
            Self::ProtectArgs => "--protect-args",
            Self::Compress => "--compress",
            Self::DestinationCleanup => "--delete",
            Self::EndOfOptions => "--",
            Self::Acls => "--acls",
            Self::Xattrs => "--xattrs",
        }
    }
}

impl TryFrom<&str> for RsyncFlag {
    type Error = ProcessSpecError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "--archive" => Ok(Self::Archive),
            "--itemize-changes" => Ok(Self::ItemizeChanges),
            "--protect-args" => Ok(Self::ProtectArgs),
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
    RemotePeerPath(SshTarget),
    SshTransport(SshTransport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    username: String,
    server: String,
    remote_path: PathBuf,
}

impl SshTarget {
    fn from_peer(peer: &SshPeer) -> Self {
        Self {
            username: peer.username().to_owned(),
            server: peer.server().to_owned(),
            remote_path: peer.remote_path().to_path_buf(),
        }
    }

    fn from_peer_at(peer: &SshPeer, relative_path: &Path) -> Result<Self, ProcessSpecError> {
        validate_relative_transfer_path(relative_path)?;
        let mut remote_path = peer.remote_path().to_path_buf();
        remote_path.push(relative_path);
        Self::from_peer_path(peer, remote_path)
    }

    fn from_peer_path(peer: &SshPeer, remote_path: PathBuf) -> Result<Self, ProcessSpecError> {
        validate_peer_path("remote target", &remote_path)?;
        Ok(Self {
            username: peer.username().to_owned(),
            server: peer.server().to_owned(),
            remote_path,
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn remote_path(&self) -> &Path {
        &self.remote_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTransport {
    port: u16,
    identity: Option<PathBuf>,
    authentication: crate::SshAuthentication,
}

impl SshTransport {
    fn from_peer(peer: &SshPeer) -> Self {
        Self {
            port: peer.port(),
            identity: peer.identity().map(Path::to_path_buf),
            authentication: peer.authentication(),
        }
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn identity(&self) -> Option<&Path> {
        self.identity.as_deref()
    }

    pub fn authentication(&self) -> crate::SshAuthentication {
        self.authentication.clone()
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteHelperKind {
    Sha256,
}

/// A fixed SSH helper invocation. The remote command is selected by this
/// enum, never supplied by a caller; the only user-controlled value is the
/// safely shell-encoded path passed to that fixed helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHelperInvocation {
    kind: RemoteHelperKind,
    path: PathBuf,
    invocation: ProcessInvocation,
}

impl RemoteHelperInvocation {
    pub fn sha256_with_permit(
        peer: &SshPeer,
        permit: &crate::SshHostTrustPermit,
        path: impl Into<PathBuf>,
    ) -> Result<Self, ProcessSpecError> {
        if permit.host() != &crate::SshHost::from_peer(peer) {
            return Err(ProcessSpecError::HostTrustPermitMismatch);
        }
        Self::sha256(peer, path)
    }

    pub fn sha256(peer: &SshPeer, path: impl Into<PathBuf>) -> Result<Self, ProcessSpecError> {
        let path = path.into();
        validate_peer_path("remote helper path", &path)?;
        let mut arguments = Vec::new();
        arguments.extend([OsString::from("-p"), OsString::from(peer.port().to_string())]);
        match peer.authentication() {
            crate::SshAuthentication::Key => {
                arguments.extend([
                    OsString::from("-o"),
                    OsString::from("IdentitiesOnly=yes"),
                    OsString::from("-o"),
                    OsString::from("IdentityAgent=none"),
                    OsString::from("-o"),
                    OsString::from("PreferredAuthentications=publickey"),
                    OsString::from("-o"),
                    OsString::from("PasswordAuthentication=no"),
                    OsString::from("-o"),
                    OsString::from("KbdInteractiveAuthentication=no"),
                ]);
                let identity = peer
                    .identity()
                    .ok_or(ProcessSpecError::UnsupportedSshTopology)?;
                arguments.extend([OsString::from("-i"), identity.as_os_str().to_os_string()]);
            }
            crate::SshAuthentication::Agent => {
                arguments.extend([
                    OsString::from("-o"),
                    OsString::from("IdentityFile=none"),
                    OsString::from("-o"),
                    OsString::from("PreferredAuthentications=publickey"),
                    OsString::from("-o"),
                    OsString::from("PasswordAuthentication=no"),
                    OsString::from("-o"),
                    OsString::from("KbdInteractiveAuthentication=no"),
                ]);
            }
            crate::SshAuthentication::InteractivePassword
            | crate::SshAuthentication::SavedPassword(_) => {
                arguments.extend([
                    OsString::from("-o"),
                    OsString::from("IdentityFile=none"),
                    OsString::from("-o"),
                    OsString::from("IdentityAgent=none"),
                    OsString::from("-o"),
                    OsString::from("PreferredAuthentications=keyboard-interactive,password"),
                    OsString::from("-o"),
                    OsString::from("PasswordAuthentication=yes"),
                    OsString::from("-o"),
                    OsString::from("KbdInteractiveAuthentication=yes"),
                ]);
            }
        }
        arguments.push(OsString::from(format!(
            "{}@{}",
            peer.username(),
            peer.server()
        )));
        arguments.push(OsString::from(format!(
            "sha256sum -- {}",
            encode_remote_shell_word(&path)
        )));
        Ok(Self {
            kind: RemoteHelperKind::Sha256,
            path,
            invocation: ProcessInvocation {
                program: OsString::from("ssh"),
                arguments,
                secret_bindings: Vec::new(),
            },
        })
    }

    pub const fn kind(&self) -> RemoteHelperKind {
        self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn invocation(&self) -> &ProcessInvocation {
        &self.invocation
    }
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
    UnsupportedSshTopology,
    UnsupportedSshFilesystemOperation,
    MirrorRequiresReviewedPlan,
    ActionNotAllowed { kind: PlanActionKind },
    ActionSourceMismatch,
    InvalidTransferPath { path: PathBuf },
    InvalidRetryPolicy { max_attempts: u8 },
    InvalidRetryDelay { milliseconds: u128 },
    HostTrustPermitMismatch,
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
            Self::UnsupportedSshTopology => {
                write!(formatter, "SSH-to-SSH synchronization is not supported")
            }
            Self::UnsupportedSshFilesystemOperation => {
                write!(formatter, "local filesystem operations cannot use an SSH peer yet")
            }
            Self::MirrorRequiresReviewedPlan => write!(
                formatter,
                "Mirror execution requires the reviewed per-item plan"
            ),
            Self::ActionNotAllowed { kind } => {
                write!(formatter, "plan action is not a file transfer: {kind:?}")
            }
            Self::ActionSourceMismatch => {
                formatter.write_str("plan action belongs to a different source peer")
            }
            Self::InvalidTransferPath { path } => {
                write!(formatter, "transfer path is not a normalized relative item path: {path:?}")
            }
            Self::InvalidRetryPolicy { max_attempts } => {
                write!(formatter, "retry policy must allow between 1 and 10 attempts, got {max_attempts}")
            }
            Self::InvalidRetryDelay { milliseconds } => write!(
                formatter,
                "retry policy initial delay must be at most 3600000 milliseconds, got {milliseconds}"
            ),
            Self::HostTrustPermitMismatch => {
                formatter.write_str("SSH host-trust permit does not match the remote endpoint")
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
    metadata: MetadataRequirements,
    partial_transfer_policy: PartialTransferPolicy,
    retry_policy: RetryPolicy,
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

    pub const fn metadata(self) -> MetadataRequirements {
        self.metadata
    }

    pub const fn specialist_metadata(self) -> crate::SpecialistMetadataRequirements { self.metadata.specialist_metadata() }

    pub const fn partial_transfer_policy(self) -> PartialTransferPolicy {
        self.partial_transfer_policy
    }

    pub const fn retry_policy(self) -> RetryPolicy {
        self.retry_policy
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

        if !(1..=RetryPolicy::MAX_ATTEMPTS).contains(&self.retry_policy.max_attempts()) {
            return Err(ProcessSpecError::InvalidRetryPolicy {
                max_attempts: self.retry_policy.max_attempts(),
            });
        }
        if self.retry_policy.initial_delay() > RetryPolicy::MAX_INITIAL_DELAY {
            return Err(ProcessSpecError::InvalidRetryDelay {
                milliseconds: self.retry_policy.initial_delay().as_millis(),
            });
        }

        Ok(ValidatedSyncOptions {
            safe_delete: self.safe_delete,
            destination_cleanup: self.destination_cleanup,
            deletion_method: self.deletion_method,
            metadata: self.metadata,
            partial_transfer_policy: self.partial_transfer_policy,
            retry_policy: self.retry_policy,
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
    mode: SyncMode,
    peer_a_root: PathBuf,
    peer_b_root: PathBuf,
    ssh_transport: Option<SshTransport>,
    peer_a_ssh: Option<SshPeer>,
    peer_b_ssh: Option<SshPeer>,
}

impl ProcessSpecification {
    pub fn from_profile(profile: &SyncProfile) -> Result<Self, ProcessSpecError> {
        if !matches!(profile.mode(), SyncMode::OneWay | SyncMode::Mirror) {
            return Err(ProcessSpecError::UnsupportedSyncMode);
        }

        let options = profile.options().validate()?;
        if profile.mode() == SyncMode::Mirror
            && (options.safe_delete() || options.destination_cleanup())
        {
            return Err(ProcessSpecError::InvalidOptionCombination {
                reason: "Mirror cannot enable One-Way deletion options",
            });
        }
        let (source, destination) = match profile.source() {
            OneWaySource::PeerA => (profile.peer_a(), profile.peer_b()),
            OneWaySource::PeerB => (profile.peer_b(), profile.peer_a()),
        };

        if profile.peer_a().is_ssh() && profile.peer_b().is_ssh() {
            return Err(ProcessSpecError::UnsupportedSshTopology);
        }

        validate_peer_path(source.name(), source.root())?;
        validate_peer_path(destination.name(), destination.root())?;

        let ssh_transport = profile
            .peer_a()
            .ssh_peer()
            .or_else(|| profile.peer_b().ssh_peer())
            .map(SshTransport::from_peer);

        let mut arguments = vec![
            ProcessArgument::Flag(RsyncFlag::Archive),
            ProcessArgument::Flag(RsyncFlag::ItemizeChanges),
        ];

        // Rsync otherwise lets its remote-shell layer reinterpret apostrophes,
        // control characters, and shell metacharacters in remote paths.
        if ssh_transport.is_some() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::ProtectArgs));
        }

        if options.specialist_metadata().access_control_lists() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::Acls));
        }
        if options.specialist_metadata().extended_attributes() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::Xattrs));
        }

        if options.destination_cleanup() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::DestinationCleanup));
        }

        for exclusion in profile.exclusions() {
            validate_exclusion_pattern(exclusion)?;
            arguments.push(ProcessArgument::ExclusionPattern(exclusion.clone()));
        }

        if let Some(ssh_transport) = &ssh_transport {
            arguments.push(ProcessArgument::SshTransport(ssh_transport.clone()));
        }

        arguments.push(ProcessArgument::Flag(RsyncFlag::EndOfOptions));
        arguments.push(peer_argument(source));
        arguments.push(peer_argument(destination));

        Ok(Self {
            arguments,
            options,
            source: profile.source(),
            source_root: source.root().to_path_buf(),
            destination_root: destination.root().to_path_buf(),
            secret_bindings: Vec::new(),
            mode: profile.mode(),
            peer_a_root: profile.peer_a().root().to_path_buf(),
            peer_b_root: profile.peer_b().root().to_path_buf(),
            ssh_transport,
            peer_a_ssh: profile.peer_a().ssh_peer().cloned(),
            peer_b_ssh: profile.peer_b().ssh_peer().cloned(),
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

    pub const fn mode(&self) -> SyncMode {
        self.mode
    }

    pub fn ssh_transport(&self) -> Option<&SshTransport> {
        self.ssh_transport.as_ref()
    }

    pub fn exclusions(&self) -> impl Iterator<Item = &str> {
        self.arguments.iter().filter_map(|argument| match argument {
            ProcessArgument::ExclusionPattern(pattern) => Some(pattern.as_str()),
            ProcessArgument::Flag(_)
            | ProcessArgument::PeerPath(_)
            | ProcessArgument::RemotePeerPath(_)
            | ProcessArgument::SshTransport(_) => None,
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

    pub fn invocation(&self) -> Result<ProcessInvocation, ProcessSpecError> {
        if self.mode == SyncMode::Mirror {
            return Err(ProcessSpecError::MirrorRequiresReviewedPlan);
        }
        Ok(ProcessInvocation {
            program: OsString::from("rsync"),
            arguments: self
                .arguments
                .iter()
                .map(ProcessArgument::to_os_string)
                .collect(),
            secret_bindings: self.secret_bindings.clone(),
        })
    }

    /// Builds the controlled per-item invocation used by the execution seam.
    /// Destination cleanup is intentionally excluded: a temporary item
    /// transfer must never turn into a tree-wide deletion command.
    pub(crate) fn item_invocation(
        &self,
        source: &Path,
        temporary_destination: &Path,
    ) -> Result<ProcessInvocation, ProcessSpecError> {
        if self.ssh_transport.is_some() {
            return Err(ProcessSpecError::UnsupportedSshFilesystemOperation);
        }
        validate_peer_path("item source", source)?;
        validate_peer_path("temporary destination", temporary_destination)?;
        Ok(ProcessInvocation {
            program: OsString::from("rsync"),
            arguments: {
                let mut arguments = vec![
                    ProcessArgument::Flag(RsyncFlag::Archive).to_os_string(),
                    ProcessArgument::Flag(RsyncFlag::ItemizeChanges).to_os_string(),
                ];
                if self.options.specialist_metadata().access_control_lists() {
                    arguments.push(ProcessArgument::Flag(RsyncFlag::Acls).to_os_string());
                }
                if self.options.specialist_metadata().extended_attributes() {
                    arguments.push(ProcessArgument::Flag(RsyncFlag::Xattrs).to_os_string());
                }
                arguments.extend([
                    ProcessArgument::Flag(RsyncFlag::EndOfOptions).to_os_string(),
                    ProcessArgument::PeerPath(source.to_path_buf()).to_os_string(),
                    ProcessArgument::PeerPath(temporary_destination.to_path_buf()).to_os_string(),
                ]);
                arguments
            },
            secret_bindings: Vec::new(),
        })
    }

    /// Build the per-item rsync invocation for one local/SSH direction. The
    /// remote endpoint remains one typed rsync target argument; no shell or
    /// arbitrary remote command is introduced at this boundary.
    pub fn ssh_item_invocation(
        &self,
        action: &PlanAction,
    ) -> Result<ProcessInvocation, ProcessSpecError> {
        let destination_side = action.source_side().opposite();
        let destination_root = match destination_side {
            PeerSide::PeerA => &self.peer_a_root,
            PeerSide::PeerB => &self.peer_b_root,
        };
        let destination = destination_root.join(action.relative_path());
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let name = destination
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| std::borrow::Cow::Borrowed("item"));
        let staging = parent.join(format!(
            ".syncplus-temporary-0-{}-{name}",
            action.action_id()
        ));
        self.ssh_item_invocation_to(action, &staging)
    }

    /// Build a typed SSH rsync invocation whose destination is an explicitly
    /// selected staging path. The caller must use the same validated plan
    /// action and only install the final destination after independent proof.
    pub fn ssh_item_invocation_to(
        &self,
        action: &PlanAction,
        destination: &Path,
    ) -> Result<ProcessInvocation, ProcessSpecError> {
        if self.ssh_transport.is_none() {
            return Err(ProcessSpecError::UnsupportedSshFilesystemOperation);
        }
        if !matches!(
            action.kind(),
            PlanActionKind::CopyToDestination | PlanActionKind::OverwriteDestination
        ) {
            return Err(ProcessSpecError::ActionNotAllowed {
                kind: action.kind(),
            });
        }
        validate_relative_transfer_path(action.relative_path())?;
        let mut arguments = vec![
            ProcessArgument::Flag(RsyncFlag::Archive).to_os_string(),
            ProcessArgument::Flag(RsyncFlag::ItemizeChanges).to_os_string(),
        ];
        // Per-item SSH transfers use the same argument-protection contract as
        // whole-tree SSH invocations.
        arguments.push(ProcessArgument::Flag(RsyncFlag::ProtectArgs).to_os_string());
        if self.options.specialist_metadata().access_control_lists() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::Acls).to_os_string());
        }
        if self.options.specialist_metadata().extended_attributes() {
            arguments.push(ProcessArgument::Flag(RsyncFlag::Xattrs).to_os_string());
        }
        if let Some(transport) = &self.ssh_transport {
            arguments.push(ProcessArgument::SshTransport(transport.clone()).to_os_string());
        }
        arguments.push(ProcessArgument::Flag(RsyncFlag::EndOfOptions).to_os_string());
        arguments.push(
            self.peer_argument_at(action.source_side(), action.relative_path())?
                .to_os_string(),
        );
        arguments.push(
            self.peer_argument_at_path(action.source_side().opposite(), destination)?
                .to_os_string(),
        );
        Ok(ProcessInvocation {
            program: OsString::from("rsync"),
            arguments,
            secret_bindings: self.secret_bindings.clone(),
        })
    }

    fn peer_argument_at(
        &self,
        side: PeerSide,
        relative_path: &Path,
    ) -> Result<ProcessArgument, ProcessSpecError> {
        validate_relative_transfer_path(relative_path)?;
        let root = match side {
            PeerSide::PeerA => &self.peer_a_root,
            PeerSide::PeerB => &self.peer_b_root,
        };
        let ssh_peer = match side {
            PeerSide::PeerA => self.peer_a_ssh.as_ref(),
            PeerSide::PeerB => self.peer_b_ssh.as_ref(),
        };
        match ssh_peer {
            Some(peer) => Ok(ProcessArgument::RemotePeerPath(
                SshTarget::from_peer_at(peer, relative_path)?,
            )),
            None => Ok(ProcessArgument::PeerPath(root.join(relative_path))),
        }
    }

    fn peer_argument_at_path(
        &self,
        side: PeerSide,
        path: &Path,
    ) -> Result<ProcessArgument, ProcessSpecError> {
        validate_peer_path("transfer destination", path)?;
        let ssh_peer = match side {
            PeerSide::PeerA => self.peer_a_ssh.as_ref(),
            PeerSide::PeerB => self.peer_b_ssh.as_ref(),
        };
        match ssh_peer {
            Some(peer) => Ok(ProcessArgument::RemotePeerPath(
                SshTarget::from_peer_path(peer, path.to_path_buf())?,
            )),
            None => Ok(ProcessArgument::PeerPath(path.to_path_buf())),
        }
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
        if self.mode == SyncMode::OneWay && action.source_side() != PeerSide::from(self.source) {
            return Err(ProcessSpecError::ActionSourceMismatch);
        }
        self.ensure_local_filesystem_operations()?;
        validate_relative_transfer_path(action.relative_path())?;
        Ok((
            self.source_path(action)?,
            self.destination_path(action)?,
        ))
    }

    pub fn source_path(&self, action: &PlanAction) -> Result<PathBuf, ProcessSpecError> {
        if self.mode == SyncMode::OneWay && action.source_side() != PeerSide::from(self.source) {
            return Err(ProcessSpecError::ActionSourceMismatch);
        }
        self.ensure_local_filesystem_operations()?;
        validate_relative_transfer_path(action.relative_path())?;
        let root = match action.source_side() {
            PeerSide::PeerA => &self.peer_a_root,
            PeerSide::PeerB => &self.peer_b_root,
        };
        Ok(root.join(action.relative_path()))
    }

    pub fn destination_path(
        &self,
        action: &PlanAction,
    ) -> Result<PathBuf, ProcessSpecError> {
        if self.mode == SyncMode::OneWay && action.source_side() != PeerSide::from(self.source) {
            return Err(ProcessSpecError::ActionSourceMismatch);
        }
        self.ensure_local_filesystem_operations()?;
        validate_relative_transfer_path(action.relative_path())?;
        let root = match action.source_side() {
            PeerSide::PeerA => &self.peer_b_root,
            PeerSide::PeerB => &self.peer_a_root,
        };
        Ok(root.join(action.relative_path()))
    }

    pub(crate) fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub fn preview(&self) -> String {
        if self.mode == SyncMode::Mirror {
            return String::from(
                "Mirror Sync uses one controlled transfer per reviewed plan action; no whole-tree command is available.",
            );
        }
        self.invocation()
            .expect("a validated One-Way specification has a whole-tree invocation")
            .preview()
    }

    fn ensure_local_filesystem_operations(&self) -> Result<(), ProcessSpecError> {
        if self.ssh_transport.is_some() {
            Err(ProcessSpecError::UnsupportedSshFilesystemOperation)
        } else {
            Ok(())
        }
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
            Self::RemotePeerPath(target) => target.to_os_string(),
            Self::SshTransport(transport) => transport.to_os_string(),
        }
    }
}

fn peer_argument(peer: &Peer) -> ProcessArgument {
    match peer.ssh_peer() {
        Some(ssh) => ProcessArgument::RemotePeerPath(SshTarget::from_peer(ssh)),
        None => ProcessArgument::PeerPath(peer.root().to_path_buf()),
    }
}

impl SshTarget {
    fn to_os_string(&self) -> OsString {
        let mut target = OsString::from(self.username.as_str());
        target.push("@");
        target.push(self.server.as_str());
        target.push(":");
        // This is one argv item. Rsync owns the subsequent remote-shell
        // escaping, so quotes must not be inserted into this value.
        target.push(self.remote_path.as_os_str());
        target
    }
}

impl SshTransport {
    fn to_os_string(&self) -> OsString {
        let mut transport = format!("--rsh=ssh -p {}", self.port);
        match &self.authentication {
            crate::SshAuthentication::Key => {
                transport.push_str(
                    " -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no",
                );
                if let Some(identity) = &self.identity {
                    transport.push_str(" -i ");
                    transport.push_str(&encode_remote_shell_word(identity));
                }
            }
            crate::SshAuthentication::Agent => {
                transport.push_str(
                    " -o IdentityFile=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no",
                );
            }
            crate::SshAuthentication::InteractivePassword
            | crate::SshAuthentication::SavedPassword(_) => {
                transport.push_str(
                    " -o IdentityFile=none -o IdentityAgent=none -o PreferredAuthentications=keyboard-interactive,password -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes",
                );
            }
        }
        OsString::from(transport)
    }
}

fn encode_remote_shell_word(path: &Path) -> String {
    let mut encoded = String::from("'");
    for character in path.to_string_lossy().chars() {
        if character == '\'' {
            encoded.push_str("'\\''");
        } else {
            encoded.push(character);
        }
    }
    encoded.push('\'');
    encoded
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
