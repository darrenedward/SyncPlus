use std::{fmt, path::Path};

use crate::{
    ActionReason, ContentProof, DeletionMethod, FileIdentity, InventoryItem, ItemMetadata, ItemType,
    MetadataRequirements, Peer,
    PlanAction, ProcessError,
    ProcessSpecification, ProcessSupervisor, RemotePrecheckPermit, ResolvedSshCredential,
    RecoveryEvidence, SourceInventory, SshHostIdentityProbe, SshHostTrustPermit, SshPeer,
    SshRemotePrecheckProbe,
};

/// The point reached by a remote transfer when it fails. A failure after the
/// destination was installed is never retried as an ordinary transport
/// failure because the filesystem result needs Recovery Review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshTransferBoundary {
    BeforeTransfer,
    TemporaryDestination,
    DestinationInstalled,
    VerificationComplete,
}

/// The boundary reached while moving a verified remote source item into the
/// configured recovery location. A result after the move starts is never
/// treated as an ordinary retry because the source/recovery state is
/// ambiguous until reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshRecoveryBoundary {
    BeforeRecovery,
    RecoveryStarted,
}

impl SshTransferBoundary {
    pub const fn requires_recovery_review(self) -> bool {
        matches!(
            self,
            Self::DestinationInstalled | Self::VerificationComplete
        )
    }

    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::BeforeTransfer | Self::TemporaryDestination)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshRunError {
    Precheck(String),
    RemoteUnavailable,
    RemoteVerificationUnavailable {
        boundary: SshTransferBoundary,
    },
    RemoteVerificationMismatch {
        boundary: SshTransferBoundary,
    },
    RemoteRecoveryUnavailable,
    RemoteRecoveryFailed {
        boundary: SshRecoveryBoundary,
        evidence: Option<RecoveryEvidence>,
    },
    RemoteRecoveryAmbiguous {
        boundary: SshRecoveryBoundary,
        evidence: Option<RecoveryEvidence>,
    },
    Disconnected {
        boundary: SshTransferBoundary,
    },
    Process {
        boundary: SshTransferBoundary,
        error: ProcessError,
    },
    SourceChanged,
    MetadataMismatch,
    Cancelled,
    InvalidOperation,
}

impl SshRunError {
    pub const fn boundary(&self) -> SshTransferBoundary {
        match self {
            Self::Precheck(_)
            | Self::RemoteUnavailable
            | Self::SourceChanged
            | Self::MetadataMismatch
            | Self::Cancelled
            | Self::RemoteRecoveryUnavailable
            | Self::RemoteRecoveryFailed { .. }
            | Self::RemoteRecoveryAmbiguous { .. }
            | Self::InvalidOperation => SshTransferBoundary::BeforeTransfer,
            Self::RemoteVerificationUnavailable { boundary }
            | Self::RemoteVerificationMismatch { boundary }
            | Self::Disconnected { boundary }
            | Self::Process { boundary, .. } => *boundary,
        }
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Disconnected { boundary } | Self::Process { boundary, .. }
                if boundary.is_retryable()
        )
    }

    pub const fn requires_recovery_review(&self) -> bool {
        self.boundary().requires_recovery_review()
            || matches!(
                self,
                Self::RemoteRecoveryUnavailable
                    | Self::RemoteRecoveryFailed { .. }
                    | Self::RemoteRecoveryAmbiguous { .. }
            )
    }

    pub const fn action_reason(&self) -> ActionReason {
        match self {
            Self::RemoteVerificationUnavailable { .. }
            | Self::RemoteVerificationMismatch { .. }
            | Self::MetadataMismatch => ActionReason::VerificationMismatch,
            Self::RemoteRecoveryAmbiguous { .. } => ActionReason::InterruptedBoundary,
            Self::SourceChanged => ActionReason::SourceChanged,
            Self::Cancelled => ActionReason::CancellationRequested,
            Self::Precheck(_)
            | Self::RemoteUnavailable
            | Self::RemoteRecoveryUnavailable
            | Self::RemoteRecoveryFailed { .. }
            | Self::Disconnected { .. }
            | Self::Process { .. } => ActionReason::DestinationUnavailable,
            Self::InvalidOperation => ActionReason::TransferFailed,
        }
    }
}

impl fmt::Display for SshRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Precheck(reason) => write!(formatter, "the SSH remote precheck failed: {reason}"),
            Self::RemoteUnavailable => formatter.write_str("the SSH peer became unavailable"),
            Self::RemoteVerificationUnavailable { boundary } => write!(
                formatter,
                "the remote destination digest was unavailable at the {boundary:?} boundary"
            ),
            Self::RemoteVerificationMismatch { boundary } => write!(
                formatter,
                "the remote destination digest did not match at the {boundary:?} boundary"
            ),
            Self::RemoteRecoveryUnavailable => {
                formatter.write_str("the verified remote Trash location is unavailable")
            }
            Self::RemoteRecoveryFailed { boundary, .. } => write!(
                formatter,
                "remote recovery failed at the {boundary:?} boundary"
            ),
            Self::RemoteRecoveryAmbiguous { boundary, .. } => write!(
                formatter,
                "remote recovery is ambiguous at the {boundary:?} boundary and requires review"
            ),
            Self::Disconnected { boundary } => {
                write!(formatter, "the SSH connection disconnected at the {boundary:?} boundary")
            }
            Self::Process { boundary, error } => {
                write!(formatter, "the controlled SSH process failed at the {boundary:?} boundary: {error}")
            }
            Self::SourceChanged => formatter.write_str("the SSH source changed during transfer"),
            Self::MetadataMismatch => {
                formatter.write_str("the SSH destination metadata did not match the approved source")
            }
            Self::Cancelled => formatter.write_str("the SSH transfer was cancelled"),
            Self::InvalidOperation => formatter.write_str("the SSH operation is not valid for this run"),
        }
    }
}

impl std::error::Error for SshRunError {}

/// Evidence returned only after a remote backend has transferred an item and
/// verified the actual destination. It carries sizes and digests, never file
/// contents or credentials. The source-stability flag is set only after the
/// backend has rechecked the approved source identity and content immediately
/// before any source-removal boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTransferEvidence {
    source_path: Option<std::path::PathBuf>,
    destination_path: Option<std::path::PathBuf>,
    source_metadata: Option<SshMetadataProof>,
    destination_metadata: Option<SshMetadataProof>,
    source_identity: Option<FileIdentity>,
    source: Option<ContentProof>,
    destination: Option<ContentProof>,
    metadata_verified: bool,
    source_stability_verified: bool,
    completed_bytes: u64,
}

/// Metadata captured independently at an SSH source or destination. Remote
/// identities are intentionally omitted; the host/account permit establishes
/// the endpoint and the run still compares file type, timestamps, symlinks,
/// and executable permissions according to the frozen profile options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshMetadataProof {
    item_type: ItemType,
    metadata: ItemMetadata,
}

impl SshMetadataProof {
    pub fn new(item_type: ItemType, metadata: ItemMetadata) -> Self {
        Self { item_type, metadata }
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
    }

    pub fn metadata(&self) -> &ItemMetadata {
        &self.metadata
    }

    fn matches_item(&self, item: &InventoryItem, requirements: MetadataRequirements) -> bool {
        (!requirements.file_type() || self.item_type == item.item_type())
            && (!requirements.executable_permissions()
                || self.metadata.executable_permissions() == item.metadata().executable_permissions())
            && (!requirements.symlink_targets()
                || self.metadata.symlink_target() == item.metadata().symlink_target())
            && (!requirements.timestamps()
                || self.metadata.modified_at() == item.metadata().modified_at())
    }

    fn matches_other(&self, other: &Self, requirements: MetadataRequirements) -> bool {
        (!requirements.file_type() || self.item_type == other.item_type)
            && (!requirements.executable_permissions()
                || self.metadata.executable_permissions() == other.metadata.executable_permissions())
            && (!requirements.symlink_targets()
                || self.metadata.symlink_target() == other.metadata.symlink_target())
            && (!requirements.timestamps()
                || self.metadata.modified_at() == other.metadata.modified_at())
    }
}

impl SshTransferEvidence {
    pub const fn new(
        source: Option<ContentProof>,
        destination: Option<ContentProof>,
        metadata_verified: bool,
        completed_bytes: u64,
    ) -> Self {
        Self {
            source_path: None,
            destination_path: None,
            source_metadata: None,
            destination_metadata: None,
            source_identity: None,
            source,
            destination,
            metadata_verified,
            source_stability_verified: false,
            completed_bytes,
        }
    }

    pub fn with_paths(
        source_path: impl Into<std::path::PathBuf>,
        destination_path: impl Into<std::path::PathBuf>,
        source_metadata: Option<SshMetadataProof>,
        destination_metadata: Option<SshMetadataProof>,
        source: Option<ContentProof>,
        destination: Option<ContentProof>,
        metadata_verified: bool,
        completed_bytes: u64,
    ) -> Self {
        Self {
            source_path: Some(source_path.into()),
            destination_path: Some(destination_path.into()),
            source_metadata,
            destination_metadata,
            source_identity: None,
            source,
            destination,
            metadata_verified,
            source_stability_verified: false,
            completed_bytes,
        }
    }

    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    pub fn destination_path(&self) -> Option<&Path> {
        self.destination_path.as_deref()
    }

    pub fn source_metadata(&self) -> Option<&SshMetadataProof> {
        self.source_metadata.as_ref()
    }

    pub fn destination_metadata(&self) -> Option<&SshMetadataProof> {
        self.destination_metadata.as_ref()
    }

    pub const fn source_identity(&self) -> Option<FileIdentity> {
        self.source_identity
    }

    pub fn with_source_identity(mut self, identity: FileIdentity) -> Self {
        self.source_identity = Some(identity);
        self
    }

    pub const fn source(&self) -> Option<ContentProof> {
        self.source
    }

    pub const fn destination(&self) -> Option<ContentProof> {
        self.destination
    }

    pub const fn metadata_verified(&self) -> bool {
        self.metadata_verified
    }

    pub const fn source_stability_verified(&self) -> bool {
        self.source_stability_verified
    }

    pub fn with_source_stability_verified(mut self) -> Self {
        self.source_stability_verified = true;
        self
    }

    pub const fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    pub fn matches_inventory(&self, item: &InventoryItem, requirements: MetadataRequirements) -> bool {
        if !self.metadata_verified || !self.source_stability_verified {
            return false;
        }
        let (Some(source_metadata), Some(destination_metadata)) =
            (&self.source_metadata, &self.destination_metadata)
        else {
            return false;
        };
        if !source_metadata.matches_item(item, requirements)
            || !destination_metadata.matches_other(source_metadata, requirements)
        {
            return false;
        }
        if item.item_type() != crate::ItemType::RegularFile {
            return true;
        }
        let Some(expected_hash) = item.content_fingerprint() else {
            return false;
        };
        let (Some(source), Some(destination)) = (self.source, self.destination) else {
            return false;
        };
        source.size() == item.metadata().size()
            && source.sha256() == expected_hash
            && destination.matches(&source)
    }

    pub fn matches_request(&self, request: &SshTransferRequest<'_>) -> bool {
        let expected_source = request
            .source_peer()
            .root()
            .join(request.action().relative_path());
        self.source_path() == Some(expected_source.as_path())
            && self.destination_path() == Some(request.destination())
    }

    pub(crate) fn recovery_evidence(&self, observed_at_unix_nanos: i64) -> Option<RecoveryEvidence> {
        let source_size = self
            .source
            .map(|content| content.size())
            .or_else(|| self.source_metadata.as_ref().map(|proof| proof.metadata().size()));
        let destination_size = self
            .destination
            .map(|content| content.size())
            .or_else(|| self.destination_metadata.as_ref().map(|proof| proof.metadata().size()));
        if source_size.is_none() || destination_size.is_none() {
            return None;
        }
        Some(RecoveryEvidence::new(
            observed_at_unix_nanos,
            None,
            true,
            true,
            false,
            source_size,
            destination_size,
            self.source.map(|content| *content.sha256()),
            self.destination.map(|content| *content.sha256()),
        ))
    }
}

/// The immutable inputs a remote backend receives for one approved action.
/// The backend must use `specification` to build the typed rsync invocation,
/// `supervisor` to supervise every SSH/rsync child, and the selected
/// credential/host permit without falling back to another method.
pub struct SshTransferRequest<'a> {
    run_id: crate::RunId,
    specification: &'a ProcessSpecification,
    action: &'a PlanAction,
    source_peer: &'a Peer,
    destination_peer: &'a Peer,
    destination: std::path::PathBuf,
    temporary_destination: std::path::PathBuf,
    previous_destination: std::path::PathBuf,
    remote_peer: &'a SshPeer,
    credential: &'a ResolvedSshCredential,
    host_permit: &'a SshHostTrustPermit,
    precheck: &'a RemotePrecheckPermit,
    supervisor: &'a ProcessSupervisor,
}

impl<'a> SshTransferRequest<'a> {
    pub(crate) fn new(
        run_id: crate::RunId,
        specification: &'a ProcessSpecification,
        action: &'a PlanAction,
        source_peer: &'a Peer,
        destination_peer: &'a Peer,
        remote_peer: &'a SshPeer,
        credential: &'a ResolvedSshCredential,
        host_permit: &'a SshHostTrustPermit,
        precheck: &'a RemotePrecheckPermit,
        supervisor: &'a ProcessSupervisor,
    ) -> Self {
        let destination = destination_peer
            .root()
            .join(action.relative_path());
        let temporary_destination = temporary_destination(&destination, run_id, action);
        let previous_destination = previous_destination(&destination, run_id, action);
        Self {
            run_id,
            specification,
            action,
            source_peer,
            destination_peer,
            destination,
            temporary_destination,
            previous_destination,
            remote_peer,
            credential,
            host_permit,
            precheck,
            supervisor,
        }
    }

    pub fn specification(&self) -> &ProcessSpecification {
        self.specification
    }

    pub const fn run_id(&self) -> crate::RunId {
        self.run_id
    }

    pub fn action(&self) -> &PlanAction {
        self.action
    }

    pub fn source_peer(&self) -> &Peer {
        self.source_peer
    }

    pub fn destination_peer(&self) -> &Peer {
        self.destination_peer
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// The hidden destination-side staging path. A backend must transfer only
    /// to this path, verify it, and then perform its explicit installation
    /// boundary; it must never stream an overwrite straight onto `destination`.
    pub fn temporary_destination(&self) -> &Path {
        &self.temporary_destination
    }

    /// The hidden sibling used to preserve an existing destination during a
    /// verified overwrite. A backend must retain it until the installation
    /// boundary is durably settled or move it into the selected recovery
    /// location according to the run policy.
    pub fn previous_destination(&self) -> &Path {
        &self.previous_destination
    }

    pub fn remote_peer(&self) -> &SshPeer {
        self.remote_peer
    }

    pub fn credential(&self) -> &ResolvedSshCredential {
        self.credential
    }

    pub fn host_permit(&self) -> &SshHostTrustPermit {
        self.host_permit
    }

    pub fn precheck(&self) -> &RemotePrecheckPermit {
        self.precheck
    }

    pub fn supervisor(&self) -> &ProcessSupervisor {
        self.supervisor
    }

    pub fn rsync_invocation(&self) -> Result<crate::ProcessInvocation, crate::ProcessSpecError> {
        if self.host_permit.host() != &crate::SshHost::from_peer(self.remote_peer) {
            return Err(crate::ProcessSpecError::HostTrustPermitMismatch);
        }
        self.specification
            .ssh_item_invocation_to(self.action, &self.temporary_destination)
    }

    pub fn remote_sha256_invocation(
        &self,
        path: &Path,
    ) -> Result<crate::ProcessInvocation, crate::ProcessSpecError> {
        crate::RemoteHelperInvocation::sha256_with_permit(self.remote_peer, self.host_permit, path)
            .map(|helper| helper.invocation().clone())
    }

    pub fn remote_recovery_target(&self) -> Option<std::path::PathBuf> {
        if self.precheck.require_recovery() {
            self.precheck
                .trash_location()
                .map(|root| root.join(self.action.relative_path()))
        } else {
            None
        }
    }

    pub fn deletion_method(&self) -> Option<DeletionMethod> {
        self.specification.options().deletion_method()
    }
}

fn temporary_destination(destination: &Path, run_id: crate::RunId, action: &PlanAction) -> std::path::PathBuf {
    staging_sibling(destination, run_id, action, "temporary")
}

fn previous_destination(destination: &Path, run_id: crate::RunId, action: &PlanAction) -> std::path::PathBuf {
    staging_sibling(destination, run_id, action, "previous")
}

fn staging_sibling(
    destination: &Path,
    run_id: crate::RunId,
    action: &PlanAction,
    kind: &str,
) -> std::path::PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed("item"));
    parent.join(format!(
        ".syncplus-{kind}-{}-{}-{name}",
        run_id.value(),
        action.action_id()
    ))
}

/// Remote operations are deliberately injected behind this small seam. A
/// production implementation uses fixed typed helpers, re-verifies the host
/// fingerprint, and uses `ProcessSupervisor`; tests can use a disposable peer
/// model without making the core depend on a shell, a network runtime, or GUI
/// types.
pub trait SshRunBackend: SshHostIdentityProbe + SshRemotePrecheckProbe {
    fn inventory(
        &self,
        peer: &SshPeer,
        credential: &ResolvedSshCredential,
        host_permit: &SshHostTrustPermit,
        exclusions: &[String],
    ) -> Result<SourceInventory, SshRunError>;

    /// Transfer one planned item and return evidence for the actual
    /// destination. For local-to-SSH this must include a digest obtained from
    /// the remote destination after transfer; an rsync exit code alone is not
    /// a successful result. Before setting the source-stability flag,
    /// implementations must independently recheck the approved source
    /// identity and content immediately before any source-removal boundary.
    /// Implementations must leave temporary files hidden and use the supplied
    /// process-group supervisor.
    fn transfer(
        &self,
        request: &SshTransferRequest<'_>,
        should_cancel: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<SshTransferEvidence, SshRunError>;

    /// Move a verified remote source item into the already verified remote
    /// recovery location. Implementations must use a fixed typed operation,
    /// recheck the source identity and content immediately before mutation,
    /// prefer an atomic same-filesystem move, write a content-free provenance
    /// sidecar before removing the source, and preserve the source on every
    /// failed or ambiguous boundary. A successful result must independently
    /// prove that the source is absent, the recovery item is present, and the
    /// destination remains the verified item.
    fn recover_source(
        &self,
        request: &SshTransferRequest<'_>,
        transfer: &SshTransferEvidence,
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<RecoveryEvidence, SshRunError>;
}
