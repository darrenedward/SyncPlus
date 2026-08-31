mod model;
mod process;
mod analysis;
mod conflict;
mod evidence;
mod precheck;
mod scope_lock;
mod parser;
mod runner;
mod verification;
mod replacement;
mod transfer;
mod removal;
mod restore;
mod workflow;
mod reconciliation;
mod volume;

pub use model::{
    ActiveRunState, AuthorizationSnapshot, CoreError, DeletionMethod, MetadataRequirements,
    SpecialistMetadataRequirements,
    OneWaySource, PartialTransferPolicy, Peer, ProfileSnapshot, ProfileSnapshotId, RetryPolicy,
    RunEvent, RunId, RunState, SafetyViolation, SyncMode, SyncOptions, SyncProfile, SyncRun,
    TerminalOutcome,
};
pub use process::{
    EnvironmentBinding, ProcessArgument, ProcessInvocation, ProcessSpecError,
    ProcessSpecification, RsyncFlag, ValidatedSyncOptions,
};
pub use analysis::{
    AnalysisError, AnalysisOutcome, AnalysisRevision, ApprovedSyncScope, ConfirmedPlan,
    FreshAnalysis, InventoryItem, ItemMetadata, ItemType, OneWayPlan, PeerInventory, PeerSide,
    PlanAction, PlanActionKind, PlanError, PlanSummary, ScopeDecision, SourceInventory,
};
pub use conflict::{
    ConflictEntry, ConflictEvidence, ConflictKind, ConflictReview, FileReviewClassification,
};
pub use evidence::{
    ActionId, ActionJournalEntry, ActionOutcome, ActionReason, FileIdentity,
    JournalEvent, PlanRecord, PreActionState, RecoveryEvidence, RecoveryResolution,
    RemovalResult, RunEvidenceStore, RunExecutionResult, RunLifecycle, RunReport, RunReportItem,
    RunReportStatus, RunSnapshot, StorageError,
};
pub use parser::{
    ItemizedRecord, ParseDiagnostic, ParsedOutput, ParsedTransferOutput, ProgressRecord,
    TransferOutputParser,
};
pub use replacement::{ReplacementError, VerifiedReplacement};
pub use runner::{ProcessError, ProcessOutcome, ProcessSupervisor};
pub use verification::{
    verify_content, verify_content_with_cancel, ContentProof, FileMetadataProof,
    SourceObservation, VerificationError, VerifiedTransferProof,
};
pub use transfer::{ControlledTransfer, TransferError};
pub use removal::{RecoveryMethod, RemovalReceipt, SafeDeleteError, SafeDeleteExecutor};
pub use restore::{CollisionSafeRestore, RecoveryProvenance, RestoreError, RestoreJournalEvent, RestoreOutcome};
pub use workflow::{RunWorkflow, WorkflowError};
pub use reconciliation::{
    CompletionReconciliation, InventorySnapshotItem, ReconciliationFinding,
    ReconciliationFindingKind, ReconciliationReason, SourceDrainStatus, SourceInventorySnapshot,
};
pub use volume::{VolumeIdentity, VolumeIdentityError};
pub use precheck::{
    AccessSnapshot, DestinationNamingPolicy, ExecutionPermit, LocalPrecheckProbe,
    NamingConflict, NamingRule, PathRiskLevel, PathRiskWarning, PrecheckBlocker,
    PrecheckBlockerKind, PrecheckBlocked, PrecheckError, PrecheckErrorKind, PrecheckFailure,
    PrecheckLease, PrecheckProbe, PrecheckResult, PermissionIssue, RunPrecheck,
    SpecialistMetadataCapabilities,
};
pub use scope_lock::{
    PeerScope, PeerScopeLock, PeerScopeLockRegistry, ScopeLockConflict, ScopeLockError,
    ScopeLockOwner,
};

#[cfg(test)]
mod contract_tests;

#[cfg(test)]
mod process_tests;

#[cfg(test)]
mod analysis_tests;

#[cfg(test)]
mod conflict_tests;

#[cfg(test)]
mod evidence_tests;
#[cfg(test)]
mod precheck_tests;

#[cfg(test)]
mod scope_lock_tests;

#[cfg(test)]
mod volume_tests;

#[cfg(test)]
mod removal_tests;
#[cfg(test)]
mod restore_tests;
#[cfg(test)]
mod release_gate_tests;
