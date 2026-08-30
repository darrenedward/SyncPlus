mod model;
mod process;
mod analysis;
mod evidence;
mod precheck;
mod scope_lock;
mod parser;
mod runner;
mod verification;
mod replacement;
mod transfer;
mod removal;
mod workflow;

pub use model::{
    ActiveRunState, AuthorizationSnapshot, CoreError, DeletionMethod, MetadataRequirements,
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
pub use workflow::{RunWorkflow, WorkflowError};
pub use precheck::{
    AccessSnapshot, DestinationNamingPolicy, ExecutionPermit, LocalPrecheckProbe,
    NamingConflict, NamingRule, PathRiskLevel, PathRiskWarning, PrecheckBlocker,
    PrecheckBlockerKind, PrecheckBlocked, PrecheckError, PrecheckErrorKind, PrecheckFailure,
    PrecheckLease, PrecheckProbe, PrecheckResult, PermissionIssue, RunPrecheck,
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
mod evidence_tests;
#[cfg(test)]
mod precheck_tests;

#[cfg(test)]
mod scope_lock_tests;

#[cfg(test)]
mod removal_tests;
