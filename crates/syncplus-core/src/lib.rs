mod model;
mod process;
mod analysis;
mod evidence;

pub use model::{
    ActiveRunState, AuthorizationSnapshot, CoreError, DeletionMethod, OneWaySource, Peer,
    ProfileSnapshot, ProfileSnapshotId, RunEvent, RunId, RunState, SafetyViolation, SyncMode,
    SyncOptions, SyncProfile, SyncRun, TerminalOutcome,
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
    RunEvidenceStore, RunExecutionResult, RunLifecycle, RunReport, RunReportItem,
    RunReportStatus, RunSnapshot, StorageError,
};

#[cfg(test)]
mod contract_tests;

#[cfg(test)]
mod process_tests;

#[cfg(test)]
mod analysis_tests;

#[cfg(test)]
mod evidence_tests;
