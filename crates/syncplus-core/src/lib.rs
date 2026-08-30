mod model;
mod process;
mod analysis;
mod precheck;
mod scope_lock;

pub use model::{
    ActiveRunState, CoreError, DeletionMethod, OneWaySource, Peer, ProfileSnapshot,
    ProfileSnapshotId, RunEvent, RunId, RunState, SafetyViolation, SyncMode, SyncOptions,
    SyncProfile, SyncRun, TerminalOutcome,
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
pub use precheck::{
    AccessSnapshot, DestinationNamingPolicy, ExecutionPermit, LocalPrecheckProbe,
    NamingConflict, NamingRule, PathRiskLevel, PathRiskWarning, PrecheckBlocker,
    PrecheckBlockerKind, PrecheckBlocked, PrecheckError, PrecheckErrorKind, PrecheckFailure,
    PrecheckLease, PrecheckProbe, PrecheckResult, RunPrecheck,
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
mod precheck_tests;

#[cfg(test)]
mod scope_lock_tests;
