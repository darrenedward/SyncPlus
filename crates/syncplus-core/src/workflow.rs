use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::replacement::cleanup_partial_transfer_artifacts;
use crate::{
    ActionOutcome, ActionReason, AnalysisError, ConfirmedPlan, ControlledTransfer, ContentProof,
    FileMetadataProof, FreshAnalysis, JournalEvent, OneWayPlan,
    PlanAction, PlanActionKind, PlanRecord, PreActionState, ProcessError, ProcessSpecification,
    PrecheckErrorKind, PrecheckFailure, PrecheckLease, PrecheckProbe, RecoveryEvidence,
    RecoveryMethod, ReplacementError, RetryPolicy, RunEvidenceStore, RunId, RunPrecheck,
    RunReport, RunReportStatus, RunSnapshot, SafeDeleteError, ScopeLockOwner,
    PeerScopeLockRegistry,
    StorageError, TransferError, VerificationError, VerifiedReplacement,
};

#[derive(Debug)]
pub enum WorkflowError {
    Analysis(AnalysisError),
    Precheck(PrecheckFailure),
    Storage(StorageError),
    Verification(VerificationError),
    ConfirmationRequired,
    InvalidRun(String),
    Io(String),
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Analysis(error) => error.fmt(formatter),
            Self::Precheck(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
            Self::Verification(error) => error.fmt(formatter),
            Self::ConfirmationRequired => {
                formatter.write_str("explicit Execution Confirmation was not given")
            }
            Self::InvalidRun(reason) => write!(formatter, "invalid Sync Run: {reason}"),
            Self::Io(reason) => write!(formatter, "Sync Run filesystem operation failed: {reason}"),
        }
    }
}

impl std::error::Error for WorkflowError {}

impl From<AnalysisError> for WorkflowError {
    fn from(error: AnalysisError) -> Self {
        Self::Analysis(error)
    }
}

impl From<StorageError> for WorkflowError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<VerificationError> for WorkflowError {
    fn from(error: VerificationError) -> Self {
        Self::Verification(error)
    }
}

#[derive(Debug, Clone)]
pub struct RunWorkflow {
    transfer: ControlledTransfer,
    recovery_method: RecoveryMethod,
    scope_locks: PeerScopeLockRegistry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionDisposition {
    Continue,
    Stop,
}

impl RunWorkflow {
    pub fn new(recovery_method: RecoveryMethod) -> Self {
        Self {
            transfer: ControlledTransfer::default(),
            recovery_method,
            scope_locks: PeerScopeLockRegistry::new(),
        }
    }

    pub fn with_supervisor(
        supervisor: crate::ProcessSupervisor,
        recovery_method: RecoveryMethod,
    ) -> Self {
        Self {
            transfer: ControlledTransfer::new(supervisor),
            recovery_method,
            scope_locks: PeerScopeLockRegistry::new(),
        }
    }

    /// Construct a workflow that shares Peer Scope Locks with other manual,
    /// scheduled, or background workflows in the process.
    pub fn with_scope_lock_registry(
        supervisor: crate::ProcessSupervisor,
        recovery_method: RecoveryMethod,
        scope_locks: PeerScopeLockRegistry,
    ) -> Self {
        Self {
            transfer: ControlledTransfer::new(supervisor),
            recovery_method,
            scope_locks,
        }
    }

    /// Run the complete safety lifecycle: Run Precheck, Fresh Analysis,
    /// explicit Execution Confirmation, and execution while the peer scopes
    /// remain locked. The confirmation callback is the UI's final approval;
    /// it runs after the plan has been freshly revalidated.
    pub fn execute<P, C, F>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        probe: &P,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        C: FnOnce(&ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        let _lease = self.acquire_precheck(run_id, profile, probe)?;
        let analysis = FreshAnalysis::analyze(profile)?;
        let confirmed = analysis.confirm(profile)?;
        if !confirm(&confirmed) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        self.recheck_precheck(profile, probe)?;
        let report = self.execute_confirmed(run_id, &confirmed, store, should_cancel)?;
        self.cleanup_partials_after_success(&confirmed, &report)?;
        Ok(report)
    }

    /// Execute only a plan that has passed the Fresh Analysis confirmation
    /// gate. Every action is planned durably before the first filesystem
    /// mutation, and cancellation settles the remaining planned actions.
    fn execute_confirmed<F>(
        &self,
        run_id: RunId,
        confirmed: &ConfirmedPlan,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        F: Fn() -> bool,
    {
        let plan = confirmed.plan();
        plan.validate()
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        let snapshot = RunSnapshot::from_profile(
            run_id,
            confirmed.profile(),
            crate::AuthorizationSnapshot::default(),
        )?;
        store.begin_run(&snapshot)?;
        self.persist_plan(run_id, plan, store)?;

        let cancel = &should_cancel as &dyn Fn() -> bool;
        let mut replacements = BTreeMap::new();
        for (index, action) in plan.actions().iter().enumerate() {
            if cancel() {
                self.cancel_remaining(run_id, &plan.actions()[index..], store)?;
                break;
            }

            if matches!(
                self.execute_action(run_id, plan, action, store, cancel, &mut replacements)?,
                ActionDisposition::Stop
            ) {
                self.cancel_remaining(run_id, &plan.actions()[index + 1..], store)?;
                break;
            }
        }

        Ok(store.load_report(run_id)?)
    }

    /// Reopen an incomplete run safely. Open action boundaries are first
    /// classified as Interrupted or Recovery Review, then a new Fresh
    /// Analysis creates a new Sync Run for the remaining current scope.
    /// Completed filesystem work is not replayed unless Fresh Analysis shows
    /// that the current peers require it again.
    /// Resume an incomplete run through the same precheck, lock, Fresh
    /// Analysis, and explicit confirmation gates as a new run. The old run's
    /// open action boundaries are classified before this method creates a new
    /// Sync Run.
    pub fn resume<P, C, F>(
        &self,
        run_id: RunId,
        probe: &P,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        C: FnOnce(&ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        let report = store.load_report(run_id)?;
        if matches!(report.status(), RunReportStatus::Completed | RunReportStatus::ReviewCleared)
        {
            return Err(WorkflowError::InvalidRun(
                "only an incomplete, cancelled, interrupted, or review-needed run can be resumed"
                    .to_owned(),
            ));
        }
        if report.status() == RunReportStatus::RecoveryReview {
            return Err(WorkflowError::InvalidRun(
                "Recovery Review must be explicitly resolved before a new run can resume"
                    .to_owned(),
            ));
        }

        let profile = report.snapshot().profile().clone();
        let next_run_id = store.next_run_id()?;
        let _lease = self.acquire_precheck(next_run_id, &profile, probe)?;
        self.classify_open_actions(run_id, &profile, &report, store)?;
        let reopened = store.load_report(run_id)?;
        if reopened.status() == RunReportStatus::RecoveryReview {
            return Err(WorkflowError::InvalidRun(
                "Recovery Review must be explicitly resolved before a new run can resume"
                    .to_owned(),
            ));
        }
        let profile = reopened.snapshot().profile().clone();
        let analysis = FreshAnalysis::analyze(&profile)?;
        let confirmed = analysis.confirm(&profile)?;
        if !confirm(&confirmed) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        self.recheck_precheck(&profile, probe)?;
        let report = self.execute_confirmed(next_run_id, &confirmed, store, should_cancel)?;
        self.cleanup_partials_after_success(&confirmed, &report)?;
        Ok(report)
    }

    fn acquire_precheck<P: PrecheckProbe>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        probe: &P,
    ) -> Result<PrecheckLease, WorkflowError> {
        RunPrecheck::check_and_lock(
            profile,
            probe,
            &self.scope_locks,
            ScopeLockOwner::new(profile.name(), run_id),
        )
        .map_err(WorkflowError::Precheck)
    }

    fn recheck_precheck<P: PrecheckProbe>(
        &self,
        profile: &crate::SyncProfile,
        probe: &P,
    ) -> Result<(), WorkflowError> {
        let result = RunPrecheck::check(profile, probe).map_err(|error| {
            WorkflowError::Precheck(match error {
                PrecheckErrorKind::InvalidSpecification(error) => {
                    PrecheckFailure::InvalidSpecification(error)
                }
                PrecheckErrorKind::Probe(error) => PrecheckFailure::Probe(error),
            })
        })?;
        result
            .require_passed()
            .map_err(|blocked| WorkflowError::Precheck(PrecheckFailure::Blocked(blocked)))
    }

    fn cleanup_partials_after_success(
        &self,
        confirmed: &ConfirmedPlan,
        report: &RunReport,
    ) -> Result<(), WorkflowError> {
        if confirmed.plan().specification().options().partial_transfer_policy()
            == crate::PartialTransferPolicy::KeepPartialForResume
            && report.status() == RunReportStatus::Completed
        {
            cleanup_partial_transfer_artifacts(destination_root(confirmed.profile()))
                .map_err(|error| WorkflowError::Io(error.to_string()))?;
        }
        Ok(())
    }

    fn persist_plan(
        &self,
        run_id: RunId,
        plan: &OneWayPlan,
        store: &mut RunEvidenceStore,
    ) -> Result<(), WorkflowError> {
        for action in plan.actions() {
            store.append_event(
                run_id,
                JournalEvent::Planned {
                    action: self.plan_record(plan, action)?,
                },
            )?;
        }
        Ok(())
    }

    fn plan_record(
        &self,
        plan: &OneWayPlan,
        action: &PlanAction,
    ) -> Result<PlanRecord, WorkflowError> {
        let specification = plan.specification();
        let path = match action.kind() {
            PlanActionKind::RemoveDestination => specification.destination_path(action),
            PlanActionKind::CopyToDestination
            | PlanActionKind::OverwriteDestination
            | PlanActionKind::RemoveSourceAfterVerification => specification.source_path(action),
        }
        .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        let metadata = FileMetadataProof::capture(&path)?;
        let sha256 = if metadata.item_type() == crate::ItemType::RegularFile {
            Some(*ContentProof::from_path(&path)?.sha256())
        } else {
            None
        };
        Ok(PlanRecord::new(
            action.action_id(),
            action.relative_path().to_path_buf(),
            action.kind(),
            action.source_side(),
            action.size(),
            PreActionState::new(
                metadata.item_type(),
                metadata.size(),
                metadata.modified_at_unix_nanos(),
                metadata.identity(),
                sha256,
            ),
        ))
    }

    fn execute_action(
        &self,
        run_id: RunId,
        plan: &OneWayPlan,
        action: &PlanAction,
        store: &mut RunEvidenceStore,
        should_cancel: &dyn Fn() -> bool,
        replacements: &mut BTreeMap<PathBuf, VerifiedReplacement>,
    ) -> Result<ActionDisposition, WorkflowError> {
        store.append_event(
            run_id,
            JournalEvent::Started {
                action_id: action.action_id(),
            },
        )?;
        store.append_event(
            run_id,
            JournalEvent::Progress {
                action_id: action.action_id(),
                completed_bytes: 0,
            },
        )?;

        match action.kind() {
            PlanActionKind::CopyToDestination | PlanActionKind::OverwriteDestination => {
                let mut progress = Vec::new();
                let result = self.retry_transfer(
                    plan.specification().options().retry_policy(),
                    should_cancel,
                    || {
                        self.transfer.execute_with_progress_and_policy(
                            plan,
                            action,
                            should_cancel,
                            |bytes| progress.push(bytes),
                        )
                    },
                );
                self.persist_progress(run_id, action.action_id(), progress, store)?;
                match result {
                    Ok(replacement) => {
                        if action.kind() == PlanActionKind::CopyToDestination
                            || plan.specification().options().safe_delete()
                        {
                            replacements.insert(action.relative_path().to_path_buf(), replacement);
                        }
                        store.append_event(
                            run_id,
                            JournalEvent::Completed {
                                action_id: action.action_id(),
                            },
                        )?;
                        Ok(ActionDisposition::Continue)
                    }
                    Err(error) => self.record_transfer_failure(
                        run_id,
                        plan,
                        action,
                        error,
                        store,
                    ),
                }
            }
            PlanActionKind::RemoveSourceAfterVerification => {
                if let Some(replacement) = replacements.remove(action.relative_path()) {
                    return self.settle_source_removal(
                        run_id,
                        plan,
                        action,
                        replacement,
                        should_cancel,
                        store,
                    );
                }
                let mut progress = Vec::new();
                let result = self.retry_transfer(
                    plan.specification().options().retry_policy(),
                    should_cancel,
                    || {
                        self.transfer.execute_source_verification(
                            plan,
                            action,
                            should_cancel,
                            |bytes| progress.push(bytes),
                        )
                    },
                );
                self.persist_progress(run_id, action.action_id(), progress, store)?;
                match result {
                    Ok(replacement) => {
                        self.settle_source_removal(
                            run_id,
                            plan,
                            action,
                            replacement,
                            should_cancel,
                            store,
                        )
                    }
                    Err(error) => self.record_transfer_failure(
                        run_id,
                        plan,
                        action,
                        error,
                        store,
                    ),
                }
            }
            PlanActionKind::RemoveDestination => {
                store.append_event(
                    run_id,
                    JournalEvent::Deferred {
                        action_id: action.action_id(),
                    },
                )?;
                Ok(ActionDisposition::Continue)
            }
        }
    }

    fn settle_source_removal(
        &self,
        run_id: RunId,
        plan: &OneWayPlan,
        action: &PlanAction,
        replacement: VerifiedReplacement,
        should_cancel: &dyn Fn() -> bool,
        store: &mut RunEvidenceStore,
    ) -> Result<ActionDisposition, WorkflowError> {
        if should_cancel() {
            store.append_event(
                run_id,
                JournalEvent::Cancelled {
                    action_id: action.action_id(),
                },
            )?;
            return Ok(ActionDisposition::Stop);
        }
        let executor = crate::SafeDeleteExecutor::new(self.recovery_method.clone());
        match executor.settle_one(run_id, plan, action, &replacement, store) {
            Ok(_) => Ok(ActionDisposition::Continue),
            Err(error) => {
                let already_recorded = store
                    .load_journal(run_id)?
                    .into_iter()
                    .find(|entry| entry.plan().action_id() == action.action_id())
                    .is_some_and(|entry| !matches!(entry.outcome(), ActionOutcome::InProgress));
                if !already_recorded {
                    let reason = safe_delete_reason(&error);
                    let event = if matches!(error, SafeDeleteError::RecoveryUncertain(_)) {
                        JournalEvent::RecoveryReview {
                            action_id: action.action_id(),
                            reason,
                            evidence: observe_action_boundary(plan, action),
                        }
                    } else {
                        JournalEvent::Unresolved {
                            action_id: action.action_id(),
                            reason,
                        }
                    };
                    store.append_event(run_id, event)?;
                }
                if matches!(error, SafeDeleteError::RecoveryUncertain(_)) {
                    Ok(ActionDisposition::Stop)
                } else {
                    Ok(ActionDisposition::Continue)
                }
            }
        }
    }

    fn retry_transfer<F>(
        &self,
        policy: RetryPolicy,
        should_cancel: &dyn Fn() -> bool,
        mut operation: F,
    ) -> Result<VerifiedReplacement, TransferError>
    where
        F: FnMut() -> Result<VerifiedReplacement, TransferError>,
    {
        for attempt in 0..policy.max_attempts() {
            if should_cancel() {
                return Err(TransferError::Replacement(ReplacementError::Cancelled));
            }
            match operation() {
                Ok(replacement) => return Ok(replacement),
                Err(error) if error.is_transient() && attempt + 1 < policy.max_attempts() => {
                    let delay = policy
                        .initial_delay()
                        .checked_mul(u32::from(attempt + 1))
                        .unwrap_or(Duration::MAX);
                    if !sleep_interruptibly(delay, should_cancel) {
                        return Err(TransferError::Replacement(ReplacementError::Cancelled));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("a validated retry policy always has at least one attempt")
    }

    fn persist_progress(
        &self,
        run_id: RunId,
        action_id: u64,
        progress: Vec<u64>,
        store: &mut RunEvidenceStore,
    ) -> Result<(), WorkflowError> {
        for completed_bytes in progress {
            store.append_event(
                run_id,
                JournalEvent::Progress {
                    action_id,
                    completed_bytes,
                },
            )?;
        }
        Ok(())
    }

    fn record_transfer_failure(
        &self,
        run_id: RunId,
        plan: &OneWayPlan,
        action: &PlanAction,
        error: TransferError,
        store: &mut RunEvidenceStore,
    ) -> Result<ActionDisposition, WorkflowError> {
        if matches!(error, TransferError::Replacement(ReplacementError::Cancelled)) {
            store.append_event(
                run_id,
                JournalEvent::Cancelled {
                    action_id: action.action_id(),
                },
            )?;
            return Ok(ActionDisposition::Stop);
        }
        let reason = transfer_reason(&error);
        if error.requires_recovery_review() {
            store.append_event(
                run_id,
                JournalEvent::RecoveryReview {
                    action_id: action.action_id(),
                    reason,
                    evidence: observe_action_boundary(plan, action),
                },
            )?;
            return Ok(ActionDisposition::Stop);
        } else {
            store.append_event(
                run_id,
                JournalEvent::Failed {
                    action_id: action.action_id(),
                    reason,
                },
            )?;
        }
        Ok(ActionDisposition::Continue)
    }

    fn cancel_remaining(
        &self,
        run_id: RunId,
        actions: &[PlanAction],
        store: &mut RunEvidenceStore,
    ) -> Result<(), WorkflowError> {
        for action in actions {
            store.append_event(
                run_id,
                JournalEvent::Cancelled {
                    action_id: action.action_id(),
                },
            )?;
        }
        Ok(())
    }

    fn classify_open_actions(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        report: &RunReport,
        store: &mut RunEvidenceStore,
    ) -> Result<(), WorkflowError> {
        let _specification = ProcessSpecification::from_profile(profile)
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        for item in report.items() {
            if !matches!(item.outcome(), ActionOutcome::InProgress) {
                continue;
            }
            let action = item.journal().plan();
            if action.operation() == PlanActionKind::RemoveSourceAfterVerification
                && (item.journal().transfer_evidence().is_some()
                    || item.journal().proof_boundary().is_some())
            {
                store.append_event(
                    run_id,
                    JournalEvent::RecoveryReview {
                        action_id: action.action_id(),
                        reason: ActionReason::InterruptedBoundary,
                        evidence: observe_journal_boundary(profile, action),
                    },
                )?;
            } else {
                store.append_event(
                    run_id,
                    JournalEvent::Interrupted {
                        action_id: action.action_id(),
                    },
                )?;
            }
        }
        Ok(())
    }
}

fn sleep_interruptibly(duration: Duration, should_cancel: &dyn Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if should_cancel() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
    !should_cancel()
}

fn destination_root(profile: &crate::SyncProfile) -> &Path {
    match profile.source() {
        crate::OneWaySource::PeerA => profile.peer_b().root(),
        crate::OneWaySource::PeerB => profile.peer_a().root(),
    }
}

fn unix_nanos(time: Option<SystemTime>) -> Option<i64> {
    let time = time?;
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).ok(),
        Err(error) => i64::try_from(error.duration().as_nanos())
            .ok()
            .and_then(|nanos| nanos.checked_neg()),
    }
}

fn observe_journal_boundary(
    profile: &crate::SyncProfile,
    action: &crate::PlanRecord,
) -> RecoveryEvidence {
    let specification = match ProcessSpecification::from_profile(profile) {
        Ok(specification) => specification,
        Err(_) => return empty_recovery_evidence(),
    };
    let source = specification.source_root().join(action.relative_path());
    let destination = destination_root(profile).join(action.relative_path());
    observe_paths(&source, &destination)
}

fn observe_action_boundary(plan: &OneWayPlan, action: &PlanAction) -> RecoveryEvidence {
    let specification = plan.specification();
    let source = match specification.source_path(action) {
        Ok(path) => path,
        Err(_) => return empty_recovery_evidence(),
    };
    let destination = match specification.destination_path(action) {
        Ok(path) => path,
        Err(_) => return empty_recovery_evidence(),
    };
    observe_paths(&source, &destination)
}

fn observe_paths(source: &Path, destination: &Path) -> RecoveryEvidence {
    let (source_present, source_size, source_sha256) = observe_content(source);
    let (destination_present, destination_size, destination_sha256) = observe_content(destination);
    RecoveryEvidence::new(
        current_unix_nanos(),
        None,
        source_present,
        destination_present,
        false,
        source_size,
        destination_size,
        source_sha256,
        destination_sha256,
    )
}

fn observe_content(path: &Path) -> (bool, Option<u64>, Option<[u8; 32]>) {
    match ContentProof::from_path(path) {
        Ok(proof) => (true, Some(proof.size()), Some(*proof.sha256())),
        Err(_) => (fs::symlink_metadata(path).is_ok(), None, None),
    }
}

fn empty_recovery_evidence() -> RecoveryEvidence {
    RecoveryEvidence::new(current_unix_nanos(), None, false, false, false, None, None, None, None)
}

fn current_unix_nanos() -> i64 {
    unix_nanos(Some(SystemTime::now())).unwrap_or(0)
}

fn transfer_reason(error: &TransferError) -> ActionReason {
    match error {
        TransferError::Replacement(ReplacementError::Verification(
            VerificationError::SourceChanged,
        )) => ActionReason::SourceChanged,
        TransferError::Replacement(ReplacementError::Verification(_))
        | TransferError::Replacement(ReplacementError::MetadataMismatch) => {
            ActionReason::VerificationMismatch
        }
        TransferError::Replacement(ReplacementError::RecoveryUncertain(_))
        | TransferError::Replacement(ReplacementError::Process(
            ProcessError::OrphanedProcessGroup | ProcessError::ProcessGroup(_),
        ))
        | TransferError::Process(ProcessError::OrphanedProcessGroup)
        | TransferError::Process(ProcessError::ProcessGroup(_)) => {
            ActionReason::InterruptedBoundary
        }
        TransferError::InvalidProcessSpecification(_)
        | TransferError::InvalidPlan(_)
        | TransferError::Process(_)
        | TransferError::Replacement(_)
        | TransferError::MalformedOutput => ActionReason::TransferFailed,
    }
}

fn safe_delete_reason(error: &SafeDeleteError) -> ActionReason {
    match error {
        SafeDeleteError::Verification(VerificationError::SourceChanged) => {
            ActionReason::SourceChanged
        }
        SafeDeleteError::Verification(_) => ActionReason::VerificationMismatch,
        SafeDeleteError::RecoveryUncertain(_) => ActionReason::InterruptedBoundary,
        SafeDeleteError::RecoveryUnavailable(_) => ActionReason::DestinationUnavailable,
        SafeDeleteError::InvalidPlan(_)
        | SafeDeleteError::InvalidAction(_)
        | SafeDeleteError::Io(_)
        | SafeDeleteError::Storage(_) => ActionReason::TransferFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use super::RunWorkflow;
    use crate::{
        ActionOutcome, AuthorizationSnapshot, ContentProof, DeletionMethod, FreshAnalysis,
        ItemType, JournalEvent, OneWaySource, Peer, PeerSide, PlanActionKind, PlanRecord,
        PreActionState, ProcessError, RecoveryEvidence, RecoveryMethod, RetryPolicy,
        LocalPrecheckProbe, PartialTransferPolicy, PeerScope, PeerScopeLockRegistry,
        PrecheckFailure,
        RunEvidenceStore, RunId, RunReportStatus, ScopeLockOwner, SyncOptions, SyncProfile,
    };

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(1);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "syncplus-workflow-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).expect("fixture root should be creatable");
            Self { root }
        }

        fn source(&self) -> PathBuf {
            self.root.join("source")
        }

        fn destination(&self) -> PathBuf {
            self.root.join("destination")
        }

        fn database(&self) -> PathBuf {
            self.root.join("evidence.sqlite")
        }

        fn profile(&self) -> SyncProfile {
            SyncProfile::new(
                "workflow fixture",
                Peer::new("source", self.source()),
                Peer::new("destination", self.destination()),
            )
            .with_source(OneWaySource::PeerA)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent should be creatable");
        }
        fs::write(path, contents).expect("fixture file should be writable");
    }

    #[test]
    fn workflow_requires_explicit_confirmation_before_journaling_or_mutation() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("pending.txt"), b"pending");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let error = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &fixture.profile(),
                &LocalPrecheckProbe::default(),
                |_| false,
                &mut store,
                || false,
            )
            .expect_err("execution must stop without final user approval");

        assert!(matches!(error, super::WorkflowError::ConfirmationRequired));
        assert!(!fixture.destination().join("pending.txt").exists());
        assert!(store.load_report(RunId::new(1)).is_err());
    }

    #[test]
    fn workflow_holds_a_shared_peer_scope_lock_before_execution() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("pending.txt"), b"pending");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");
        let registry = PeerScopeLockRegistry::new();
        let held = registry
            .acquire(
                ScopeLockOwner::new("other profile", RunId::new(99)),
                [PeerScope::new(fixture.source()), PeerScope::new(fixture.destination())],
            )
            .expect("fixture lock should be acquired");
        let workflow = RunWorkflow::with_scope_lock_registry(
            crate::ProcessSupervisor::default(),
            RecoveryMethod::trash(fixture.root.join("trash")),
            registry,
        );
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let error = workflow
            .execute(
                RunId::new(1),
                &fixture.profile(),
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect_err("overlapping scope must block before mutation");

        assert!(matches!(
            error,
            super::WorkflowError::Precheck(PrecheckFailure::ScopeLocked(_))
        ));
        assert!(!fixture.destination().join("pending.txt").exists());
        drop(held);
    }

    fn plan_record_for_source(action_id: u64, path: &Path, relative: &str) -> PlanRecord {
        let metadata = crate::FileMetadataProof::capture(path).expect("source metadata");
        let content = ContentProof::from_path(path).expect("source content");
        PlanRecord::new(
            action_id,
            PathBuf::from(relative),
            PlanActionKind::CopyToDestination,
            PeerSide::PeerA,
            Some(content.size()),
            PreActionState::new(
                ItemType::RegularFile,
                metadata.size(),
                metadata.modified_at_unix_nanos(),
                metadata.identity(),
                Some(*content.sha256()),
            ),
        )
    }

    #[test]
    fn cancellation_records_current_action_and_preserves_source_and_previous_destination() {
        let fixture = Fixture::new();
        let source = fixture.source().join("large.bin");
        let destination = fixture.destination().join("large.bin");
        write_file(&source, &vec![0x5a; 32 * 1024 * 1024]);
        write_file(&destination, b"previous destination");

        let analysis = FreshAnalysis::analyze(&fixture.profile()).expect("fresh analysis");
        let confirmed = analysis.confirm(&fixture.profile()).expect("confirmed analysis");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        let calls = AtomicUsize::new(0);
        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_confirmed(RunId::new(1), &confirmed, &mut store, || {
                calls.fetch_add(1, Ordering::Relaxed) >= 514
            })
            .expect("cancellation should produce a durable report");

        assert_eq!(report.status(), RunReportStatus::Cancelled);
        assert!(matches!(
            report.items()[0].outcome(),
            ActionOutcome::Cancelled
        ));
        assert_eq!(fs::read(&source).expect("source should remain"), vec![0x5a; 32 * 1024 * 1024]);
        assert_eq!(
            fs::read(&destination).expect("previous destination should remain"),
            b"previous destination"
        );
        assert!(!fs::read_dir(fixture.destination())
            .expect("destination should be readable")
            .any(|entry| entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".syncplus-temporary-")));
        assert!(calls.load(Ordering::Relaxed) >= 514);
    }

    #[test]
    fn keep_partial_remains_until_a_resumed_run_completes() {
        let fixture = Fixture::new();
        let source = fixture.source().join("large.bin");
        let destination = fixture.destination().join("large.bin");
        write_file(&source, &vec![0x2a; 32 * 1024 * 1024]);
        write_file(&destination, b"previous destination");
        let profile = fixture.profile().with_options(SyncOptions {
            partial_transfer_policy: PartialTransferPolicy::KeepPartialForResume,
            ..SyncOptions::default()
        });
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        let calls = AtomicUsize::new(0);
        let workflow = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")));

        let cancelled = workflow
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || calls.fetch_add(1, Ordering::Relaxed) >= 516,
            )
            .expect("cancellation should produce a durable report");
        assert_eq!(cancelled.status(), RunReportStatus::Cancelled);
        assert!(fs::read_dir(fixture.destination())
            .expect("destination should be readable")
            .any(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".syncplus-partial-")
            }));

        let resumed = workflow
            .resume(
                RunId::new(1),
                &LocalPrecheckProbe::default(),
                |_| {
                    assert!(fs::read_dir(fixture.destination())
                        .expect("destination should be readable")
                        .any(|entry| {
                            entry
                                .expect("directory entry")
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".syncplus-partial-")
                        }));
                    true
                },
                &mut store,
                || false,
            )
            .expect("resume should finish the retained partial transfer");

        assert_eq!(resumed.status(), RunReportStatus::Completed);
        assert_eq!(fs::read(destination).expect("destination should be installed"), vec![0x2a; 32 * 1024 * 1024]);
        assert!(!fs::read_dir(fixture.destination())
            .expect("destination should be readable")
            .any(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".syncplus-partial-")
            }));
    }

    #[test]
    fn cancellation_before_execution_marks_all_remaining_actions_cancelled() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("a.txt"), b"a");
        write_file(&fixture.source().join("b.txt"), b"b");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");

        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &fixture.profile(),
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || true,
            )
            .expect("cancellation should produce a durable report");

        assert_eq!(report.status(), RunReportStatus::Cancelled);
        assert_eq!(report.items().len(), 2);
        assert!(report
            .items()
            .iter()
            .all(|item| matches!(item.outcome(), ActionOutcome::Cancelled)));
        assert!(!fixture.destination().join("a.txt").exists());
        assert!(!fixture.destination().join("b.txt").exists());
    }

    #[test]
    fn bounded_retry_does_not_restart_a_transient_action_forever() {
        let workflow = RunWorkflow::new(RecoveryMethod::permanent_removal());
        let attempts = Arc::new(AtomicUsize::new(0));
        let operation_attempts = Arc::clone(&attempts);
        let error = workflow
            .retry_transfer(
                RetryPolicy::new(3, std::time::Duration::ZERO),
                &|| false,
                move || {
                    operation_attempts.fetch_add(1, Ordering::Relaxed);
                    Err(crate::TransferError::Process(ProcessError::Io(
                        "temporary transport failure".to_owned(),
                    )))
                },
            )
            .expect_err("three transient failures should stop at the bound");

        assert!(matches!(error, crate::TransferError::Process(ProcessError::Io(_))));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn safe_delete_reverifies_an_already_equal_destination_before_source_removal() {
        let fixture = Fixture::new();
        let source = fixture.source().join("same.txt");
        let destination = fixture.destination().join("same.txt");
        write_file(&source, b"already installed");
        write_file(&destination, b"already installed");
        let source_modified = fs::metadata(&source)
            .expect("source metadata")
            .modified()
            .expect("source modification time");
        fs::File::options()
            .write(true)
            .open(&destination)
            .expect("destination should be writable")
            .set_modified(source_modified)
            .expect("destination timestamp should match");

        let profile = fixture.profile().with_options(SyncOptions {
            safe_delete: true,
            deletion_method: Some(DeletionMethod::Trash),
            ..SyncOptions::default()
        });
        let trash = fixture.root.join("trash");
        fs::create_dir_all(&trash).expect("trash should be creatable");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        let report = RunWorkflow::new(RecoveryMethod::trash(&trash))
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("Safe Delete should reverify equal content before removal");

        assert_eq!(report.status(), RunReportStatus::Completed);
        assert_eq!(report.items().len(), 1);
        assert_eq!(
            report.items()[0].operation(),
            PlanActionKind::RemoveSourceAfterVerification
        );
        assert!(matches!(
            report.items()[0].outcome(),
            ActionOutcome::Completed
        ));
        assert!(!source.exists());
        assert_eq!(fs::read(destination).expect("destination remains"), b"already installed");
    }

    #[test]
    fn resume_does_not_bypass_an_existing_recovery_review() {
        let fixture = Fixture::new();
        let source = fixture.source().join("uncertain.txt");
        write_file(&source, b"source remains");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");
        let profile = fixture.profile();
        let run_id = RunId::new(1);
        let snapshot = crate::RunSnapshot::from_profile(
            run_id,
            &profile,
            AuthorizationSnapshot::default(),
        )
        .expect("snapshot");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        store.begin_run(&snapshot).expect("persist snapshot");
        store
            .append_event(
                run_id,
                JournalEvent::Planned {
                    action: plan_record_for_source(1, &source, "uncertain.txt"),
                },
            )
            .expect("persist plan");
        store
            .append_event(run_id, JournalEvent::Started { action_id: 1 })
            .expect("persist start");
        store
            .append_event(
                run_id,
                JournalEvent::RecoveryReview {
                    action_id: 1,
                    reason: crate::ActionReason::InterruptedBoundary,
                    evidence: RecoveryEvidence::new(
                        1, None, true, false, false, Some(13), None, None, None,
                    ),
                },
            )
            .expect("persist recovery review");

        let error = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .resume(
                run_id,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect_err("an unresolved Recovery Review must not be bypassed");
        assert!(matches!(error, super::WorkflowError::InvalidRun(_)));
        assert!(!fixture.destination().join("uncertain.txt").exists());
    }

    #[test]
    fn resume_freshly_analyzes_and_does_not_replay_completed_actions() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("a.txt"), b"already transferred");
        write_file(&fixture.destination().join("a.txt"), b"already transferred");
        write_file(&fixture.source().join("b.txt"), b"remaining work");

        let profile = fixture.profile();
        let snapshot = crate::RunSnapshot::from_profile(
            RunId::new(1),
            &profile,
            AuthorizationSnapshot::default(),
        )
        .expect("snapshot");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        store.begin_run(&snapshot).expect("persist snapshot");
        store
            .append_event(
                RunId::new(1),
                JournalEvent::Planned {
                    action: plan_record_for_source(1, &fixture.source().join("a.txt"), "a.txt"),
                },
            )
            .expect("plan completed action");
        store
            .append_event(RunId::new(1), JournalEvent::Started { action_id: 1 })
            .expect("start completed action");
        store
            .append_event(RunId::new(1), JournalEvent::Completed { action_id: 1 })
            .expect("complete completed action");
        store
            .append_event(
                RunId::new(1),
                JournalEvent::Planned {
                    action: plan_record_for_source(2, &fixture.source().join("b.txt"), "b.txt"),
                },
            )
            .expect("plan interrupted action");
        store
            .append_event(RunId::new(1), JournalEvent::Started { action_id: 2 })
            .expect("start interrupted action");

        let resumed = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .resume(
                RunId::new(1),
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("resume should create a fresh run");

        assert_eq!(resumed.run_id(), RunId::new(2));
        assert_eq!(resumed.status(), RunReportStatus::Completed);
        assert_eq!(resumed.items().len(), 1);
        assert_eq!(resumed.items()[0].relative_path(), Path::new("b.txt"));
        assert!(matches!(
            store.load_report(RunId::new(1)).expect("old report").status(),
            RunReportStatus::Interrupted
        ));
        assert_eq!(fs::read(fixture.destination().join("b.txt")).expect("b destination"), b"remaining work");
    }
}
