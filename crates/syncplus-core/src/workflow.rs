use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::replacement::cleanup_partial_transfer_artifacts;
use crate::{
    ActionOutcome, ActionReason, AnalysisError, AuthorizationSnapshot, ConfirmedPlan, ConflictResolution,
    DeletionMethod,
    ConflictResolutionAction, CompletionReconciliation, ContentProof, ControlledTransfer,
    FileMetadataProof, FilesystemResolutionExecutor, FreshAnalysis, JournalEvent, OneWayPlan,
    MirrorResolutionOutcome, MirrorResolutionReportItem, MirrorResolutionReviewState,
    PlanAction, PlanActionKind, PlanRecord, PreActionState, PrecheckBlocked,
    PrecheckErrorKind, PrecheckFailure, PrecheckLease, PrecheckProbe,
    PreservedCopyExecutionError, PreservedCopyExecutionOutcome, ProcessError,
    ProcessSpecification, RecoveryEvidence,
    MirrorDeletionResult, RecoveryMethod, ReplacementError, ResolutionRun, ResolutionRunError,
    ResolutionRunOutcome,
    RetryPolicy,
    RunEvidenceStore, RunId, RunPrecheck, RunReport, RunReportStatus, RunSnapshot,
    SafeDeleteError, ScopeLockOwner,
    SourceInventorySnapshot, StorageError, SyncBaseline, TransferError, VerificationError,
    VerifiedReplacement, PeerScope, PeerScopeLock, PeerScopeLockRegistry, SshRunBackend,
    SshRecoveryBoundary, SshRunError, SshRemotePrecheck, RemotePrecheckRequest,
    SshTransferEvidence,
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
    Resolution(ResolutionRunError),
    Ssh(SshRunError),
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
            Self::Resolution(error) => write!(formatter, "Resolution Run failed: {error}"),
            Self::Ssh(error) => write!(formatter, "SSH Sync Run failed: {error}"),
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

impl From<ResolutionRunError> for WorkflowError {
    fn from(error: ResolutionRunError) -> Self {
        Self::Resolution(error)
    }
}

impl From<VerificationError> for WorkflowError {
    fn from(error: VerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<SshRunError> for WorkflowError {
    fn from(error: SshRunError) -> Self {
        Self::Ssh(error)
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
        self.execute_with_authorizations(
            run_id,
            profile,
            probe,
            AuthorizationSnapshot::default(),
            confirm,
            store,
            should_cancel,
        )
    }

    /// Run the complete lifecycle with the immutable authorization decision
    /// selected for this run. The authorization snapshot is persisted with
    /// the run before any filesystem mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_authorizations<P, C, F>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        probe: &P,
        authorizations: AuthorizationSnapshot,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        C: FnOnce(&ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        let lease = match self.acquire_precheck(run_id, profile, probe) {
            Ok(lease) => lease,
            Err(error) => {
                let (source_volume_identity, destination_volume_identity) =
                    blocked_volume_identities(&error);
                self.persist_blocked_with_authorizations(
                    run_id,
                    profile,
                    store,
                    &error,
                    source_volume_identity,
                    destination_volume_identity,
                    authorizations,
                )?;
                return Err(error);
            }
        };
        let source_volume_identity = lease.result().source_volume_identity();
        let destination_volume_identity = lease.result().destination_volume_identity();
        let analysis = FreshAnalysis::analyze(profile)?;
        let confirmed = analysis.confirm(profile)?;
        if !confirm(&confirmed) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        if let Err(error) = self.recheck_precheck(
            profile,
            probe,
            source_volume_identity,
            destination_volume_identity,
            false,
            false,
        ) {
            self.persist_blocked_with_authorizations(
                run_id,
                profile,
                store,
                &error,
                source_volume_identity,
                destination_volume_identity,
                authorizations,
            )?;
            return Err(error);
        }
        let report = self.execute_confirmed_with_authorizations(
            run_id,
            &confirmed,
            authorizations,
            store,
            should_cancel,
            source_volume_identity,
            destination_volume_identity,
        )?;
        self.cleanup_partials_after_success(&confirmed, &report)?;
        Ok(report)
    }

    /// Execute a reviewed Mirror Resolution Run through the same precheck,
    /// scope-lock, fresh-analysis, confirmation, reconciliation, and durable
    /// report boundaries as an ordinary Sync Run.
    pub fn execute_resolution_run<P, C, F>(
        &self,
        run_id: RunId,
        resolution: &ResolutionRun,
        profile: &crate::SyncProfile,
        baseline: Option<&SyncBaseline>,
        probe: &P,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        C: FnOnce(&FreshAnalysis, &[ConflictResolutionAction]) -> bool,
        F: Fn() -> bool,
    {
        self.execute_resolution_run_with_authorizations(
            run_id,
            resolution,
            profile,
            baseline,
            probe,
            AuthorizationSnapshot::default(),
            confirm,
            store,
            should_cancel,
        )
    }

    /// Execute a reviewed Mirror Resolution Run with the selected immutable
    /// authorization snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_resolution_run_with_authorizations<P, C, F>(
        &self,
        run_id: RunId,
        resolution: &ResolutionRun,
        profile: &crate::SyncProfile,
        baseline: Option<&SyncBaseline>,
        probe: &P,
        authorizations: AuthorizationSnapshot,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        C: FnOnce(&FreshAnalysis, &[ConflictResolutionAction]) -> bool,
        F: Fn() -> bool,
    {
        let lease = match self.acquire_precheck(run_id, profile, probe) {
            Ok(lease) => lease,
            Err(error) => {
                let (source_volume_identity, destination_volume_identity) =
                    blocked_volume_identities(&error);
                self.persist_blocked_with_authorizations(
                    run_id,
                    profile,
                    store,
                    &error,
                    source_volume_identity,
                    destination_volume_identity,
                    authorizations,
                )?;
                return Err(error);
            }
        };
        let source_volume_identity = lease.result().source_volume_identity();
        let destination_volume_identity = lease.result().destination_volume_identity();
        let reviewed = resolution.fresh_analysis(profile, baseline)?;
        if !confirm(&reviewed, resolution.plan().actions()) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        let confirmed = resolution.prepare(profile, baseline, true)?;
        self.recheck_precheck(
            profile,
            probe,
            source_volume_identity,
            destination_volume_identity,
            false,
            false,
        )?;

        let (peer_a_volume_identity, peer_b_volume_identity) = orient_volume_identities(
            profile,
            source_volume_identity,
            destination_volume_identity,
        );
        let snapshot = RunSnapshot::from_profile_with_volume_identities(
            run_id,
            profile,
            authorizations,
            peer_a_volume_identity,
            peer_b_volume_identity,
        )?;
        store.begin_run(&snapshot)?;
        let inventory = SourceInventorySnapshot::from_inventory(
            confirmed.fresh_analysis().source_inventory(),
        );
        let destination_inventory = SourceInventorySnapshot::from_inventory(
            confirmed.fresh_analysis().destination_inventory(),
        );
        store.record_source_inventory(run_id, &inventory)?;
        store.record_destination_inventory(run_id, &destination_inventory)?;

        let action_ids = resolution_action_ids(confirmed.actions());
        for action in confirmed.actions() {
            let action_id = action_ids
                .get(action.relative_path())
                .copied()
                .expect("every resolution action has a journal id");
            store.append_event(
                run_id,
                JournalEvent::Planned {
                    action: resolution_plan_record(
                        confirmed.fresh_analysis(),
                        action_id,
                        action,
                    )?,
                },
            )?;
        }

        let peer_a_naming_policy = probe.destination_naming_policy(profile.peer_a().root());
        let peer_b_naming_policy = probe.destination_naming_policy(profile.peer_b().root());
        let mut executor = match FilesystemResolutionExecutor::new_with_naming_policies(
            &confirmed,
            self.transfer,
            should_cancel,
            peer_a_naming_policy,
            peer_b_naming_policy,
        ) {
            Ok(executor) => executor,
            Err(_error) => {
                record_resolution_setup_failure(
                    run_id,
                    confirmed.actions(),
                    &action_ids,
                    store,
                    ActionReason::TransferFailed,
                )?;
                let report_items = resolution_setup_failure_items(
                    confirmed.actions(),
                    ActionReason::TransferFailed,
                );
                store.record_mirror_resolutions(run_id, &report_items)?;
                return self.reconcile_run_with_resolutions(
                    run_id,
                    profile,
                    &inventory,
                    &destination_inventory,
                    store,
                    confirmed.actions(),
                );
            }
        };
        // Persist the selected resolution and every collision-safe generated
        // path before the first filesystem mutation. These rows intentionally
        // start unresolved: a crash before the action boundary must remain
        // visible and cannot be mistaken for a completed resolution.
        let planned_report_items = resolution_planned_report_items(&confirmed, &executor);
        store.record_mirror_resolutions(run_id, &planned_report_items)?;
        let execution = {
            let mut durable_executor = JournaledResolutionExecutor {
                inner: &mut executor,
                store,
                run_id,
                action_ids: &action_ids,
            };
            confirmed.execute(&mut durable_executor)
        };
        let report_items = resolution_report_items(&confirmed, &execution, &executor);
        store.record_mirror_resolutions(run_id, &report_items)?;
        let report = self.reconcile_run_with_resolutions(
            run_id,
            profile,
            &inventory,
            &destination_inventory,
            store,
            confirmed.actions(),
        )?;
        self.cleanup_partials_after_resolution(profile, &report)?;
        Ok(report)
    }

    /// Execute a Sync Run with exactly one SSH peer. Remote probing and
    /// transfer are injected so the core remains independent of a network
    /// runtime, while the safety lifecycle stays centralized here.
    pub fn execute_ssh<B, C, F>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        precheck: &crate::RemotePrecheckPermit,
        backend: &B,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        B: SshRunBackend,
        C: FnOnce(&ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        self.execute_ssh_with_authorizations(
            run_id,
            profile,
            credential,
            host_permit,
            precheck,
            AuthorizationSnapshot::default(),
            backend,
            confirm,
            store,
            should_cancel,
        )
    }

    /// Execute an SSH run with the immutable authorization snapshot selected
    /// for this run. Permanent Removal is never available without its
    /// separate authorization; remote Trash remains the default recoverable
    /// path for Safe Delete.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_ssh_with_authorizations<B, C, F>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        precheck: &crate::RemotePrecheckPermit,
        authorizations: AuthorizationSnapshot,
        backend: &B,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        B: SshRunBackend,
        C: FnOnce(&ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        let _scope_lock = self.acquire_ssh_scope(run_id, profile)?;
        let (_remote_side, remote_peer) = ssh_peer_for_profile(profile)?;
        let (_, remote_request) = RemotePrecheckRequest::from_profile(profile)
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        validate_ssh_permits(remote_peer, credential, host_permit, precheck, remote_request)?;
        let _initial_remote_permit =
            self.refresh_ssh_precheck(profile, credential, host_permit, backend)?;
        let analysis = self.analyze_ssh(profile, credential, host_permit, backend)?;
        let refreshed = self.analyze_ssh(profile, credential, host_permit, backend)?;
        let confirmed = analysis.confirm_refreshed(profile, &refreshed)?;
        if !confirm(&confirmed) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        let remote_permit = self.refresh_ssh_precheck(profile, credential, host_permit, backend)?;
        self.execute_ssh_confirmed(
            run_id,
            &confirmed,
            authorizations,
            credential,
            host_permit,
            &remote_permit,
            backend,
            store,
            should_cancel,
        )
    }

    /// Resume an incomplete SSH run only after open boundaries are classified
    /// and both remote Fresh Analysis and explicit confirmation succeed again.
    pub fn resume_ssh<B, C, F>(
        &self,
        run_id: RunId,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        precheck: &crate::RemotePrecheckPermit,
        backend: &B,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        B: SshRunBackend,
        C: FnOnce(&ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        let report = store.load_report(run_id)?;
        if matches!(report.status(), RunReportStatus::Completed | RunReportStatus::ReviewCleared)
        {
            return Err(WorkflowError::InvalidRun(
                "only an incomplete SSH run can be resumed".to_owned(),
            ));
        }
        if report.status() == RunReportStatus::RecoveryReview {
            return Err(WorkflowError::InvalidRun(
                "Recovery Review must be explicitly resolved before an SSH run can resume"
                    .to_owned(),
            ));
        }
        let profile = report.snapshot().profile().clone();
        let next_run_id = store.next_run_id()?;
        let _scope_lock = self.acquire_ssh_scope(next_run_id, &profile)?;
        let (_remote_side, remote_peer) = ssh_peer_for_profile(&profile)?;
        let (_, remote_request) = RemotePrecheckRequest::from_profile(&profile)
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        validate_ssh_permits(
            remote_peer,
            credential,
            host_permit,
            precheck,
            remote_request,
        )?;
        self.classify_ssh_open_actions(run_id, &report, store)?;
        let reopened = store.load_report(run_id)?;
        if reopened.status() == RunReportStatus::RecoveryReview {
            return Err(WorkflowError::InvalidRun(
                "Recovery Review must be explicitly resolved before an SSH run can resume"
                    .to_owned(),
            ));
        }
        let profile = reopened.snapshot().profile().clone();
        let authorizations = reopened.snapshot().authorizations();
        let _initial_remote_permit =
            self.refresh_ssh_precheck(&profile, credential, host_permit, backend)?;
        let analysis = self.analyze_ssh(&profile, credential, host_permit, backend)?;
        let refreshed = self.analyze_ssh(&profile, credential, host_permit, backend)?;
        let confirmed = analysis.confirm_refreshed(&profile, &refreshed)?;
        if !confirm(&confirmed) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        let remote_permit = self.refresh_ssh_precheck(&profile, credential, host_permit, backend)?;
        self.execute_ssh_confirmed(
            next_run_id,
            &confirmed,
            authorizations,
            credential,
            host_permit,
            &remote_permit,
            backend,
            store,
            should_cancel,
        )
    }

    fn acquire_ssh_scope(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
    ) -> Result<PeerScopeLock, WorkflowError> {
        self.scope_locks
            .acquire(
                ScopeLockOwner::new(profile.name(), run_id),
                [
                    PeerScope::for_peer(profile.peer_a()),
                    PeerScope::for_peer(profile.peer_b()),
                ],
            )
            .map_err(|error| {
                WorkflowError::InvalidRun(format!("could not acquire peer scope lock: {error:?}"))
            })
    }

    fn analyze_ssh<B>(
        &self,
        profile: &crate::SyncProfile,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        backend: &B,
    ) -> Result<FreshAnalysis, WorkflowError>
    where
        B: SshRunBackend,
    {
        let specification = ProcessSpecification::from_profile(profile)
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        let exclusions: Vec<String> = specification
            .exclusions()
            .map(ToOwned::to_owned)
            .collect();
        let (source_side, destination_side) = if profile.mode() == crate::SyncMode::Mirror {
            (crate::PeerSide::PeerA, crate::PeerSide::PeerB)
        } else {
            let source_side = crate::PeerSide::from(profile.source());
            (source_side, source_side.opposite())
        };
        let source_inventory = self.ssh_inventory(
            peer_for_side(profile, source_side),
            credential,
            host_permit,
            &exclusions,
            backend,
        )?;
        let destination_inventory = self.ssh_inventory(
            peer_for_side(profile, destination_side),
            credential,
            host_permit,
            &exclusions,
            backend,
        )?;
        FreshAnalysis::from_inventories(
            profile,
            specification,
            source_inventory,
            destination_inventory,
        )
        .map_err(WorkflowError::from)
    }

    fn refresh_ssh_precheck<B>(
        &self,
        profile: &crate::SyncProfile,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        backend: &B,
    ) -> Result<crate::RemotePrecheckPermit, WorkflowError>
    where
        B: SshRunBackend,
    {
        let (peer, request) = RemotePrecheckRequest::from_profile(profile)
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        let observed = crate::SshHostIdentityProbe::probe(backend, &peer).map_err(|error| {
            WorkflowError::Ssh(SshRunError::Precheck(format!(
                "SSH host identity could not be reverified: {error}"
            )))
        })?;
        if &observed != host_permit.fingerprint() {
            return Err(WorkflowError::Ssh(SshRunError::Precheck(
                "SSH host fingerprint changed; review the server identity before continuing"
                    .to_owned(),
            )));
        }
        SshRemotePrecheck::check(&peer, credential, host_permit, &request, backend)
            .map_err(|error| WorkflowError::Ssh(SshRunError::Precheck(error.to_string())))?
            .require_passed()
            .map_err(|blocked| {
                WorkflowError::Ssh(SshRunError::Precheck(format!(
                    "remote precheck remained blocked: {:?}",
                    blocked.blockers()
                )))
            })
    }

    fn ssh_inventory<B>(
        &self,
        peer: &crate::Peer,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        exclusions: &[String],
        backend: &B,
    ) -> Result<crate::SourceInventory, WorkflowError>
    where
        B: SshRunBackend,
    {
        if let Some(ssh_peer) = peer.ssh_peer() {
            backend
                .inventory(ssh_peer, credential, host_permit, exclusions)
                .map_err(WorkflowError::Ssh)
        } else {
            FreshAnalysis::collect_local_inventory(peer, exclusions).map_err(WorkflowError::from)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_ssh_confirmed<B, F>(
        &self,
        run_id: RunId,
        confirmed: &ConfirmedPlan,
        authorizations: AuthorizationSnapshot,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        precheck: &crate::RemotePrecheckPermit,
        backend: &B,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        B: SshRunBackend,
        F: Fn() -> bool,
    {
        let plan = confirmed.plan();
        plan.validate()
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        if plan.specification().options().deletion_method()
            == Some(crate::DeletionMethod::PermanentRemoval)
            && !authorizations.allow_unattended_permanent_removal()
        {
            return Err(WorkflowError::InvalidRun(
                "SSH Permanent Removal requires separate explicit authorization"
                    .to_owned(),
            ));
        }
        let snapshot = RunSnapshot::from_profile_with_volume_identities(
            run_id,
            confirmed.profile(),
            authorizations,
            None,
            None,
        )?;
        store.begin_run(&snapshot)?;
        let inventory = SourceInventorySnapshot::from_inventory(plan.source_inventory());
        let destination_inventory =
            SourceInventorySnapshot::from_inventory(plan.destination_inventory());
        store.record_source_inventory(run_id, &inventory)?;
        if confirmed.profile().mode() == crate::SyncMode::Mirror {
            store.record_destination_inventory(run_id, &destination_inventory)?;
        }
        for action in plan.actions() {
            store.append_event(
                run_id,
                JournalEvent::Planned {
                    action: ssh_plan_record(plan, action)?,
                },
            )?;
        }

        let cancel = &should_cancel as &dyn Fn() -> bool;
        let mut verified_transfers = BTreeMap::new();
        for (index, action) in plan.actions().iter().enumerate() {
            if cancel() {
                self.cancel_remaining(run_id, &plan.actions()[index..], store)?;
                break;
            }
            if matches!(
                self.execute_ssh_action(
                    run_id,
                    confirmed.profile(),
                    plan,
                    action,
                    credential,
                    host_permit,
                    precheck,
                    backend,
                    store,
                    cancel,
                    &mut verified_transfers,
                )?,
                ActionDisposition::Stop
            ) {
                self.cancel_remaining(run_id, &plan.actions()[index + 1..], store)?;
                break;
            }
        }

        self.reconcile_ssh_run(
            run_id,
            confirmed.profile(),
            &inventory,
            &destination_inventory,
            credential,
            host_permit,
            backend,
            store,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_ssh_action<B>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        plan: &OneWayPlan,
        action: &PlanAction,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        precheck: &crate::RemotePrecheckPermit,
        backend: &B,
        store: &mut RunEvidenceStore,
        should_cancel: &dyn Fn() -> bool,
        verified_transfers: &mut BTreeMap<PathBuf, SshTransferEvidence>,
    ) -> Result<ActionDisposition, WorkflowError>
    where
        B: SshRunBackend,
    {
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
        let source_peer = peer_for_side(profile, action.source_side());
        let destination_peer = peer_for_side(profile, action.source_side().opposite());
        if action.kind() == PlanActionKind::RemoveSourceAfterVerification
            && !source_peer.is_ssh()
        {
            store.append_event(
                run_id,
                JournalEvent::Deferred {
                    action_id: action.action_id(),
                },
            )?;
            return Ok(ActionDisposition::Continue);
        }
        if !matches!(
            action.kind(),
            PlanActionKind::CopyToDestination
                | PlanActionKind::OverwriteDestination
                | PlanActionKind::RemoveSourceAfterVerification
        ) {
            store.append_event(
                run_id,
                JournalEvent::Deferred {
                    action_id: action.action_id(),
                },
            )?;
            return Ok(ActionDisposition::Continue);
        }
        let remote_peer = source_peer
            .ssh_peer()
            .or_else(|| destination_peer.ssh_peer())
            .ok_or_else(|| WorkflowError::InvalidRun("SSH action has no remote endpoint".to_owned()))?;
        let request = crate::SshTransferRequest::new(
            run_id,
            plan.specification(),
            action,
            source_peer,
            destination_peer,
            remote_peer,
            credential,
            host_permit,
            precheck,
            self.transfer.supervisor(),
        );
        match action.kind() {
            PlanActionKind::CopyToDestination | PlanActionKind::OverwriteDestination => {
                let evidence = match self.run_ssh_transfer(
                    plan.specification().options().retry_policy(),
                    &request,
                    backend,
                    should_cancel,
                ) {
                    Ok((evidence, progress)) => {
                        self.persist_progress(run_id, action.action_id(), progress, store)?;
                        evidence
                    }
                    Err((error, progress)) => {
                        self.persist_progress(run_id, action.action_id(), progress, store)?;
                        return self.record_ssh_failure(run_id, action, error, store);
                    }
                };
                let item = ssh_source_item(plan, action)?;
                if !evidence.matches_request(&request)
                    || !evidence.matches_inventory(item, plan.specification().options().metadata())
                {
                    store.append_event(
                        run_id,
                        JournalEvent::Unresolved {
                            action_id: action.action_id(),
                            reason: ActionReason::VerificationMismatch,
                        },
                    )?;
                    return Ok(ActionDisposition::Continue);
                }
                if item.item_type() == crate::ItemType::RegularFile {
                    let proof = evidence.recovery_evidence(current_unix_nanos()).ok_or_else(|| {
                        WorkflowError::InvalidRun(
                            "a verified regular-file SSH transfer has no content evidence"
                                .to_owned(),
                        )
                    })?;
                    store.append_event(
                        run_id,
                        JournalEvent::TransferVerified {
                            action_id: action.action_id(),
                            evidence: proof,
                            metadata_verified: evidence.metadata_verified(),
                        },
                    )?;
                }
                verified_transfers.insert(action.relative_path().to_path_buf(), evidence);
                store.append_event(
                    run_id,
                    JournalEvent::Completed {
                        action_id: action.action_id(),
                    },
                )?;
                Ok(ActionDisposition::Continue)
            }
            PlanActionKind::RemoveSourceAfterVerification => {
                let evidence = if let Some(evidence) =
                    verified_transfers.remove(action.relative_path())
                {
                    evidence
                } else {
                    match self.run_ssh_transfer(
                        plan.specification().options().retry_policy(),
                        &request,
                        backend,
                        should_cancel,
                    ) {
                        Ok((evidence, progress)) => {
                            self.persist_progress(run_id, action.action_id(), progress, store)?;
                            evidence
                        }
                        Err((error, progress)) => {
                            self.persist_progress(run_id, action.action_id(), progress, store)?;
                            return self.record_ssh_failure(run_id, action, error, store);
                        }
                    }
                };
                let item = ssh_source_item(plan, action)?;
                if !evidence.matches_request(&request)
                    || !evidence.matches_inventory(item, plan.specification().options().metadata())
                {
                    store.append_event(
                        run_id,
                        JournalEvent::Unresolved {
                            action_id: action.action_id(),
                            reason: ActionReason::VerificationMismatch,
                        },
                    )?;
                    return Ok(ActionDisposition::Continue);
                }
                let proof = evidence.recovery_evidence(current_unix_nanos()).ok_or_else(|| {
                    WorkflowError::InvalidRun(
                        "a verified SSH removal has no source or destination evidence".to_owned(),
                    )
                })?;
                store.append_event(
                    run_id,
                    JournalEvent::TransferVerified {
                        action_id: action.action_id(),
                        evidence: proof.clone(),
                        metadata_verified: evidence.metadata_verified(),
                    },
                )?;
                let Some(DeletionMethod::Trash) = request.deletion_method() else {
                    store.append_event(
                        run_id,
                        JournalEvent::Unresolved {
                            action_id: action.action_id(),
                            reason: ActionReason::DestinationUnavailable,
                        },
                    )?;
                    return Ok(ActionDisposition::Continue);
                };
                if request.remote_recovery_target().is_none() {
                    return self.record_ssh_failure(
                        run_id,
                        action,
                        SshRunError::RemoteRecoveryUnavailable,
                        store,
                    );
                }
                store.append_event(
                    run_id,
                    JournalEvent::ProofBoundary {
                        action_id: action.action_id(),
                        deletion_method: DeletionMethod::Trash,
                        evidence: proof,
                        metadata_verified: evidence.metadata_verified(),
                    },
                )?;
                if should_cancel() {
                    store.append_event(
                        run_id,
                        JournalEvent::Cancelled {
                            action_id: action.action_id(),
                        },
                    )?;
                    return Ok(ActionDisposition::Stop);
                }
                store.append_event(
                    run_id,
                    JournalEvent::RemovalStarted {
                        action_id: action.action_id(),
                        deletion_method: DeletionMethod::Trash,
                    },
                )?;
                match backend.recover_source(&request, &evidence, should_cancel) {
                    Ok(recovery) => {
                        if Self::validate_remote_recovery(&request, &evidence, &recovery) {
                            store.append_event(
                                run_id,
                                JournalEvent::RemovalCompleted {
                                    action_id: action.action_id(),
                                    result: crate::RemovalResult::new(
                                        DeletionMethod::Trash,
                                        recovery,
                                    ),
                                },
                            )?;
                            Ok(ActionDisposition::Continue)
                        } else {
                            self.record_ssh_failure(
                                run_id,
                                action,
                                SshRunError::RemoteRecoveryAmbiguous {
                                    boundary: SshRecoveryBoundary::RecoveryStarted,
                                    evidence: Some(recovery),
                                },
                                store,
                            )
                        }
                    }
                    Err(error) => self.record_ssh_failure(run_id, action, error, store),
                }
            }
            PlanActionKind::RemoveDestination => unreachable!(),
        }
    }

    fn run_ssh_transfer<B>(
        &self,
        policy: RetryPolicy,
        request: &crate::SshTransferRequest<'_>,
        backend: &B,
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<(SshTransferEvidence, Vec<u64>), (SshRunError, Vec<u64>)>
    where
        B: SshRunBackend,
    {
        let mut progress = Vec::new();
        for attempt in 0..policy.max_attempts() {
            if should_cancel() {
                return Err((SshRunError::Cancelled, progress));
            }
            let mut report_progress = |bytes| progress.push(bytes);
            match backend.transfer(request, should_cancel, &mut report_progress) {
                Ok(evidence) => return Ok((evidence, progress)),
                Err(error) if error.is_retryable() && attempt + 1 < policy.max_attempts() => {
                    let delay = policy
                        .initial_delay()
                        .checked_mul(u32::from(attempt + 1))
                        .unwrap_or(Duration::MAX);
                    if !sleep_interruptibly(delay, should_cancel) {
                        return Err((SshRunError::Cancelled, progress));
                    }
                }
                Err(error) => return Err((error, progress)),
            }
        }
        unreachable!("a validated retry policy always has at least one attempt")
    }

    fn record_ssh_failure(
        &self,
        run_id: RunId,
        action: &PlanAction,
        error: SshRunError,
        store: &mut RunEvidenceStore,
    ) -> Result<ActionDisposition, WorkflowError> {
        if matches!(error, SshRunError::Cancelled) {
            store.append_event(
                run_id,
                JournalEvent::Cancelled {
                    action_id: action.action_id(),
                },
            )?;
            return Ok(ActionDisposition::Stop);
        }
        if error.requires_recovery_review() {
            let evidence = match &error {
                SshRunError::RemoteRecoveryFailed {
                    evidence: Some(evidence), ..
                }
                | SshRunError::RemoteRecoveryAmbiguous {
                    evidence: Some(evidence), ..
                } => evidence.clone(),
                _ => empty_recovery_evidence(),
            };
            store.append_event(
                run_id,
                JournalEvent::RecoveryReview {
                    action_id: action.action_id(),
                    reason: error.action_reason(),
                    evidence,
                },
            )?;
            return Ok(ActionDisposition::Stop);
        }
        let unresolved = matches!(
            error,
            SshRunError::RemoteVerificationUnavailable { .. }
                | SshRunError::RemoteVerificationMismatch { .. }
                | SshRunError::SourceChanged
                | SshRunError::MetadataMismatch
        );
        let event = if unresolved {
            JournalEvent::Unresolved {
                action_id: action.action_id(),
                reason: error.action_reason(),
            }
        } else {
            JournalEvent::Failed {
                action_id: action.action_id(),
                reason: error.action_reason(),
            }
        };
        store.append_event(run_id, event)?;
        Ok(ActionDisposition::Continue)
    }

    fn validate_remote_recovery(
        request: &crate::SshTransferRequest<'_>,
        transfer: &SshTransferEvidence,
        recovery: &RecoveryEvidence,
    ) -> bool {
        let Some(expected_target) = request.remote_recovery_target() else {
            return false;
        };
        if !transfer.source_stability_verified() {
            return false;
        }
        let Some(expected_transfer) = transfer.recovery_evidence(0) else {
            return false;
        };
        let source_path = request
            .remote_peer()
            .remote_path()
            .join(request.action().relative_path());
        if expected_target == source_path
            || expected_target.starts_with(&source_path)
            || source_path.starts_with(&expected_target)
        {
            return false;
        }
        if recovery.source_present()
            || !recovery.destination_present()
            || !recovery.recovery_present()
            || recovery.recovery_target() != Some(expected_target.as_path())
            || recovery.source_size() != expected_transfer.source_size()
            || recovery.destination_size() != expected_transfer.destination_size()
            || recovery.source_sha256() != expected_transfer.source_sha256()
            || recovery.destination_sha256() != expected_transfer.destination_sha256()
        {
            return false;
        }
        let Some(source) = transfer.source() else {
            return false;
        };
        let Some(source_identity) = transfer.source_identity() else {
            return false;
        };
        if recovery.recovery_size() != Some(source.size()) {
            return false;
        }
        if recovery.recovery_sha256() != Some(source.sha256()) {
            return false;
        }
        let Some(provenance) = recovery.provenance() else {
            return false;
        };
        let expected_peer = format!(
            "{}@{}:{}",
            request.remote_peer().username(),
            request.remote_peer().server(),
            request.remote_peer().port()
        );
        let Some(source_metadata) = transfer.source_metadata() else {
            return false;
        };
        let content_matches = match (provenance.content(), transfer.source()) {
            (Some(provenance), Some(source)) => provenance == source,
            (None, None) => true,
            _ => false,
        };
        provenance.peer() == expected_peer
            && provenance.original_root() == request.remote_peer().remote_path()
            && provenance.relative_path() == request.action().relative_path()
            && provenance.run_id() == request.run_id()
            && provenance.item_type() == source_metadata.item_type()
            && provenance.source_identity() == Some(source_identity)
            && content_matches
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_ssh_run<B>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        inventory: &SourceInventorySnapshot,
        destination_inventory: &SourceInventorySnapshot,
        credential: &crate::ResolvedSshCredential,
        host_permit: &crate::SshHostTrustPermit,
        backend: &B,
        store: &mut RunEvidenceStore,
    ) -> Result<RunReport, WorkflowError>
    where
        B: SshRunBackend,
    {
        let journal = store.load_journal(run_id)?;
        let current = self.analyze_ssh(profile, credential, host_permit, backend);
        let reconciliation = match current {
            Ok(current) if profile.mode() == crate::SyncMode::Mirror => {
                CompletionReconciliation::reconcile_mirror(
                    profile,
                    inventory,
                    destination_inventory,
                    &current,
                    &journal,
                )
            }
            Ok(current) => CompletionReconciliation::reconcile(profile, inventory, &current, &journal),
            Err(_) => CompletionReconciliation::unavailable(
                profile,
                inventory,
                &journal,
                &AnalysisError::RootUnavailable {
                    peer: "SSH peer".to_owned(),
                    path: profile.peer_a().root().to_path_buf(),
                },
            ),
        };
        store.record_reconciliation(run_id, &reconciliation)?;
        Ok(store.load_report(run_id)?)
    }

    fn classify_ssh_open_actions(
        &self,
        run_id: RunId,
        report: &RunReport,
        store: &mut RunEvidenceStore,
    ) -> Result<(), WorkflowError> {
        for item in report.items() {
            if !matches!(item.outcome(), ActionOutcome::InProgress) {
                continue;
            }
            if let Some(evidence) = item.journal().transfer_evidence() {
                store.append_event(
                    run_id,
                    JournalEvent::RecoveryReview {
                        action_id: item.action_id(),
                        reason: ActionReason::InterruptedBoundary,
                        evidence: evidence.clone(),
                    },
                )?;
            } else {
                store.append_event(
                    run_id,
                    JournalEvent::Interrupted {
                        action_id: item.action_id(),
                    },
                )?;
            }
        }
        Ok(())
    }

    /// Execute only a plan that has passed the Fresh Analysis confirmation
    /// gate. Every action is planned durably before the first filesystem
    /// mutation, and cancellation settles the remaining planned actions.
    fn execute_confirmed_with_authorizations<F>(
        &self,
        run_id: RunId,
        confirmed: &ConfirmedPlan,
        authorizations: AuthorizationSnapshot,
        store: &mut RunEvidenceStore,
        should_cancel: F,
        source_volume_identity: Option<crate::VolumeIdentity>,
        destination_volume_identity: Option<crate::VolumeIdentity>,
    ) -> Result<RunReport, WorkflowError>
    where
        F: Fn() -> bool,
    {
        let plan = confirmed.plan();
        plan.validate()
            .map_err(|error| WorkflowError::InvalidRun(error.to_string()))?;
        let (peer_a_volume_identity, peer_b_volume_identity) = orient_volume_identities(
            confirmed.profile(),
            source_volume_identity,
            destination_volume_identity,
        );
        let snapshot = RunSnapshot::from_profile_with_volume_identities(
            run_id,
            confirmed.profile(),
            authorizations,
            peer_a_volume_identity,
            peer_b_volume_identity,
        )?;
        store.begin_run(&snapshot)?;
        let inventory = SourceInventorySnapshot::from_inventory(plan.source_inventory());
        let destination_inventory = SourceInventorySnapshot::from_inventory(plan.destination_inventory());
        store.record_source_inventory(run_id, &inventory)?;
        if confirmed.profile().mode() == crate::SyncMode::Mirror {
            store.record_destination_inventory(run_id, &destination_inventory)?;
        }
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

        self.reconcile_run(
            run_id,
            confirmed.profile(),
            &inventory,
            &destination_inventory,
            store,
        )
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
        self.resume_with_replacement_confirmation(
            run_id,
            probe,
            |_| false,
            confirm,
            store,
            should_cancel,
        )
    }

    /// Resume an incomplete run, optionally accepting a different volume only
    /// after a separate explicit replacement confirmation. The ordinary
    /// `resume` entry point always rejects replacement volumes.
    pub fn resume_with_replacement_confirmation<P, A, C, F>(
        &self,
        run_id: RunId,
        probe: &P,
        authorize_replacement: A,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        A: FnOnce(&PrecheckBlocked) -> bool,
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
        let authorizations = report.snapshot().authorizations();
        let expected_source_volume_identity = report
            .snapshot()
            .volume_identity(crate::PeerSide::from(profile.source()));
        let source_side = if profile.mode() == crate::SyncMode::Mirror {
            crate::PeerSide::PeerA
        } else {
            crate::PeerSide::from(profile.source())
        };
        let expected_destination_volume_identity = report
            .snapshot()
            .volume_identity(source_side.opposite());
        let next_run_id = store.next_run_id()?;
        let mut authorize_replacement = Some(authorize_replacement);
        let lease = match self.acquire_precheck_with_expected_volumes(
            next_run_id,
            &profile,
            probe,
            expected_source_volume_identity,
            expected_destination_volume_identity,
            true,
            false,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                let replacement_authorized = match &error {
                    WorkflowError::Precheck(PrecheckFailure::Blocked(blocked))
                        if blocked.is_replacement_only() => authorize_replacement
                        .take()
                        .is_some_and(|authorize| authorize(blocked)),
                    _ => false,
                };
                if replacement_authorized {
                    match self.acquire_precheck_with_expected_volumes(
                        next_run_id,
                        &profile,
                        probe,
                        expected_source_volume_identity,
                        expected_destination_volume_identity,
                        true,
                        true,
                    ) {
                        Ok(lease) => lease,
                        Err(error) => {
                            self.persist_blocked_with_authorizations(
                                next_run_id,
                                &profile,
                                store,
                                &error,
                                expected_source_volume_identity,
                                expected_destination_volume_identity,
                                authorizations,
                            )?;
                            return Err(error);
                        }
                    }
                } else {
                    self.persist_blocked_with_authorizations(
                        next_run_id,
                        &profile,
                        store,
                        &error,
                        expected_source_volume_identity,
                        expected_destination_volume_identity,
                        authorizations,
                    )?;
                    return Err(error);
                }
            }
        };
        let source_volume_identity = lease.result().source_volume_identity();
        let destination_volume_identity = lease.result().destination_volume_identity();
        self.classify_open_actions(run_id, &profile, &report, store)?;
        let reopened = store.load_report(run_id)?;
        if reopened.status() == RunReportStatus::RecoveryReview {
            return Err(WorkflowError::InvalidRun(
                "Recovery Review must be explicitly resolved before a new run can resume"
                    .to_owned(),
            ));
        }
        let profile = reopened.snapshot().profile().clone();
        let authorizations = reopened.snapshot().authorizations();
        let analysis = FreshAnalysis::analyze(&profile)?;
        let confirmed = analysis.confirm(&profile)?;
        if !confirm(&confirmed) {
            return Err(WorkflowError::ConfirmationRequired);
        }
        if let Err(error) = self.recheck_precheck(
            &profile,
            probe,
            source_volume_identity,
            destination_volume_identity,
            true,
            false,
        ) {
            self.persist_blocked_with_authorizations(
                next_run_id,
                &profile,
                store,
                &error,
                expected_source_volume_identity,
                expected_destination_volume_identity,
                authorizations,
            )?;
            return Err(error);
        }
        let report = self.execute_confirmed_with_authorizations(
            next_run_id,
            &confirmed,
            authorizations,
            store,
            should_cancel,
            source_volume_identity,
            destination_volume_identity,
        )?;
        self.cleanup_partials_after_success(&confirmed, &report)?;
        Ok(report)
    }

    fn acquire_precheck<P: PrecheckProbe>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        probe: &P,
    ) -> Result<PrecheckLease, WorkflowError> {
        self.acquire_precheck_with_expected_volumes(
            run_id, profile, probe, None, None, false, false,
        )
    }

    fn acquire_precheck_with_expected_volumes<P: PrecheckProbe>(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        probe: &P,
        expected_source_volume_identity: Option<crate::VolumeIdentity>,
        expected_destination_volume_identity: Option<crate::VolumeIdentity>,
        require_recorded_identity: bool,
        allow_replacement: bool,
    ) -> Result<PrecheckLease, WorkflowError> {
        let owner = ScopeLockOwner::new(profile.name(), run_id);
        let result = if require_recorded_identity {
            RunPrecheck::check_and_lock_for_resume_with_replacement(
                profile,
                probe,
                &self.scope_locks,
                owner,
                expected_source_volume_identity,
                expected_destination_volume_identity,
                allow_replacement,
            )
        } else {
            RunPrecheck::check_and_lock_with_expected_volumes(
                profile,
                probe,
                &self.scope_locks,
                owner,
                expected_source_volume_identity,
                expected_destination_volume_identity,
            )
        };
        result.map_err(WorkflowError::Precheck)
    }

    fn persist_blocked_with_authorizations(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        store: &mut RunEvidenceStore,
        error: &WorkflowError,
        source_volume_identity: Option<crate::VolumeIdentity>,
        destination_volume_identity: Option<crate::VolumeIdentity>,
        authorizations: AuthorizationSnapshot,
    ) -> Result<(), WorkflowError> {
        let (peer_a_volume_identity, peer_b_volume_identity) = orient_volume_identities(
            profile,
            source_volume_identity,
            destination_volume_identity,
        );
        let snapshot = RunSnapshot::from_profile_with_volume_identities(
            run_id,
            profile,
            authorizations,
            peer_a_volume_identity,
            peer_b_volume_identity,
        )?;
        store.begin_run(&snapshot)?;
        store.mark_blocked(run_id, &error.to_string())?;
        Ok(())
    }

    fn reconcile_run(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        inventory: &SourceInventorySnapshot,
        destination_inventory: &SourceInventorySnapshot,
        store: &mut RunEvidenceStore,
    ) -> Result<RunReport, WorkflowError> {
        self.reconcile_run_with_resolutions(
            run_id,
            profile,
            inventory,
            destination_inventory,
            store,
            &[],
        )
    }

    fn reconcile_run_with_resolutions(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        inventory: &SourceInventorySnapshot,
        destination_inventory: &SourceInventorySnapshot,
        store: &mut RunEvidenceStore,
        resolutions: &[ConflictResolutionAction],
    ) -> Result<RunReport, WorkflowError> {
        self.reconcile_run_with_resolutions_and_deletions(
            run_id,
            profile,
            inventory,
            destination_inventory,
            store,
            resolutions,
            &[],
        )
    }

    /// Reconcile a previously journaled Mirror deletion result against the
    /// final two-peer state. This keeps an explicitly completed counterpart
    /// deletion from being mistaken for an unexplained missing item.
    pub fn reconcile_mirror_deletions(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        inventory: &SourceInventorySnapshot,
        destination_inventory: &SourceInventorySnapshot,
        deletions: &[MirrorDeletionResult],
        store: &mut RunEvidenceStore,
    ) -> Result<RunReport, WorkflowError> {
        if profile.mode() != crate::SyncMode::Mirror {
            return Err(WorkflowError::InvalidRun(
                "Mirror deletion reconciliation requires Mirror Sync".to_owned(),
            ));
        }
        self.reconcile_run_with_resolutions_and_deletions(
            run_id,
            profile,
            inventory,
            destination_inventory,
            store,
            &[],
            deletions,
        )
    }

    /// Persist the action boundaries for explicit, already-authorized Mirror
    /// deletion outcomes and reconcile the final two-peer state. The actual
    /// filesystem deletion is supplied by the typed deletion executor; this
    /// method owns its journal and completion evidence.
    pub fn record_mirror_deletion_results(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        inventory: &SourceInventorySnapshot,
        destination_inventory: &SourceInventorySnapshot,
        deletions: &[MirrorDeletionResult],
        store: &mut RunEvidenceStore,
    ) -> Result<RunReport, WorkflowError> {
        if profile.mode() != crate::SyncMode::Mirror {
            return Err(WorkflowError::InvalidRun(
                "Mirror deletion results require Mirror Sync".to_owned(),
            ));
        }
        // Take a fresh observation before marking any typed deletion as
        // completed. The result object records what the authorized executor
        // attempted; this observation is the independent absence boundary
        // that keeps a stale or malformed completion from clearing review.
        let current = FreshAnalysis::analyze(profile).ok();
        let next_action_id = store
            .load_journal(run_id)?
            .into_iter()
            .map(|entry| entry.plan().action_id())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        for (offset, deletion) in deletions.iter().enumerate() {
            let action_id = next_action_id.saturating_add(offset as crate::ActionId);
            let affected_inventory = match deletion.affected_peer() {
                crate::PeerSide::PeerA => inventory,
                crate::PeerSide::PeerB => destination_inventory,
            };
            let item = affected_inventory.item(deletion.relative_path()).ok_or_else(|| {
                WorkflowError::InvalidRun(format!(
                    "deletion result {:?} is outside the affected inventory",
                    deletion.relative_path()
                ))
            })?;
            store.append_event(
                run_id,
                JournalEvent::Planned {
                    action: PlanRecord::new(
                        action_id,
                        deletion.relative_path().to_path_buf(),
                        PlanActionKind::RemoveDestination,
                        deletion.affected_peer(),
                        (item.item_type() == crate::ItemType::RegularFile)
                            .then_some(item.size()),
                        PreActionState::new(
                            item.item_type(),
                            item.size(),
                            item.modified_at_unix_nanos(),
                            None,
                            item.content_fingerprint().copied(),
                        ),
                    ),
                },
            )?;
            store.append_event(run_id, JournalEvent::Started { action_id })?;
            match deletion.outcome() {
                crate::MirrorDeletionOutcome::Completed => {
                    let independently_verified = current.as_ref().is_some_and(|current| {
                        current.source_inventory().item(deletion.relative_path()).is_none()
                            && current
                                .destination_inventory()
                                .item(deletion.relative_path())
                                .is_none()
                    });
                    if independently_verified && !deletion.requires_review() {
                        store.append_event(run_id, JournalEvent::Completed { action_id })?;
                    } else {
                        store.append_event(
                            run_id,
                            JournalEvent::Unresolved {
                                action_id,
                                reason: if current.is_some() {
                                    ActionReason::VerificationMismatch
                                } else {
                                    ActionReason::FilesystemUncertain
                                },
                            },
                        )?;
                    }
                }
                crate::MirrorDeletionOutcome::FailedPreserved => {
                    store.append_event(
                        run_id,
                        JournalEvent::Unresolved {
                            action_id,
                            reason: ActionReason::TransferFailed,
                        },
                    )?;
                }
                crate::MirrorDeletionOutcome::Deferred => {
                    store.append_event(run_id, JournalEvent::Deferred { action_id })?;
                }
            }
        }
        self.reconcile_mirror_deletions(
            run_id,
            profile,
            inventory,
            destination_inventory,
            deletions,
            store,
        )
    }

    fn reconcile_run_with_resolutions_and_deletions(
        &self,
        run_id: RunId,
        profile: &crate::SyncProfile,
        inventory: &SourceInventorySnapshot,
        destination_inventory: &SourceInventorySnapshot,
        store: &mut RunEvidenceStore,
        resolutions: &[ConflictResolutionAction],
        deletions: &[MirrorDeletionResult],
    ) -> Result<RunReport, WorkflowError> {
        let journal = store.load_journal(run_id)?;
        let (reconciliation, current_analysis) = match FreshAnalysis::analyze(profile) {
            Ok(current) => {
                let reconciliation = if profile.mode() == crate::SyncMode::Mirror {
                    CompletionReconciliation::reconcile_mirror_with_resolutions_and_deletions(
                        profile,
                        inventory,
                        destination_inventory,
                        &current,
                        &journal,
                        resolutions,
                        deletions,
                    )
                } else {
                    CompletionReconciliation::reconcile(profile, inventory, &current, &journal)
                };
                (reconciliation, Some(current))
            }
            Err(error) => {
                (
                    CompletionReconciliation::unavailable(profile, inventory, &journal, &error),
                    None,
                )
            }
        };
        store.record_reconciliation(run_id, &reconciliation)?;
        if profile.mode() == crate::SyncMode::Mirror {
            if let Some(current) = current_analysis.as_ref() {
                let current_peer_a = SourceInventorySnapshot::from_inventory(current.source_inventory());
                let current_peer_b =
                    SourceInventorySnapshot::from_inventory(current.destination_inventory());
                let baseline = SyncBaseline::from_reconciled_inventories(
                    profile.name(),
                    &current_peer_a,
                    &current_peer_b,
                    &journal,
                    &reconciliation,
                    profile.options().metadata,
                );
                store.update_mirror_baseline(&baseline)?;
            }
        }
        Ok(store.load_report(run_id)?)
    }

    fn recheck_precheck<P: PrecheckProbe>(
        &self,
        profile: &crate::SyncProfile,
        probe: &P,
        expected_source_volume_identity: Option<crate::VolumeIdentity>,
        expected_destination_volume_identity: Option<crate::VolumeIdentity>,
        require_recorded_identity: bool,
        allow_replacement: bool,
    ) -> Result<(), WorkflowError> {
        let result = if require_recorded_identity {
            RunPrecheck::check_for_resume_with_replacement(
                profile,
                probe,
                expected_source_volume_identity,
                expected_destination_volume_identity,
                allow_replacement,
            )
        } else {
            RunPrecheck::check_with_expected_volumes(
                profile,
                probe,
                expected_source_volume_identity,
                expected_destination_volume_identity,
            )
        }
        .map_err(|error| {
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
            for root in partial_cleanup_roots(confirmed.profile()) {
                cleanup_partial_transfer_artifacts(root)
                    .map_err(|error| WorkflowError::Io(error.to_string()))?;
            }
        }
        Ok(())
    }

    fn cleanup_partials_after_resolution(
        &self,
        profile: &crate::SyncProfile,
        report: &RunReport,
    ) -> Result<(), WorkflowError> {
        if profile.options().partial_transfer_policy == crate::PartialTransferPolicy::KeepPartialForResume
            && report.status() == RunReportStatus::Completed
        {
            for root in partial_cleanup_roots(profile) {
                cleanup_partial_transfer_artifacts(root)
                    .map_err(|error| WorkflowError::Io(error.to_string()))?;
            }
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

fn ssh_peer_for_profile(
    profile: &crate::SyncProfile,
) -> Result<(crate::PeerSide, &crate::SshPeer), WorkflowError> {
    match (profile.peer_a().ssh_peer(), profile.peer_b().ssh_peer()) {
        (Some(peer), None) => Ok((crate::PeerSide::PeerA, peer)),
        (None, Some(peer)) => Ok((crate::PeerSide::PeerB, peer)),
        (None, None) => Err(WorkflowError::InvalidRun(
            "SSH workflow requires one SSH peer".to_owned(),
        )),
        (Some(_), Some(_)) => Err(WorkflowError::InvalidRun(
            "SSH workflow does not support two SSH peers".to_owned(),
        )),
    }
}

fn peer_for_side(profile: &crate::SyncProfile, side: crate::PeerSide) -> &crate::Peer {
    match side {
        crate::PeerSide::PeerA => profile.peer_a(),
        crate::PeerSide::PeerB => profile.peer_b(),
    }
}

fn validate_ssh_permits(
    peer: &crate::SshPeer,
    credential: &crate::ResolvedSshCredential,
    host_permit: &crate::SshHostTrustPermit,
    precheck: &crate::RemotePrecheckPermit,
    request: RemotePrecheckRequest,
) -> Result<(), WorkflowError> {
    precheck
        .validate_for(peer, credential, host_permit, request)
        .map_err(|error| WorkflowError::InvalidRun(format!("SSH precheck permit is invalid: {error}")))
}

fn ssh_source_item<'a>(
    plan: &'a OneWayPlan,
    action: &PlanAction,
) -> Result<&'a crate::InventoryItem, WorkflowError> {
    let inventory = if plan.specification().mode() == crate::SyncMode::Mirror {
        match action.source_side() {
            crate::PeerSide::PeerA => plan.source_inventory(),
            crate::PeerSide::PeerB => plan.destination_inventory(),
        }
    } else {
        plan.source_inventory()
    };
    inventory.item(action.relative_path()).ok_or_else(|| {
        WorkflowError::InvalidRun(format!(
            "SSH action {:?} is outside the frozen source inventory",
            action.relative_path()
        ))
    })
}

fn ssh_plan_record(plan: &OneWayPlan, action: &PlanAction) -> Result<PlanRecord, WorkflowError> {
    let inventory = if action.kind() == PlanActionKind::RemoveDestination {
        plan.destination_inventory()
    } else if plan.specification().mode() == crate::SyncMode::Mirror {
        match action.source_side() {
            crate::PeerSide::PeerA => plan.source_inventory(),
            crate::PeerSide::PeerB => plan.destination_inventory(),
        }
    } else {
        plan.source_inventory()
    };
    let item = inventory.item(action.relative_path()).ok_or_else(|| {
        WorkflowError::InvalidRun(format!(
            "SSH action {:?} is outside the frozen inventory",
            action.relative_path()
        ))
    })?;
    Ok(PlanRecord::new(
        action.action_id(),
        action.relative_path().to_path_buf(),
        action.kind(),
        action.source_side(),
        action.size(),
        PreActionState::new(
            item.item_type(),
            item.metadata().size(),
            unix_nanos(item.metadata().modified_at()),
            None,
            item.content_fingerprint().copied(),
        ),
    ))
}

fn resolution_report_items<F>(
    confirmed: &crate::ConfirmedResolutionRun,
    execution: &crate::ResolutionExecutionReport,
    executor: &FilesystemResolutionExecutor<F>,
) -> Vec<MirrorResolutionReportItem>
where
    F: Fn() -> bool,
{
    confirmed
        .actions()
        .iter()
        .flat_map(|action| {
            let result = execution
                .result_for(action.relative_path())
                .expect("every confirmed resolution action has an execution result");
            if matches!(
                action.resolution(),
                ConflictResolution::PreserveBoth | ConflictResolution::RenamePreserveForReview
            ) {
                if let Some(report) = executor.preserved_copy_report(action.relative_path()) {
                    return report
                        .items()
                        .iter()
                        .map(|item| {
                            let outcome = match item.outcome() {
                                PreservedCopyExecutionOutcome::Copied => {
                                    MirrorResolutionOutcome::Completed
                                }
                                PreservedCopyExecutionOutcome::Unresolved(error) => {
                                    MirrorResolutionOutcome::Unresolved(
                                        preserved_copy_failure_reason(error),
                                    )
                                }
                            };
                            MirrorResolutionReportItem::new(
                                item.copy().original_path(),
                                Some(item.copy().generated_path()),
                                item.copy().resolution(),
                                action.operation(),
                                Some(item.copy().source_peer()),
                                Some(item.copy().target_peer()),
                                outcome,
                                MirrorResolutionReviewState::ReviewLater,
                            )
                        })
                        .collect::<Vec<_>>();
                }
            }
            vec![MirrorResolutionReportItem::new(
                action.relative_path(),
                None::<PathBuf>,
                action.resolution(),
                action.operation(),
                action.source_side(),
                action.target_side(),
                mirror_resolution_outcome(result.outcome()),
                if matches!(
                    action.resolution(),
                    ConflictResolution::PreserveBoth
                        | ConflictResolution::RenamePreserveForReview
                ) {
                    MirrorResolutionReviewState::ReviewLater
                } else {
                    MirrorResolutionReviewState::Settled
                },
            )]
        })
        .collect()
}

fn resolution_planned_report_items<F>(
    confirmed: &crate::ConfirmedResolutionRun,
    executor: &FilesystemResolutionExecutor<F>,
) -> Vec<MirrorResolutionReportItem>
where
    F: Fn() -> bool,
{
    confirmed
        .actions()
        .iter()
        .flat_map(|action| {
            if let Some(plan) = executor.preserved_copy_plan(action.relative_path()) {
                return plan
                    .copies()
                    .iter()
                    .map(|copy| {
                        MirrorResolutionReportItem::new(
                            copy.original_path(),
                            Some(copy.generated_path()),
                            copy.resolution(),
                            action.operation(),
                            Some(copy.source_peer()),
                            Some(copy.target_peer()),
                            MirrorResolutionOutcome::Unresolved(ActionReason::InterruptedBoundary),
                            MirrorResolutionReviewState::ReviewLater,
                        )
                    })
                    .collect::<Vec<_>>();
            }

            vec![MirrorResolutionReportItem::new(
                action.relative_path(),
                None::<PathBuf>,
                action.resolution(),
                action.operation(),
                action.source_side(),
                action.target_side(),
                if action.resolution() == ConflictResolution::Defer {
                    MirrorResolutionOutcome::Deferred
                } else {
                    MirrorResolutionOutcome::Unresolved(ActionReason::InterruptedBoundary)
                },
                if action.resolution() == ConflictResolution::Defer {
                    MirrorResolutionReviewState::ReviewLater
                } else {
                    MirrorResolutionReviewState::Settled
                },
            )]
        })
        .collect()
}

struct JournaledResolutionExecutor<'a, F> {
    inner: &'a mut FilesystemResolutionExecutor<F>,
    store: &'a mut RunEvidenceStore,
    run_id: RunId,
    action_ids: &'a BTreeMap<PathBuf, crate::ActionId>,
}

impl<F> JournaledResolutionExecutor<'_, F>
where
    F: Fn() -> bool,
{
    fn action_id(&self, action: &ConflictResolutionAction) -> crate::ActionId {
        self.action_ids
            .get(action.relative_path())
            .copied()
            .expect("every resolution action has a journal id")
    }

    fn start(&mut self, action: &ConflictResolutionAction) -> Result<crate::ActionId, ActionReason> {
        let action_id = self.action_id(action);
        self.store
            .append_event(
                self.run_id,
                JournalEvent::Started { action_id },
            )
            .map_err(|_| ActionReason::InterruptedBoundary)?;
        Ok(action_id)
    }

    fn finish(
        &mut self,
        action_id: crate::ActionId,
        outcome: &Result<(), ActionReason>,
    ) -> Result<(), ActionReason> {
        let event = match outcome {
            Ok(()) => JournalEvent::Completed { action_id },
            Err(reason) => JournalEvent::Unresolved {
                action_id,
                reason: *reason,
            },
        };
        self.store
            .append_event(self.run_id, event)
            .map_err(|_| ActionReason::InterruptedBoundary)
    }
}

impl<F> crate::ResolutionActionExecutor for JournaledResolutionExecutor<'_, F>
where
    F: Fn() -> bool,
{
    fn execute(
        &mut self,
        action: &ConflictResolutionAction,
        analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason> {
        let action_id = self.start(action)?;
        let result = self.inner.execute(action, analysis);
        if self.finish(action_id, &result).is_err() {
            return Err(ActionReason::InterruptedBoundary);
        }
        result
    }

    fn defer(
        &mut self,
        action: &ConflictResolutionAction,
        _analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason> {
        let action_id = self.start(action)?;
        self.store
            .append_event(
                self.run_id,
                JournalEvent::Deferred { action_id },
            )
            .map_err(|_| ActionReason::InterruptedBoundary)
    }

    fn cancel(
        &mut self,
        action: &ConflictResolutionAction,
        _analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason> {
        let action_id = self.action_id(action);
        self.store
            .append_event(
                self.run_id,
                JournalEvent::Cancelled { action_id },
            )
            .map_err(|_| ActionReason::InterruptedBoundary)
    }
}

fn resolution_action_ids(
    actions: &[ConflictResolutionAction],
) -> BTreeMap<PathBuf, crate::ActionId> {
    actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            (
                action.relative_path().to_path_buf(),
                (index + 1) as crate::ActionId,
            )
        })
        .collect()
}

fn resolution_plan_record(
    analysis: &FreshAnalysis,
    action_id: crate::ActionId,
    action: &ConflictResolutionAction,
) -> Result<PlanRecord, WorkflowError> {
    let affected_side = action.source_side().unwrap_or(crate::PeerSide::PeerA);
    let inventory = match affected_side {
        crate::PeerSide::PeerA => analysis.source_inventory(),
        crate::PeerSide::PeerB => analysis.destination_inventory(),
    };
    let item = inventory.item(action.relative_path()).ok_or_else(|| {
        WorkflowError::InvalidRun(format!(
            "resolution action {:?} is outside the fresh inventory",
            action.relative_path()
        ))
    })?;
    Ok(PlanRecord::new(
        action_id,
        action.relative_path().to_path_buf(),
        PlanActionKind::CopyToDestination,
        affected_side,
        (item.item_type() == crate::ItemType::RegularFile).then_some(item.metadata().size()),
        PreActionState::new(
            item.item_type(),
            item.metadata().size(),
            unix_nanos(item.metadata().modified_at()),
            None,
            item.content_fingerprint().copied(),
        ),
    ))
}

fn record_resolution_setup_failure(
    run_id: RunId,
    actions: &[ConflictResolutionAction],
    action_ids: &BTreeMap<PathBuf, crate::ActionId>,
    store: &mut RunEvidenceStore,
    reason: ActionReason,
) -> Result<(), WorkflowError> {
    for action in actions {
        let action_id = action_ids
            .get(action.relative_path())
            .copied()
            .expect("every resolution action has a journal id");
        store.append_event(run_id, JournalEvent::Started { action_id })?;
        if action.resolution() == ConflictResolution::Defer {
            store.append_event(run_id, JournalEvent::Deferred { action_id })?;
        } else {
            store.append_event(
                run_id,
                JournalEvent::Unresolved { action_id, reason },
            )?;
        }
    }
    Ok(())
}

fn resolution_setup_failure_items(
    actions: &[ConflictResolutionAction],
    reason: ActionReason,
) -> Vec<MirrorResolutionReportItem> {
    actions
        .iter()
        .map(|action| {
            MirrorResolutionReportItem::new(
                action.relative_path(),
                None::<PathBuf>,
                action.resolution(),
                action.operation(),
                action.source_side(),
                action.target_side(),
                if action.resolution() == ConflictResolution::Defer {
                    MirrorResolutionOutcome::Deferred
                } else {
                    MirrorResolutionOutcome::Failed(reason)
                },
                if action.resolution() == ConflictResolution::Defer {
                    MirrorResolutionReviewState::ReviewLater
                } else {
                    MirrorResolutionReviewState::Settled
                },
            )
        })
        .collect()
}

fn mirror_resolution_outcome(outcome: ResolutionRunOutcome) -> MirrorResolutionOutcome {
    match outcome {
        ResolutionRunOutcome::Completed => MirrorResolutionOutcome::Completed,
        ResolutionRunOutcome::Deferred => MirrorResolutionOutcome::Deferred,
        ResolutionRunOutcome::Unresolved(reason) => MirrorResolutionOutcome::Failed(reason),
    }
}

fn preserved_copy_failure_reason(error: &PreservedCopyExecutionError) -> ActionReason {
    match error {
        PreservedCopyExecutionError::SourceChanged(_) => ActionReason::SourceChanged,
        PreservedCopyExecutionError::Verification(_, _) => ActionReason::VerificationMismatch,
        PreservedCopyExecutionError::UnsafePath(_)
        | PreservedCopyExecutionError::SourceUnavailable(_, _)
        | PreservedCopyExecutionError::UnsupportedItem(_)
        | PreservedCopyExecutionError::DestinationOccupied(_)
        | PreservedCopyExecutionError::Io(_, _) => ActionReason::TransferFailed,
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

fn partial_cleanup_roots(profile: &crate::SyncProfile) -> Vec<&Path> {
    if profile.mode() == crate::SyncMode::Mirror {
        vec![profile.peer_a().root(), profile.peer_b().root()]
    } else {
        vec![destination_root(profile)]
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
    let source_root = match action.affected_side() {
        crate::PeerSide::PeerA => profile.peer_a().root(),
        crate::PeerSide::PeerB => profile.peer_b().root(),
    };
    let destination_root = match action.affected_side() {
        crate::PeerSide::PeerA => profile.peer_b().root(),
        crate::PeerSide::PeerB => profile.peer_a().root(),
    };
    let source = source_root.join(action.relative_path());
    let destination = destination_root.join(action.relative_path());
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

fn orient_volume_identities(
    profile: &crate::SyncProfile,
    source_volume_identity: Option<crate::VolumeIdentity>,
    destination_volume_identity: Option<crate::VolumeIdentity>,
) -> (
    Option<crate::VolumeIdentity>,
    Option<crate::VolumeIdentity>,
) {
    if profile.mode() == crate::SyncMode::Mirror {
        return (source_volume_identity, destination_volume_identity);
    }
    match profile.source() {
        crate::OneWaySource::PeerA => (source_volume_identity, destination_volume_identity),
        crate::OneWaySource::PeerB => (destination_volume_identity, source_volume_identity),
    }
}

fn blocked_volume_identities(
    error: &WorkflowError,
) -> (
    Option<crate::VolumeIdentity>,
    Option<crate::VolumeIdentity>,
) {
    match error {
        WorkflowError::Precheck(PrecheckFailure::Blocked(blocked)) => (
            blocked.source_volume_identity(),
            blocked.destination_volume_identity(),
        ),
        _ => (None, None),
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
        ffi::CString,
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    #[cfg(unix)]
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{symlink, PermissionsExt},
    };

    use super::RunWorkflow;
    use crate::{
        ActionOutcome, ActionReason, AuthorizationSnapshot, ContentProof, DeletionMethod,
        DestinationNamingPolicy, FreshAnalysis, ItemMetadata,
        ItemType, JournalEvent, OneWaySource, Peer, PeerSide, PlanActionKind, PlanRecord,
        PreActionState, ProcessError, RecoveryEvidence, RecoveryMethod, RetryPolicy,
        LocalPrecheckProbe, PartialTransferPolicy, PeerScope, PeerScopeLockRegistry,
        PrecheckFailure, PrecheckProbe,
        MirrorDeletionChoice, MirrorDeletionDecision, RunEvidenceStore, RunId, RunReportStatus,
        RunSnapshot, ScopeLockOwner, SourceInventorySnapshot, SyncMode, SyncOptions,
        SyncProfile, SshAuthentication, SshHostFingerprint, SshHostIdentityError,
        SshHostIdentityProbe, SshHostTrustController, SshPeer, SshRemotePrecheck,
        SshRemotePrecheckProbe, RemotePrecheckObservation, RemotePrecheckRequest,
        AccessSnapshot, RemoteRsyncCapability, RemoteSha256Capability, RemoteTrashCapability,
        ResolvedSshCredential, SshRecoveryBoundary, SshRunBackend, SshRunError,
        SshTransferBoundary,
        WorkflowError,
        SshMetadataProof, SshTransferEvidence, SshTransferRequest,
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

        fn remote(&self) -> PathBuf {
            self.root.join("remote")
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

    fn ssh_metadata(path: &Path) -> SshMetadataProof {
        let metadata = fs::symlink_metadata(path).expect("SSH metadata should be readable");
        let item_type = if metadata.file_type().is_file() {
            ItemType::RegularFile
        } else if metadata.file_type().is_dir() {
            ItemType::Directory
        } else if metadata.file_type().is_symlink() {
            ItemType::Symlink
        } else {
            ItemType::Unsupported
        };
        #[cfg(unix)]
        let permissions = Some(metadata.permissions().mode());
        #[cfg(not(unix))]
        let permissions = None;
        SshMetadataProof::new(
            item_type,
            ItemMetadata::new(
                metadata.len(),
                metadata.modified().ok(),
                metadata.permissions().readonly(),
                permissions,
                if item_type == ItemType::Symlink {
                    fs::read_link(path).ok()
                } else {
                    None
                },
            ),
        )
    }

    fn file_identity(path: &Path) -> Option<crate::FileIdentity> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(path).ok()?;
            Some(crate::FileIdentity::new(metadata.dev(), metadata.ino()))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }

    struct FixedSshHostProbe(SshHostFingerprint);

    impl SshHostIdentityProbe for FixedSshHostProbe {
        fn probe(&self, _peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError> {
            Ok(self.0)
        }
    }

    struct FakeSshBackend {
        remote_root: PathBuf,
        calls: AtomicUsize,
        prechecks: AtomicUsize,
        fail_first: AtomicBool,
        mismatch: bool,
        remote_trash: bool,
        recovery_calls: AtomicUsize,
        recovery_failure: bool,
    }

    impl FakeSshBackend {
        fn new(remote_root: PathBuf) -> Self {
            Self {
                remote_root,
                calls: AtomicUsize::new(0),
                prechecks: AtomicUsize::new(0),
                fail_first: AtomicBool::new(false),
                mismatch: false,
                remote_trash: false,
                recovery_calls: AtomicUsize::new(0),
                recovery_failure: false,
            }
        }

        fn with_retry_on_first_call(self) -> Self {
            self.fail_first.store(true, Ordering::Relaxed);
            self
        }

        fn with_mismatched_destination(mut self) -> Self {
            self.mismatch = true;
            self
        }

        fn with_remote_trash(mut self) -> Self {
            self.remote_trash = true;
            self
        }

        fn with_recovery_failure(mut self) -> Self {
            self.recovery_failure = true;
            self
        }

        fn remote_path(&self, relative: &Path) -> PathBuf {
            self.remote_root.join(relative)
        }
    }

    impl SshRemotePrecheckProbe for FakeSshBackend {
        fn probe(
            &self,
            _peer: &SshPeer,
            _credential: &ResolvedSshCredential,
            _host_permit: &crate::SshHostTrustPermit,
            _request: &RemotePrecheckRequest,
        ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
            self.prechecks.fetch_add(1, Ordering::Relaxed);
            Ok(RemotePrecheckObservation::new(
                true,
                AccessSnapshot::new(true, true, true),
                RemoteRsyncCapability::Compatible,
                RemoteSha256Capability::Available,
                if self.remote_trash {
                    RemoteTrashCapability::verified("/srv/trash")
                        .expect("fixture Trash location should be valid")
                } else {
                    RemoteTrashCapability::unavailable()
                },
            ))
        }
    }

    impl SshHostIdentityProbe for FakeSshBackend {
        fn probe(&self, _peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError> {
            Ok(SshHostFingerprint::sha256([9; 32]))
        }
    }

    impl SshRunBackend for FakeSshBackend {
        fn inventory(
            &self,
            peer: &SshPeer,
            _credential: &ResolvedSshCredential,
            _host_permit: &crate::SshHostTrustPermit,
            exclusions: &[String],
        ) -> Result<crate::SourceInventory, SshRunError> {
            let backing_peer = Peer::new("remote backing", self.remote_root.clone());
            let inventory = FreshAnalysis::collect_local_inventory(&backing_peer, exclusions)
                .map_err(|_| SshRunError::RemoteUnavailable)?;
            Ok(crate::SourceInventory::from_items(
                "SSH peer",
                peer.remote_path().to_path_buf(),
                inventory.items().to_vec(),
            ))
        }

        fn transfer(
            &self,
            request: &SshTransferRequest<'_>,
            should_cancel: &dyn Fn() -> bool,
            progress: &mut dyn FnMut(u64),
        ) -> Result<SshTransferEvidence, SshRunError> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_first.load(Ordering::Relaxed) && call == 0 {
                return Err(SshRunError::Disconnected {
                    boundary: SshTransferBoundary::BeforeTransfer,
                });
            }
            if should_cancel() {
                return Err(SshRunError::Cancelled);
            }
            let _rsync = request
                .rsync_invocation()
                .map_err(|_| SshRunError::InvalidOperation)?;
            if !_rsync.arguments().iter().any(|argument| {
                argument.to_string_lossy().starts_with("--rsh=ssh ")
            }) {
                return Err(SshRunError::InvalidOperation);
            }
            if !_rsync.arguments().iter().any(|argument| {
                argument
                    .to_string_lossy()
                    .contains(".syncplus-temporary-")
            }) {
                return Err(SshRunError::InvalidOperation);
            }
            let _helper = request
                .remote_sha256_invocation(
                    &request
                        .remote_peer()
                        .remote_path()
                        .join(request.action().relative_path()),
                )
                .map_err(|_| SshRunError::InvalidOperation)?;

            let source = if request.source_peer().is_ssh() {
                self.remote_path(request.action().relative_path())
            } else {
                request
                    .source_peer()
                    .root()
                    .join(request.action().relative_path())
            };
            let destination = if request.destination_peer().is_ssh() {
                self.remote_path(request.action().relative_path())
            } else {
                request
                    .destination_peer()
                    .root()
                    .join(request.action().relative_path())
            };
            let temporary = if request.destination_peer().is_ssh() {
                let relative = request
                    .temporary_destination()
                    .strip_prefix(request.remote_peer().remote_path())
                    .map_err(|_| SshRunError::InvalidOperation)?;
                self.remote_root.join(relative)
            } else {
                request.temporary_destination().to_path_buf()
            };
            let previous = if request.destination_peer().is_ssh() {
                let relative = request
                    .previous_destination()
                    .strip_prefix(request.remote_peer().remote_path())
                    .map_err(|_| SshRunError::InvalidOperation)?;
                self.remote_root.join(relative)
            } else {
                request.previous_destination().to_path_buf()
            };
            let source_proof = ContentProof::from_path(&source)
                .map_err(|_| SshRunError::SourceChanged)?;
            let source_identity = file_identity(&source).ok_or(SshRunError::SourceChanged)?;
            if let Some(parent) = temporary.parent() {
                fs::create_dir_all(parent).map_err(|_| SshRunError::RemoteUnavailable)?;
            }
            fs::copy(&source, &temporary).map_err(|_| SshRunError::RemoteUnavailable)?;
            let temporary_proof = ContentProof::from_path(&temporary)
                .map_err(|_| SshRunError::RemoteVerificationUnavailable {
                    boundary: SshTransferBoundary::TemporaryDestination,
                })?;
            if destination.exists() {
                fs::rename(&destination, &previous).map_err(|_| SshRunError::Disconnected {
                    boundary: SshTransferBoundary::DestinationInstalled,
                })?;
            }
            fs::rename(&temporary, &destination).map_err(|_| SshRunError::Disconnected {
                boundary: SshTransferBoundary::DestinationInstalled,
            })?;
            let destination_proof = ContentProof::from_path(&destination)
                .map_err(|_| SshRunError::RemoteVerificationUnavailable {
                    boundary: SshTransferBoundary::DestinationInstalled,
                })?;
            let stable_source_proof = ContentProof::from_path(&source)
                .map_err(|_| SshRunError::SourceChanged)?;
            let stable_source_identity = file_identity(&source).ok_or(SshRunError::SourceChanged)?;
            if stable_source_proof != source_proof || stable_source_identity != source_identity {
                return Err(SshRunError::SourceChanged);
            }
            progress(source_proof.size());
            let destination_proof = if self.mismatch {
                ContentProof::new(destination_proof.size(), [0; 32])
            } else {
                destination_proof
            };
            Ok(SshTransferEvidence::with_paths(
                request
                    .source_peer()
                    .root()
                    .join(request.action().relative_path()),
                request.destination().to_path_buf(),
                Some(ssh_metadata(&source)),
                Some(ssh_metadata(&destination)),
                Some(source_proof),
                Some(destination_proof),
                true,
                temporary_proof.size(),
            )
            .with_source_identity(source_identity)
            .with_source_stability_verified())
        }

        fn recover_source(
            &self,
            request: &SshTransferRequest<'_>,
            transfer: &SshTransferEvidence,
            should_cancel: &dyn Fn() -> bool,
        ) -> Result<RecoveryEvidence, SshRunError> {
            self.recovery_calls.fetch_add(1, Ordering::Relaxed);
            if should_cancel() {
                return Err(SshRunError::Cancelled);
            }
            if self.recovery_failure {
                return Err(SshRunError::RemoteRecoveryFailed {
                    boundary: SshRecoveryBoundary::BeforeRecovery,
                    evidence: None,
                });
            }
            let source = self.remote_path(request.action().relative_path());
            let recovery_root = self.remote_root.parent().unwrap().join("trash");
            let recovery = recovery_root.join(request.action().relative_path());
            let source_proof = transfer.source().ok_or(SshRunError::InvalidOperation)?;
            let source_identity = transfer
                .source_identity()
                .ok_or(SshRunError::InvalidOperation)?;
            let current_source_proof = ContentProof::from_path(&source)
                .map_err(|_| SshRunError::SourceChanged)?;
            let current_source_identity = file_identity(&source).ok_or(SshRunError::SourceChanged)?;
            if current_source_proof != source_proof || current_source_identity != source_identity {
                return Err(SshRunError::SourceChanged);
            }
            let item_type = transfer
                .source_metadata()
                .ok_or(SshRunError::InvalidOperation)?
                .item_type();
            let provenance = crate::RecoveryProvenance::new(
                format!(
                    "{}@{}:{}",
                    request.remote_peer().username(),
                    request.remote_peer().server(),
                    request.remote_peer().port()
                ),
                request.remote_peer().remote_path().to_path_buf(),
                request.action().relative_path().to_path_buf(),
                request.run_id(),
                item_type,
                Some(source_proof),
                Some(source_identity),
            )
            .map_err(|_| SshRunError::InvalidOperation)?;
            if let Some(parent) = recovery.parent() {
                fs::create_dir_all(parent).map_err(|_| SshRunError::RemoteUnavailable)?;
            }
            let sidecar = recovery.with_extension("syncplus-manifest");
            provenance
                .write_sidecar(&sidecar)
                .map_err(|_| SshRunError::RemoteRecoveryFailed {
                    boundary: SshRecoveryBoundary::BeforeRecovery,
                    evidence: None,
                })?;
            if let Err(_error) = fs::rename(&source, &recovery) {
                let _ = fs::remove_file(&sidecar);
                return Err(SshRunError::RemoteRecoveryFailed {
                    boundary: SshRecoveryBoundary::BeforeRecovery,
                    evidence: None,
                });
            }
            let recovery_proof = match ContentProof::from_path(&recovery) {
                Ok(proof) => proof,
                Err(_) => {
                    let restored = fs::rename(&recovery, &source).is_ok();
                    let _ = fs::remove_file(&sidecar);
                    return Err(if restored {
                        SshRunError::RemoteRecoveryFailed {
                            boundary: SshRecoveryBoundary::RecoveryStarted,
                            evidence: None,
                        }
                    } else {
                        SshRunError::RemoteRecoveryAmbiguous {
                            boundary: SshRecoveryBoundary::RecoveryStarted,
                            evidence: None,
                        }
                    });
                }
            };
            Ok(RecoveryEvidence::new(
                super::current_unix_nanos(),
                request.remote_recovery_target(),
                false,
                true,
                true,
                transfer.source().map(|proof| proof.size()),
                transfer.destination().map(|proof| proof.size()),
                transfer.source().map(|proof| *proof.sha256()),
                transfer.destination().map(|proof| *proof.sha256()),
            )
            .with_recovery_proof(recovery_proof.size(), Some(*recovery_proof.sha256()))
            .with_provenance(provenance))
        }
    }

    fn ssh_profile(fixture: &Fixture, source_is_remote: bool) -> (SyncProfile, SshPeer) {
        let ssh = SshPeer::new(
            "backup.example.test",
            "sync-user",
            2222,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        )
        .expect("SSH fixture should be valid");
        let profile = SyncProfile::new(
            if source_is_remote { "SSH pull" } else { "SSH push" },
            Peer::new("local", if source_is_remote { fixture.destination() } else { fixture.source() }),
            Peer::from_ssh("SSH peer", ssh.clone()),
        )
        .with_source(if source_is_remote {
            OneWaySource::PeerB
        } else {
            OneWaySource::PeerA
        });
        (profile, ssh)
    }

    fn ssh_safe_delete_profile(
        fixture: &Fixture,
    ) -> (SyncProfile, SshPeer) {
        let (profile, ssh) = ssh_profile(fixture, true);
        (
            profile.with_options(SyncOptions {
                safe_delete: true,
                destination_cleanup: false,
                deletion_method: Some(DeletionMethod::Trash),
                metadata: Default::default(),
                partial_transfer_policy: Default::default(),
                retry_policy: Default::default(),
            }),
            ssh,
        )
    }

    fn ssh_permits(
        profile: &SyncProfile,
        ssh: &SshPeer,
    ) -> (ResolvedSshCredential, crate::SshHostTrustPermit, crate::RemotePrecheckPermit) {
        ssh_permits_with_trash(profile, ssh, false)
    }

    fn ssh_permits_with_trash(
        profile: &SyncProfile,
        ssh: &SshPeer,
        remote_trash: bool,
    ) -> (ResolvedSshCredential, crate::SshHostTrustPermit, crate::RemotePrecheckPermit) {
        let credential = ResolvedSshCredential::Agent;
        let mut controller = SshHostTrustController::new(
            RunEvidenceStore::open_in_memory().expect("host trust store"),
        );
        let host_probe = FixedSshHostProbe(SshHostFingerprint::sha256([9; 32]));
        let decision = controller
            .inspect(ssh, &host_probe)
            .expect("host identity inspection");
        controller
            .approve(ssh, &decision, crate::HostTrustMode::Interactive)
            .expect("host identity approval");
        let host_permit = controller
            .pre_mutation_permit(ssh, &host_probe)
            .expect("approved host permit");
        let (_, request) = RemotePrecheckRequest::from_profile(profile)
            .expect("SSH profile should derive remote precheck");
        let observation = RemotePrecheckObservation::new(
            true,
            AccessSnapshot::new(true, true, true),
            RemoteRsyncCapability::Compatible,
            RemoteSha256Capability::Available,
            if remote_trash {
                RemoteTrashCapability::verified("/srv/trash")
                    .expect("fixture Trash location should be valid")
            } else {
                RemoteTrashCapability::unavailable()
            },
        );
        struct PassingRemoteProbe(RemotePrecheckObservation);
        impl SshRemotePrecheckProbe for PassingRemoteProbe {
            fn probe(
                &self,
                _peer: &SshPeer,
                _credential: &ResolvedSshCredential,
                _host_permit: &crate::SshHostTrustPermit,
                _request: &RemotePrecheckRequest,
            ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
                Ok(self.0.clone())
            }
        }
        let permit = SshRemotePrecheck::check(
            ssh,
            &credential,
            &host_permit,
            &request,
            &PassingRemoteProbe(observation),
        )
        .expect("remote precheck should complete")
        .require_passed()
        .expect("remote precheck should pass");
        (credential, host_permit, permit)
    }

    #[test]
    fn mirror_workflow_transfers_both_directions_and_reports_both_peer_views() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.source()).expect("Peer A should be creatable");
        fs::create_dir_all(fixture.destination()).expect("Peer B should be creatable");
        write_file(&fixture.source().join("from-a.txt"), b"from A");
        write_file(&fixture.destination().join("from-b.txt"), b"from B");
        let profile = fixture
            .profile()
            .with_source(OneWaySource::PeerB)
            .with_mode(SyncMode::Mirror);

        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("a first Mirror run should transfer both one-sided items");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert_eq!(fs::read(fixture.destination().join("from-a.txt")).unwrap(), b"from A");
        assert_eq!(fs::read(fixture.source().join("from-b.txt")).unwrap(), b"from B");
        assert_eq!(report.peer_a_inventory().unwrap().peer_name(), "source");
        assert_eq!(report.peer_b_inventory().unwrap().peer_name(), "destination");
        let baseline = store
            .load_mirror_baseline(profile.name())
            .expect("the Mirror baseline should load")
            .expect("a completed Mirror run should persist a baseline");
        assert_eq!(baseline.items().len(), 2);
        assert!(baseline.item("from-a.txt").unwrap().peer_a().is_some());
        assert!(baseline.item("from-a.txt").unwrap().peer_b().is_some());
        assert!(baseline.item("from-b.txt").unwrap().peer_a().is_some());
        assert!(baseline.item("from-b.txt").unwrap().peer_b().is_some());

        let from_a = report
            .items()
            .iter()
            .find(|item| item.relative_path() == Path::new("from-a.txt"))
            .expect("Peer A action should be in the report");
        assert_eq!(from_a.affected_side(), PeerSide::PeerA);
        assert_eq!(from_a.source_path(), fixture.source().join("from-a.txt"));
        assert_eq!(from_a.destination_path(), fixture.destination().join("from-a.txt"));
        assert!(from_a.consequence().contains("Peer A"));
    }

    #[test]
    fn partial_mirror_run_keeps_failed_and_successful_paths_review_required() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.source()).expect("Peer A should be creatable");
        fs::create_dir_all(fixture.destination()).expect("Peer B should be creatable");
        write_file(&fixture.source().join("a.txt"), b"original A");
        write_file(&fixture.destination().join("b.txt"), b"original B");
        let profile = fixture.profile().with_mode(SyncMode::Mirror);
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || fixture.destination().join("a.txt").exists(),
            )
            .expect("partial Mirror execution should return its report");

        assert_eq!(report.status(), RunReportStatus::RecoveryReview, "report: {report:?}");
        assert!(report.items().iter().any(|item| {
            item.relative_path() == Path::new("a.txt")
                && matches!(item.outcome(), ActionOutcome::RecoveryReview(_))
        }));
        assert!(report.items().iter().any(|item| {
            item.relative_path() == Path::new("b.txt")
                && matches!(item.outcome(), ActionOutcome::Cancelled)
        }));
        assert!(report
            .reconciliation()
            .expect("partial Mirror reconciliation")
            .requires_review());
        assert!(!report.can_mark_review_cleared());
        assert!(fixture.source().join("a.txt").exists());
        assert_eq!(
            fs::read(fixture.destination().join("b.txt")).unwrap(),
            b"original B"
        );
    }

    #[test]
    fn completed_mirror_deletion_reconciles_both_peers_as_absent() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.source()).expect("Peer A should be creatable");
        fs::create_dir_all(fixture.destination()).expect("Peer B should be creatable");
        write_file(&fixture.source().join("gone.txt"), b"same item");
        write_file(&fixture.destination().join("gone.txt"), b"same item");
        let profile = fixture.profile().with_mode(SyncMode::Mirror);
        let workflow = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")));
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        workflow
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("initial equal Mirror run should settle");
        fs::remove_file(fixture.source().join("gone.txt")).expect("user deletion should succeed");

        let analysis = FreshAnalysis::analyze(&profile).expect("current analysis");
        let current_a = SourceInventorySnapshot::from_inventory(analysis.source_inventory());
        let current_b = SourceInventorySnapshot::from_inventory(analysis.destination_inventory());
        let baseline = store
            .load_mirror_baseline(profile.name())
            .expect("baseline should load")
            .expect("initial run should create a baseline");
        let confirmed = baseline
            .deletion_review(&current_a, &current_b)
            .resolve([MirrorDeletionDecision::new(
                "gone.txt",
                MirrorDeletionChoice::DeleteCounterpart,
            )])
            .expect("baseline-backed deletion should require an explicit decision")
            .confirm(true)
            .expect("deletion should require final confirmation");
        fs::remove_file(fixture.destination().join("gone.txt"))
            .expect("confirmed counterpart deletion should be applied");

        let run_id = RunId::new(2);
        let snapshot = RunSnapshot::from_profile(run_id, &profile, AuthorizationSnapshot::default())
            .expect("deletion run snapshot");
        store.begin_run(&snapshot).expect("deletion run should begin");
        store
            .record_source_inventory(run_id, &current_a)
            .expect("Peer A inventory should persist");
        store
            .record_destination_inventory(run_id, &current_b)
            .expect("Peer B inventory should persist");
        let result = confirmed.deletion_actions()[0].completed();
        let report = workflow
            .record_mirror_deletion_results(
                run_id,
                &profile,
                &current_a,
                &current_b,
                &[result],
                &mut store,
            )
            .expect("deletion result should reconcile through the workflow");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert!(report.reconciliation().unwrap().findings().is_empty());
        assert!(report.can_mark_review_cleared());
        assert!(store
            .load_mirror_baseline(profile.name())
            .unwrap()
            .unwrap()
            .item("gone.txt")
            .is_some());
    }

    #[cfg(unix)]
    #[test]
    fn local_item_fidelity_preserves_empty_directories_symlinks_and_executable_files() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("run.sh"), b"#!/bin/sh\necho safe\n");
        fs::set_permissions(
            fixture.source().join("run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("source executable bit should be set");
        fs::create_dir_all(fixture.source().join("empty")).expect("empty directory");
        symlink("run.sh", fixture.source().join("run-link"))
            .expect("source symlink should be creatable");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");

        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");
        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &fixture.profile(),
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("essential item types should transfer");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert!(fs::metadata(fixture.destination().join("empty"))
            .expect("empty directory should transfer")
            .is_dir());
        assert!(fs::read_dir(fixture.destination().join("empty"))
            .expect("transferred empty directory should be readable")
            .next()
            .is_none());
        assert_eq!(
            fs::symlink_metadata(fixture.destination().join("run-link"))
                .expect("symlink should transfer")
                .file_type()
                .is_symlink(),
            true
        );
        assert_eq!(
            fs::read_link(fixture.destination().join("run-link"))
                .expect("symlink target should be readable"),
            PathBuf::from("run.sh")
        );
        assert_eq!(
            fs::metadata(fixture.destination().join("run.sh"))
                .expect("executable should transfer")
                .permissions()
                .mode()
                & 0o111,
            0o111
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_permission_changes_are_planned_as_overwrites() {
        let fixture = Fixture::new();
        let source = fixture.source().join("run.sh");
        let destination = fixture.destination().join("run.sh");
        write_file(&source, b"#!/bin/sh\necho same\n");
        write_file(&destination, b"#!/bin/sh\necho same\n");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755))
            .expect("source executable bit should be set");
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))
            .expect("destination should start non-executable");
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

        let analysis = FreshAnalysis::analyze(&fixture.profile())
            .expect("executable metadata difference should be analyzable");
        assert_eq!(
            analysis
                .plan()
                .action_for("run.sh")
                .expect("executable difference should be planned")
                .kind(),
            PlanActionKind::OverwriteDestination
        );
    }

    #[test]
    fn local_item_fidelity_does_not_copy_excluded_children_when_creating_directories() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("folder/keep.txt"), b"keep");
        write_file(&fixture.source().join("folder/skip.tmp"), b"skip");
        write_file(&fixture.destination().join("folder/skip.tmp"), b"existing skip");
        let profile = fixture.profile().with_exclusion("*.tmp");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("directory transfer should respect exclusions");

        assert_eq!(
            fs::read(fixture.destination().join("folder/keep.txt"))
                .expect("included child should transfer"),
            b"keep"
        );
        assert_eq!(
            fs::read(fixture.destination().join("folder/skip.tmp"))
                .expect("excluded destination child should remain"),
            b"existing skip"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_special_files_remain_visible_and_keep_the_source() {
        let fixture = Fixture::new();
        fs::create_dir_all(&fixture.source()).expect("source should be creatable");
        let special = fixture.source().join("named-pipe");
        let special_c = CString::new(special.as_os_str().as_bytes())
            .expect("fixture path should not contain a NUL byte");
        let result = unsafe { libc::mkfifo(special_c.as_ptr(), 0o644) };
        assert_eq!(result, 0, "special fixture should be creatable");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute(
                RunId::new(1),
                &fixture.profile(),
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("unsupported items should produce a reviewable report");

        assert_eq!(report.status(), RunReportStatus::CompletedWithReviewRequired);
        assert!(special.exists(), "unsupported source item must be preserved");
        assert!(!fixture.destination().join("named-pipe").exists());
        assert!(report
            .reconciliation()
            .expect("reconciliation should be persisted")
            .findings()
            .iter()
            .any(|finding| {
                finding.relative_path() == Path::new("named-pipe")
                    && finding.kind() == crate::ReconciliationFindingKind::Unverifiable
            }));
    }

    #[cfg(unix)]
    #[test]
    fn safe_delete_verifies_and_recovers_symlinks_without_following_targets() {
        let fixture = Fixture::new();
        write_file(&fixture.root.join("target.txt"), b"target remains");
        fs::create_dir_all(fixture.source()).expect("source should be creatable");
        symlink("../target.txt", fixture.source().join("link.txt"))
            .expect("source symlink should be creatable");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");
        let trash = fixture.root.join("trash");
        fs::create_dir_all(&trash).expect("trash should be creatable");
        let profile = fixture.profile().with_options(SyncOptions {
            safe_delete: true,
            deletion_method: Some(DeletionMethod::Trash),
            ..SyncOptions::default()
        });
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
            .expect("Safe Delete should support symlink items");

        assert_eq!(report.status(), RunReportStatus::Completed);
        assert!(!fixture.source().join("link.txt").exists());
        assert!(fixture.root.join("target.txt").exists());
        let recovered = trash.join("link.txt");
        assert!(fs::symlink_metadata(&recovered)
            .expect("recovered symlink should exist")
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(recovered).expect("recovered symlink target"),
            PathBuf::from("../target.txt")
        );
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
        let blocked = store
            .load_report(RunId::new(1))
            .expect("blocked precheck should leave a durable report");
        assert_eq!(blocked.status(), RunReportStatus::Blocked);
        assert!(blocked.blocked_reason().is_some());
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
            .execute_confirmed_with_authorizations(
                RunId::new(1),
                &confirmed,
                AuthorizationSnapshot::default(),
                &mut store,
                || calls.fetch_add(1, Ordering::Relaxed) >= 514,
                None,
                None,
            )
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
    fn resolution_run_executes_through_workflow_reconciliation_and_report_storage() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("conflict.txt"), b"peer A");
        write_file(&fixture.destination().join("conflict.txt"), b"peer B");
        let profile = fixture.profile().with_mode(SyncMode::Mirror);
        let resolution = crate::ResolutionRun::start(
            &profile,
            [crate::ConflictDecision::new(
                "conflict.txt",
                crate::ConflictResolution::KeepPeerA,
            )],
            None,
        )
        .expect("resolution review should start");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_resolution_run(
                RunId::new(1),
                &resolution,
                &profile,
                None,
                &LocalPrecheckProbe::default(),
                |analysis, actions| {
                    assert_eq!(analysis.conflict_review().entries().len(), 1);
                    assert_eq!(actions.len(), 1);
                    true
                },
                &mut store,
                || false,
            )
            .expect("the confirmed Resolution Run should execute");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert_eq!(fs::read(fixture.destination().join("conflict.txt")).unwrap(), b"peer A");
        assert_eq!(report.mirror_resolutions().len(), 1);
        assert_eq!(
            report.mirror_resolutions()[0].outcome(),
            crate::MirrorResolutionOutcome::Completed
        );
        assert_eq!(report.items().len(), 1);
        assert!(matches!(
            report.items()[0].outcome(),
            ActionOutcome::Completed
        ));
        assert!(report.can_mark_review_cleared());

        drop(store);
        let reopened = RunEvidenceStore::open(&fixture.database()).expect("reopen evidence store");
        let persisted = reopened.load_report(RunId::new(1)).expect("load report");
        assert_eq!(persisted.mirror_resolutions(), report.mirror_resolutions());
        assert_eq!(persisted.status(), RunReportStatus::Completed);
    }

    #[test]
    fn preserve_both_resolution_creates_collision_safe_copies_and_stays_review_required() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("conflict.txt"), b"peer A");
        write_file(&fixture.destination().join("conflict.txt"), b"peer B");
        write_file(&fixture.destination().join("conflict (Peer A).txt"), b"occupied");
        let profile = fixture.profile().with_mode(SyncMode::Mirror);
        let resolution = crate::ResolutionRun::start(
            &profile,
            [crate::ConflictDecision::new(
                "conflict.txt",
                crate::ConflictResolution::PreserveBoth,
            )],
            None,
        )
        .expect("preservation review should start");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_resolution_run(
                RunId::new(1),
                &resolution,
                &profile,
                None,
                &LocalPrecheckProbe::default(),
                |_, _| true,
                &mut store,
                || false,
            )
            .expect("preservation should complete without deleting either original");

        assert_eq!(report.status(), RunReportStatus::CompletedWithReviewRequired);
        assert_eq!(fs::read(fixture.source().join("conflict.txt")).unwrap(), b"peer A");
        assert_eq!(fs::read(fixture.destination().join("conflict.txt")).unwrap(), b"peer B");
        assert_eq!(report.mirror_resolutions().len(), 2);
        assert!(report.mirror_resolutions().iter().all(|item| {
            item.review_state() == crate::MirrorResolutionReviewState::ReviewLater
                && item.generated_path().is_some()
                && item.requires_review()
        }));
        for item in report.mirror_resolutions() {
            let target_root = match item.target_peer().expect("preserved target peer") {
                PeerSide::PeerA => fixture.source(),
                PeerSide::PeerB => fixture.destination(),
            };
            assert!(target_root.join(item.generated_path().unwrap()).exists());
        }
        assert!(!report.can_mark_review_cleared());

        let persisted = store.load_report(RunId::new(1)).expect("reload report");
        assert_eq!(persisted.mirror_resolutions(), report.mirror_resolutions());
    }

    #[test]
    fn preserved_copies_use_each_peer_effective_naming_policy() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("conflict.txt"), b"peer A");
        write_file(&fixture.destination().join("conflict.txt"), b"peer B");
        write_file(
            &fixture.destination().join("CONFLICT (PEER A).TXT"),
            b"occupied under a case-insensitive filesystem",
        );
        let profile = fixture.profile().with_mode(SyncMode::Mirror);
        let resolution = crate::ResolutionRun::start(
            &profile,
            [crate::ConflictDecision::new(
                "conflict.txt",
                crate::ConflictResolution::PreserveBoth,
            )],
            None,
        )
        .expect("preservation review should start");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_resolution_run(
                RunId::new(1),
                &resolution,
                &profile,
                None,
                &LocalPrecheckProbe::new(DestinationNamingPolicy::case_insensitive()),
                |_, _| true,
                &mut store,
                || false,
            )
            .expect("preservation should honor the effective naming policy");

        let peer_a_copy = report
            .mirror_resolutions()
            .iter()
            .find(|item| item.target_peer() == Some(PeerSide::PeerB))
            .expect("Peer A copy should target Peer B");
        assert_eq!(
            peer_a_copy.generated_path(),
            Some(Path::new("conflict (Peer A) (2).txt"))
        );
        assert_eq!(
            fs::read(fixture.destination().join(peer_a_copy.generated_path().unwrap())).unwrap(),
            b"peer A"
        );
    }

    #[test]
    fn deferred_resolution_is_reported_and_keeps_review_cleared_unavailable() {
        let fixture = Fixture::new();
        write_file(&fixture.source().join("conflict.txt"), b"peer A");
        write_file(&fixture.destination().join("conflict.txt"), b"peer B");
        let profile = fixture.profile().with_mode(SyncMode::Mirror);
        let resolution = crate::ResolutionRun::start(
            &profile,
            [crate::ConflictDecision::new(
                "conflict.txt",
                crate::ConflictResolution::Defer,
            )],
            None,
        )
        .expect("deferred review should start");
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_resolution_run(
                RunId::new(1),
                &resolution,
                &profile,
                None,
                &LocalPrecheckProbe::default(),
                |_, _| true,
                &mut store,
                || false,
            )
            .expect("deferring does not require a file mutation");

        assert_eq!(report.status(), RunReportStatus::CompletedWithReviewRequired);
        assert_eq!(report.mirror_resolutions().len(), 1);
        assert_eq!(
            report.mirror_resolutions()[0].outcome(),
            crate::MirrorResolutionOutcome::Deferred
        );
        assert!(!report.can_mark_review_cleared());
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
        assert_eq!(
            report
                .reconciliation()
                .expect("completed runs require reconciliation")
                .source_drain_status(),
            crate::SourceDrainStatus::Drained
        );
        assert!(report.can_mark_review_cleared());
        store
            .mark_review_cleared(RunId::new(1))
            .expect("reconciled run should be clearable");
        assert_eq!(
            store
                .load_report(RunId::new(1))
                .expect("cleared report")
                .status(),
            RunReportStatus::ReviewCleared
        );
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
    fn critical_file_reconciliation_preserves_source_and_allows_safe_resume() {
        let fixture = Fixture::new();
        let source = fixture.source().join("critical.txt");
        let destination = fixture.destination().join("critical.txt");
        let recovery_path = fixture.root.join("recovery-file");
        write_file(&source, b"critical source");
        fs::create_dir_all(fixture.destination()).expect("destination should be creatable");
        fs::write(&recovery_path, b"recovery path is unavailable")
            .expect("recovery fixture should be writable");
        let profile = fixture.profile().with_options(SyncOptions {
            safe_delete: true,
            deletion_method: Some(DeletionMethod::Trash),
            ..SyncOptions::default()
        });
        let workflow = RunWorkflow::new(RecoveryMethod::trash(&recovery_path));
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let blocked = workflow
            .execute(
                RunId::new(1),
                &profile,
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("an unresolved safety boundary should produce a report");

        assert_eq!(blocked.status(), RunReportStatus::CompletedWithReviewRequired);
        assert!(blocked
            .reconciliation()
            .expect("reconciliation should be persisted")
            .findings()
            .iter()
            .any(|finding| {
                finding.relative_path() == Path::new("critical.txt")
                    && finding.kind() == crate::ReconciliationFindingKind::Unavailable
            }));
        assert!(!blocked.can_mark_review_cleared());
        assert_eq!(fs::read(&source).expect("source must be preserved"), b"critical source");
        assert_eq!(fs::read(&destination).expect("destination should be installed"), b"critical source");

        drop(store);
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("reopened evidence store");
        let persisted_inventory = store
            .load_source_inventory(RunId::new(1))
            .expect("Source Inventory should survive restart");
        assert!(persisted_inventory.item("critical.txt").is_some());
        let persisted = store
            .load_report(RunId::new(1))
            .expect("reconciliation should survive restart");
        assert_eq!(persisted.status(), RunReportStatus::CompletedWithReviewRequired);
        assert!(persisted.reconciliation().is_some());

        fs::remove_file(&recovery_path).expect("unavailable recovery path should be removable");
        fs::create_dir(&recovery_path).expect("recovery folder should be restorable");
        let resumed = workflow
            .resume(
                RunId::new(1),
                &LocalPrecheckProbe::default(),
                |_| true,
                &mut store,
                || false,
            )
            .expect("resume should require fresh proof and then complete");

        assert_eq!(resumed.status(), RunReportStatus::Completed);
        assert_eq!(
            resumed
                .reconciliation()
                .expect("resumed reconciliation")
                .source_drain_status(),
            crate::SourceDrainStatus::Drained
        );
        assert!(!source.exists());
        assert_eq!(fs::read(destination).expect("destination should remain"), b"critical source");
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
        let probe = LocalPrecheckProbe::default();
        let source_volume_identity = probe
            .volume_identity(&fixture.source())
            .expect("source volume identity")
            .expect("source volume identity should be available");
        let destination_volume_identity = probe
            .volume_identity(&fixture.destination())
            .expect("destination volume identity")
            .expect("destination volume identity should be available");
        let snapshot = crate::RunSnapshot::from_profile_with_volume_identities(
            RunId::new(1),
            &profile,
            AuthorizationSnapshot::default(),
            Some(source_volume_identity),
            Some(destination_volume_identity),
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
                &probe,
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

    #[test]
    fn ssh_push_retries_transport_and_persists_verified_remote_content() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.source()).expect("local source");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.source().join("report.txt"), b"remote-safe transfer");
        let (profile, ssh) = ssh_profile(&fixture, false);
        let (credential, host_permit, precheck) = ssh_permits(&profile, &ssh);
        let backend = FakeSshBackend::new(fixture.remote()).with_retry_on_first_call();
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_ssh(
                RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || false,
            )
            .expect("SSH push should complete");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
        assert_eq!(backend.prechecks.load(Ordering::Relaxed), 2);
        assert_eq!(
            fs::read(fixture.remote().join("report.txt")).expect("remote destination"),
            b"remote-safe transfer"
        );
        assert!(fixture.source().join("report.txt").exists());
        assert!(report.snapshot().profile().peer_b().is_ssh());
        assert!(report.items()[0].journal().transfer_evidence().is_some());
    }

    #[test]
    fn ssh_pull_uses_the_same_confirmed_workflow_and_preserves_remote_source() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.destination()).expect("local destination");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.remote().join("report.txt"), b"remote source");
        let (profile, ssh) = ssh_profile(&fixture, true);
        let (credential, host_permit, precheck) = ssh_permits(&profile, &ssh);
        let backend = FakeSshBackend::new(fixture.remote());
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_ssh(
                RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || false,
            )
            .expect("SSH pull should complete");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert_eq!(backend.prechecks.load(Ordering::Relaxed), 2);
        assert_eq!(
            fs::read(fixture.destination().join("report.txt")).expect("local destination"),
            b"remote source"
        );
        assert!(fixture.remote().join("report.txt").exists());
        assert!(report.snapshot().profile().peer_b().is_ssh());
    }

    #[test]
    fn ssh_safe_delete_moves_remote_source_to_verified_trash_with_provenance() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.destination()).expect("local destination");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.remote().join("report.txt"), b"recoverable remote source");
        let (profile, ssh) = ssh_safe_delete_profile(&fixture);
        let (credential, host_permit, precheck) = ssh_permits_with_trash(&profile, &ssh, true);
        let backend = FakeSshBackend::new(fixture.remote()).with_remote_trash();
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_ssh(
                RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || false,
            )
            .expect("remote Safe Delete should complete");

        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert!(!fixture.remote().join("report.txt").exists());
        assert_eq!(
            fs::read(fixture.destination().join("report.txt")).expect("local destination"),
            b"recoverable remote source"
        );
        let recovery = fixture.root.join("trash/report.txt");
        assert_eq!(fs::read(&recovery).expect("remote recovery item"), b"recoverable remote source");
        let sidecar = recovery.with_extension("syncplus-manifest");
        let provenance = crate::RecoveryProvenance::read_sidecar(&sidecar)
            .expect("remote recovery sidecar");
        assert_eq!(provenance.peer(), "sync-user@backup.example.test:2222");
        assert_eq!(provenance.relative_path(), Path::new("report.txt"));
        assert_eq!(provenance.run_id(), RunId::new(1));
        assert_eq!(provenance.content().expect("digest provenance").size(), 25);
        let removal = report
            .items()
            .iter()
            .find_map(|item| item.journal().removal_result())
            .expect("remote removal should be journaled");
        let recovery_proof = ContentProof::from_path(&recovery).expect("recovery proof");
        assert_eq!(removal.evidence().recovery_size(), Some(recovery_proof.size()));
        assert_eq!(
            removal.evidence().recovery_sha256(),
            Some(recovery_proof.sha256())
        );
        assert_eq!(
            removal
                .evidence()
                .provenance()
                .expect("journal provenance")
                .relative_path(),
            Path::new("report.txt")
        );
        let reopened = RunEvidenceStore::open(&fixture.database()).expect("reopen evidence store");
        let reopened_report = reopened.load_report(RunId::new(1)).expect("reopened report");
        assert!(reopened_report.items().iter().any(|item| {
            item.journal()
                .removal_result()
                .is_some_and(|result| {
                    result
                        .evidence()
                        .provenance()
                        .is_some_and(|provenance| provenance.run_id() == RunId::new(1))
                        && result.evidence().recovery_size() == Some(25)
                        && result.evidence().recovery_sha256() == Some(recovery_proof.sha256())
                })
        }));
    }

    #[test]
    fn remote_recovery_failure_preserves_source_and_requires_review() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.destination()).expect("local destination");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.remote().join("report.txt"), b"keep on recovery failure");
        let (profile, ssh) = ssh_safe_delete_profile(&fixture);
        let (credential, host_permit, precheck) = ssh_permits_with_trash(&profile, &ssh, true);
        let backend = FakeSshBackend::new(fixture.remote())
            .with_remote_trash()
            .with_recovery_failure();
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_ssh(
                RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || false,
            )
            .expect("recovery failure should remain reviewable");

        assert_eq!(report.status(), RunReportStatus::RecoveryReview, "report: {report:?}");
        assert!(fixture.remote().join("report.txt").exists());
        assert!(!fixture.remote().join("trash/report.txt").exists());
        assert_eq!(backend.recovery_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unavailable_remote_trash_blocks_before_any_ssh_mutation() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.destination()).expect("local destination");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.remote().join("report.txt"), b"Trash is required");
        let (profile, ssh) = ssh_safe_delete_profile(&fixture);
        let (_, host_permit, valid_precheck) = ssh_permits_with_trash(&profile, &ssh, true);
        let backend = FakeSshBackend::new(fixture.remote());
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let result = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash"))).execute_ssh(
            RunId::new(1),
            &profile,
            &ResolvedSshCredential::Agent,
            &host_permit,
            &valid_precheck,
            &backend,
            |_| true,
            &mut store,
            || false,
        );

        assert!(matches!(result, Err(WorkflowError::Ssh(SshRunError::Precheck(_)))));
        assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
        assert_eq!(backend.recovery_calls.load(Ordering::Relaxed), 0);
        assert!(fixture.remote().join("report.txt").exists());
    }

    #[test]
    fn remote_permanent_removal_requires_separate_authorization() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.destination()).expect("local destination");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.remote().join("report.txt"), b"never remove silently");
        let (profile, ssh) = ssh_profile(&fixture, true);
        let profile = profile.with_options(SyncOptions {
            safe_delete: true,
            destination_cleanup: false,
            deletion_method: Some(DeletionMethod::PermanentRemoval),
            metadata: Default::default(),
            partial_transfer_policy: Default::default(),
            retry_policy: Default::default(),
        });
        let (credential, host_permit, precheck) = ssh_permits_with_trash(&profile, &ssh, false);
        let backend = FakeSshBackend::new(fixture.remote());
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let result = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash"))).execute_ssh(
            RunId::new(1),
            &profile,
            &credential,
            &host_permit,
            &precheck,
            &backend,
            |_| true,
            &mut store,
            || false,
        );

        assert!(matches!(
            result,
            Err(WorkflowError::InvalidRun(reason))
                if reason.contains("separate explicit authorization")
        ));
        assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
        assert_eq!(backend.recovery_calls.load(Ordering::Relaxed), 0);
        assert!(fixture.remote().join("report.txt").exists());
    }

    #[test]
    fn ssh_destination_digest_mismatch_keeps_the_action_unresolved_and_source_present() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.source()).expect("local source");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.source().join("report.txt"), b"must remain");
        let (profile, ssh) = ssh_profile(&fixture, false);
        let (credential, host_permit, precheck) = ssh_permits(&profile, &ssh);
        let backend = FakeSshBackend::new(fixture.remote()).with_mismatched_destination();
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let report = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")))
            .execute_ssh(
                RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || false,
            )
            .expect("a mismatch should return a reviewable report");

        assert_eq!(report.status(), RunReportStatus::CompletedWithReviewRequired);
        assert!(matches!(
            report.items()[0].outcome(),
            ActionOutcome::Unresolved(ActionReason::VerificationMismatch)
        ));
        assert!(fixture.source().join("report.txt").exists());
    }

    #[test]
    fn ssh_resume_reanalyzes_after_cancellation_before_starting_new_transfer() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.source()).expect("local source");
        fs::create_dir_all(fixture.remote()).expect("remote backing");
        write_file(&fixture.source().join("report.txt"), b"resume me");
        let (profile, ssh) = ssh_profile(&fixture, false);
        let (credential, host_permit, precheck) = ssh_permits(&profile, &ssh);
        let backend = FakeSshBackend::new(fixture.remote());
        let workflow = RunWorkflow::new(RecoveryMethod::trash(fixture.root.join("trash")));
        let mut store = RunEvidenceStore::open(&fixture.database()).expect("evidence store");

        let cancelled = workflow
            .execute_ssh(
                RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || true,
            )
            .expect("cancellation should produce a report");
        assert_eq!(cancelled.status(), RunReportStatus::Cancelled);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 0);

        let resumed = workflow
            .resume_ssh(
                RunId::new(1),
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut store,
                || false,
            )
            .expect("resume should repeat SSH Fresh Analysis and transfer");
        assert_eq!(resumed.run_id(), RunId::new(2));
        assert_eq!(resumed.status(), RunReportStatus::Completed, "report: {resumed:?}");
        assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    }
}
