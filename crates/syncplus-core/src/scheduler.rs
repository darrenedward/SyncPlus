use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::storage::{ClaimedScheduledRun, SyncProfileId};
use crate::{
    CredentialResolver, PrecheckProbe, RemotePrecheckPermit,
    MissedScheduleDecision, PersistedSyncProfile, RunEvidenceStore, RunReport, RunSnapshot,
    RunWorkflow, RunReportStatus, PrecheckFailure, SecretStore, SshHostTrustPermit,
    SchedulerEventKind,
    SshRunBackend, SshRunMode, StorageError, WorkflowError, PeerScopeLockRegistry,
};
use crate::workflow::mark_unattended_blocked;

/// A clock boundary kept outside scheduling policy so due-run behavior can be
/// tested without changing the machine clock.
pub trait SchedulerClock {
    fn now_unix_seconds(&self) -> Result<i64, SchedulerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSchedulerClock;

impl SchedulerClock for SystemSchedulerClock {
    fn now_unix_seconds(&self) -> Result<i64, SchedulerError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                SchedulerError::Clock(format!("system clock is before Unix epoch: {error}"))
            })
            .and_then(|duration| {
                i64::try_from(duration.as_secs())
                    .map_err(|_| SchedulerError::Clock("system clock is out of range".to_owned()))
            })
    }
}

#[derive(Debug)]
pub enum SchedulerError {
    Storage(StorageError),
    Clock(String),
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "scheduler storage error: {error}"),
            Self::Clock(reason) => write!(formatter, "scheduler clock error: {reason}"),
        }
    }
}

impl std::error::Error for SchedulerError {}

impl From<StorageError> for SchedulerError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// A schedule occurrence claimed by this OS-user scheduler. The snapshot is
/// frozen before the claim is returned and is the only profile value a launch
/// may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRun {
    profile_id: SyncProfileId,
    run_id: crate::RunId,
    scheduled_at_unix_seconds: i64,
    snapshot: RunSnapshot,
}

impl ScheduledRun {
    pub const fn profile_id(&self) -> SyncProfileId {
        self.profile_id
    }

    pub const fn run_id(&self) -> crate::RunId {
        self.run_id
    }

    pub const fn scheduled_at_unix_seconds(&self) -> i64 {
        self.scheduled_at_unix_seconds
    }

    pub fn snapshot(&self) -> &RunSnapshot {
        &self.snapshot
    }

    /// Launch this occurrence through the shared RunWorkflow safety lifecycle.
    /// The scheduler supplies no confirmation shortcut to the workflow: the
    /// unattended entry point still performs precheck, Fresh Analysis,
    /// recheck, verification, reconciliation, and durable reporting.
    pub fn execute<P, F>(
        &self,
        workflow: &RunWorkflow,
        probe: &P,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        F: Fn() -> bool,
    {
        let result = workflow.execute_unattended(
            self.run_id,
            self.snapshot.profile(),
            self.snapshot.authorizations(),
            probe,
            store,
            should_cancel,
        );
        match &result {
            Ok(report) => self.record_outcome_event(store, report.status())?,
            Err(error) => {
                self.record_error_event(store, error)?;
                self.record_missed_schedule(store, error)?;
            }
        }
        result
    }

    /// Resolve the profile's selected SSH credential in unattended mode and
    /// launch through the shared SSH workflow. An interactive password source
    /// is rejected by the resolver before a prompt can be attempted.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_ssh<S, B, F>(
        &self,
        workflow: &RunWorkflow,
        resolver: &CredentialResolver<S>,
        host_permit: &SshHostTrustPermit,
        precheck: &RemotePrecheckPermit,
        backend: &B,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        S: SecretStore,
        B: SshRunBackend,
        F: Fn() -> bool,
    {
        let peer = match (
            self.snapshot().profile().peer_a().ssh_peer(),
            self.snapshot().profile().peer_b().ssh_peer(),
        ) {
            (Some(peer), None) | (None, Some(peer)) => peer,
            (None, None) => {
                let error = WorkflowError::InvalidRun(
                    "scheduled SSH execution requires exactly one SSH peer".to_owned(),
                );
                mark_unattended_blocked(store, self.run_id, self.snapshot().profile(), &error)?;
                self.record_missed_schedule(store, &error)?;
                self.record_error_event(store, &error)?;
                return Err(error);
            }
            (Some(_), Some(_)) => {
                let error = WorkflowError::InvalidRun(
                    "scheduled SSH execution does not support two SSH peers".to_owned(),
                );
                mark_unattended_blocked(store, self.run_id, self.snapshot().profile(), &error)?;
                self.record_missed_schedule(store, &error)?;
                self.record_error_event(store, &error)?;
                return Err(error);
            }
        };
        let credential = match resolver.resolve(peer, SshRunMode::Unattended, None) {
            Ok(credential) => credential,
            Err(error) => {
                let error = WorkflowError::InvalidRun(format!(
                    "scheduled SSH credential is unavailable: {error}"
                ));
                mark_unattended_blocked(store, self.run_id, self.snapshot().profile(), &error)?;
                self.record_missed_schedule(store, &error)?;
                self.record_error_event(store, &error)?;
                return Err(error);
            }
        };
        let result = workflow.execute_ssh_unattended(
            self.run_id,
            self.snapshot().profile(),
            self.snapshot().authorizations(),
            &credential,
            host_permit,
            precheck,
            backend,
            store,
            should_cancel,
        );
        match &result {
            Ok(report) => self.record_outcome_event(store, report.status())?,
            Err(error) => {
                self.record_error_event(store, error)?;
                self.record_missed_schedule(store, error)?;
            }
        }
        result
    }

    fn record_outcome_event(
        &self,
        store: &mut RunEvidenceStore,
        status: RunReportStatus,
    ) -> Result<(), WorkflowError> {
        let kind = match status {
            RunReportStatus::Completed => SchedulerEventKind::Completed,
            RunReportStatus::Failed => SchedulerEventKind::Failed,
            RunReportStatus::Cancelled => SchedulerEventKind::Cancelled,
            RunReportStatus::Interrupted => SchedulerEventKind::Interrupted,
            RunReportStatus::CompletedWithReviewRequired | RunReportStatus::RecoveryReview => {
                SchedulerEventKind::PendingReview
            }
            RunReportStatus::ReviewCleared => SchedulerEventKind::ReviewCleared,
            RunReportStatus::Blocked => SchedulerEventKind::BlockedPreflight,
            RunReportStatus::InProgress => SchedulerEventKind::Failed,
        };
        store.record_scheduler_event(self.profile_id, self.run_id, kind)?;
        Ok(())
    }

    fn record_error_event(
        &self,
        store: &mut RunEvidenceStore,
        error: &WorkflowError,
    ) -> Result<(), WorkflowError> {
        let kind = if matches!(error, WorkflowError::Precheck(PrecheckFailure::ScopeLocked(_))) {
            SchedulerEventKind::SkippedOverlap
        } else {
            store
                .load_report(self.run_id)
                .map(|report| match report.status() {
                    RunReportStatus::Blocked => SchedulerEventKind::BlockedPreflight,
                    RunReportStatus::Cancelled => SchedulerEventKind::Cancelled,
                    RunReportStatus::Interrupted => SchedulerEventKind::Interrupted,
                    RunReportStatus::CompletedWithReviewRequired | RunReportStatus::RecoveryReview => {
                        SchedulerEventKind::PendingReview
                    }
                    RunReportStatus::Failed | RunReportStatus::InProgress => SchedulerEventKind::Failed,
                    RunReportStatus::Completed | RunReportStatus::ReviewCleared => {
                        SchedulerEventKind::Failed
                    }
                })
                .unwrap_or(SchedulerEventKind::BlockedPreflight)
        };
        store.record_scheduler_event(self.profile_id, self.run_id, kind)?;
        Ok(())
    }

    fn record_missed_schedule(
        &self,
        store: &mut RunEvidenceStore,
        error: &WorkflowError,
    ) -> Result<(), WorkflowError> {
        let reason = format!(
            "{error}. The Scheduled Run did not complete. Next action: choose Yes, Run Now for a fresh interactive analysis, precheck, and confirmation, or No, Not Now."
        );
        store.record_missed_schedule(
            self.profile_id,
            self.run_id,
            self.scheduled_at_unix_seconds,
            &reason,
        )?;
        Ok(())
    }
}

impl crate::MissedScheduleNotice {
    /// Start one safe interactive catch-up from the current persisted profile.
    /// The missed Scheduled Run snapshot is never reused: this allocates a new
    /// Sync Run and delegates to the normal interactive workflow, including
    /// Fresh Analysis, Run Precheck, and the caller's confirmation callback.
    #[allow(clippy::too_many_arguments)]
    pub fn run_now<P, C, F>(
        &self,
        workflow: &RunWorkflow,
        current_profile: &PersistedSyncProfile,
        probe: &P,
        confirm: C,
        store: &mut RunEvidenceStore,
        should_cancel: F,
    ) -> Result<RunReport, WorkflowError>
    where
        P: PrecheckProbe,
        C: FnOnce(&crate::ConfirmedPlan) -> bool,
        F: Fn() -> bool,
    {
        if current_profile.id() != self.profile_id() {
            return Err(WorkflowError::InvalidRun(
                "missed schedule catch-up profile does not match the notice".to_owned(),
            ));
        }
        store.mark_missed_schedule_decision(self.notice_id(), MissedScheduleDecision::RunNow)?;
        let run_id = store.next_run_id()?;
        workflow.execute(
            run_id,
            current_profile.profile(),
            probe,
            confirm,
            store,
            should_cancel,
        )
    }
}

/// Per-user scheduler policy. It owns due-time claiming and the process-shared
/// scope-lock registry; the caller owns the user-level process/service lifetime
/// and supplies workflows configured with the returned registry.
#[derive(Debug, Clone)]
pub struct BackgroundScheduler<C = SystemSchedulerClock> {
    clock: C,
    scope_locks: PeerScopeLockRegistry,
}

impl BackgroundScheduler<SystemSchedulerClock> {
    pub fn new() -> Self {
        Self {
            clock: SystemSchedulerClock,
            scope_locks: PeerScopeLockRegistry::new(),
        }
    }
}

impl Default for BackgroundScheduler<SystemSchedulerClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SchedulerClock> BackgroundScheduler<C> {
    pub fn with_clock(clock: C) -> Self {
        Self {
            clock,
            scope_locks: PeerScopeLockRegistry::new(),
        }
    }

    /// Return the registry that must be shared by every workflow launched by
    /// this scheduler and by foreground workflows in the same process.
    pub fn scope_lock_registry(&self) -> PeerScopeLockRegistry {
        self.scope_locks.clone()
    }

    /// Claim each currently due enabled schedule once. Claiming advances the
    /// next occurrence and persists the frozen Run Report snapshot in one
    /// SQLite transaction, so concurrent user-level polls cannot duplicate it.
    pub fn poll_due(
        &self,
        store: &mut RunEvidenceStore,
    ) -> Result<Vec<ScheduledRun>, SchedulerError> {
        let now = self.clock.now_unix_seconds()?;
        let profiles = store.list_profiles()?;
        let mut runs = Vec::new();
        for profile in profiles
            .into_iter()
            .filter(|profile| profile.schedule_enabled())
        {
            if let Some(claim) = store.claim_due_schedule(profile.id(), now)? {
                runs.push(ScheduledRun::from_claim(claim));
            }
        }
        Ok(runs)
    }
}

impl ScheduledRun {
    fn from_claim(claim: ClaimedScheduledRun) -> Self {
        Self {
            profile_id: claim.profile_id(),
            run_id: claim.run_id(),
            scheduled_at_unix_seconds: claim.scheduled_at_unix_seconds(),
            snapshot: claim.snapshot().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{BackgroundScheduler, SchedulerClock, SchedulerError};
    use crate::{
        AccessSnapshot, ApplicationMode, CredentialResolver, DeletionMethod, LocalPrecheckProbe,
        MissedScheduleDecision, PasswordSource, Peer, PeerScope, PeerScopeLockRegistry,
        ProcessSupervisor, RecoveryEvidence, RecoveryMethod, RemotePrecheckObservation,
        RemotePrecheckRequest, RemoteRsyncCapability, RemoteSha256Capability, RemoteTrashCapability,
        ResolvedSshCredential, RunEvidenceStore, RunId, RunReportStatus, SchedulerEventKind,
        SchedulerNotificationSink, ScopeLockOwner, SecretStore, SecretStoreError, SecretValue,
        SshAuthentication, SshHostFingerprint, SshHostIdentityError, SshHostIdentityProbe,
        SshPeer, SshRemotePrecheck, SshRemotePrecheckProbe, SshRunBackend, SshRunError,
        SshTransferEvidence, SshTransferRequest, SourceInventory, SyncOptions, SyncProfile,
        SavedSecretReference,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(i64);

    impl SchedulerClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<i64, SchedulerError> {
            Ok(self.0)
        }
    }

    struct MissingSecretStore;

    impl SecretStore for MissingSecretStore {
        fn save(
            &self,
            _reference: &SavedSecretReference,
            _secret: &SecretValue,
        ) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn load(&self, _reference: &SavedSecretReference) -> Result<SecretValue, SecretStoreError> {
            Err(SecretStoreError::Missing)
        }

        fn delete(&self, _reference: &SavedSecretReference) -> Result<(), SecretStoreError> {
            Ok(())
        }
    }

    struct FixedHostProbe;

    impl SshHostIdentityProbe for FixedHostProbe {
        fn probe(
            &self,
            _peer: &SshPeer,
        ) -> Result<SshHostFingerprint, SshHostIdentityError> {
            Ok(SshHostFingerprint::sha256([4; 32]))
        }
    }

    struct PassingRemoteProbe;

    impl SshRemotePrecheckProbe for PassingRemoteProbe {
        fn probe(
            &self,
            _peer: &SshPeer,
            _credential: &ResolvedSshCredential,
            _host_permit: &crate::SshHostTrustPermit,
            _request: &RemotePrecheckRequest,
        ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
            Ok(RemotePrecheckObservation::new(
                true,
                AccessSnapshot::new(true, true, true),
                RemoteRsyncCapability::Compatible,
                RemoteSha256Capability::Available,
                RemoteTrashCapability::unavailable(),
            ))
        }
    }

    struct UnusedSshBackend;

    impl SshHostIdentityProbe for UnusedSshBackend {
        fn probe(
            &self,
            _peer: &SshPeer,
        ) -> Result<SshHostFingerprint, SshHostIdentityError> {
            Ok(SshHostFingerprint::sha256([4; 32]))
        }
    }

    impl SshRemotePrecheckProbe for UnusedSshBackend {
        fn probe(
            &self,
            _peer: &SshPeer,
            _credential: &ResolvedSshCredential,
            _host_permit: &crate::SshHostTrustPermit,
            _request: &RemotePrecheckRequest,
        ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
            unreachable!("missing credential must stop before remote probing")
        }
    }

    impl SshRunBackend for UnusedSshBackend {
        fn inventory(
            &self,
            _peer: &SshPeer,
            _credential: &ResolvedSshCredential,
            _host_permit: &crate::SshHostTrustPermit,
            _exclusions: &[String],
        ) -> Result<SourceInventory, SshRunError> {
            unreachable!("missing credential must stop before inventory")
        }

        fn transfer(
            &self,
            _request: &SshTransferRequest<'_>,
            _should_cancel: &dyn Fn() -> bool,
            _progress: &mut dyn FnMut(u64),
        ) -> Result<SshTransferEvidence, SshRunError> {
            unreachable!("missing credential must stop before transfer")
        }

        fn recover_source(
            &self,
            _request: &SshTransferRequest<'_>,
            _transfer: &SshTransferEvidence,
            _should_cancel: &dyn Fn() -> bool,
        ) -> Result<RecoveryEvidence, SshRunError> {
            unreachable!("missing credential must stop before recovery")
        }
    }

    fn fixture_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "syncplus-scheduler-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn poll_due_claims_once_and_launches_a_durable_unattended_run() {
        let root = fixture_root();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).expect("source");
        fs::create_dir_all(&destination).expect("destination");
        fs::write(source.join("scheduled.txt"), b"scheduled data").expect("source file");
        let profile = SyncProfile::new(
            "scheduled profile",
            Peer::new("source", source.clone()),
            Peer::new("destination", destination.clone()),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");

        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        let mut claims = scheduler.poll_due(&mut store).expect("due poll");
        assert_eq!(claims.len(), 1);
        assert!(scheduler.poll_due(&mut store).expect("second due poll").is_empty());
        let claim = claims.pop().expect("claim");
        let workflow = crate::RunWorkflow::new(RecoveryMethod::trash(root.join("trash")));
        let report = claim
            .execute(&workflow, &LocalPrecheckProbe::default(), &mut store, || false)
            .expect("scheduled run");
        assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
        assert_eq!(
            fs::read(destination.join("scheduled.txt")).expect("destination file"),
            b"scheduled data"
        );
        assert_eq!(
            store
                .load_report(claim.run_id())
                .expect("durable report")
                .status(),
            RunReportStatus::Completed
        );
        let snapshot = store.load_snapshot(claim.run_id()).expect("snapshot");
        assert!(snapshot.peer_a_volume_identity().is_some());
        assert!(snapshot.peer_b_volume_identity().is_some());
        let events = store.list_scheduler_events().expect("scheduler events");
        assert!(events.iter().any(|event| {
            event.run_id() == claim.run_id() && event.kind() == SchedulerEventKind::Completed
        }));
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn disabled_schedule_is_not_claimed_by_the_background_scheduler() {
        let profile = SyncProfile::new(
            "disabled schedule profile",
            Peer::new("source", PathBuf::from("/source")),
            Peer::new("destination", PathBuf::from("/destination")),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(
            1,
            "UTC",
            false,
            None,
        )
        .expect("disabled schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Simple, 100)
            .expect("schedule update");

        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        assert!(scheduler.poll_due(&mut store).expect("due poll").is_empty());
        assert_eq!(
            store
                .list_profiles()
                .expect("profiles")
                .into_iter()
                .next()
                .expect("profile")
                .schedule()
                .expect("schedule")
                .next_run_at_unix_seconds(),
            None,
            "a disabled schedule remains configured but has no next occurrence"
        );
    }

    #[test]
    fn scheduled_run_snapshot_freezes_transport_and_authorization_before_profile_edits() {
        let profile = SyncProfile::new(
            "snapshot schedule profile",
            Peer::new("source", PathBuf::from("/source")),
            Peer::new("destination", PathBuf::from("/destination")),
        )
        .with_options(SyncOptions {
            safe_delete: true,
            deletion_method: Some(DeletionMethod::Trash),
            bandwidth_limit_kib_per_second: Some(512),
            ..SyncOptions::default()
        });
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store
            .create_profile_with_authorizations(
                &profile,
                crate::AuthorizationSnapshot::new(true, false),
            )
            .expect("authorized profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");

        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        let claim = scheduler
            .poll_due(&mut store)
            .expect("due poll")
            .pop()
            .expect("claim");

        let edited = profile.clone().with_options(SyncOptions {
            bandwidth_limit_kib_per_second: Some(1024),
            ..SyncOptions::default()
        });
        store
            .update_profile(persisted.id(), &edited)
            .expect("edit profile after claim");

        assert_eq!(
            claim
                .snapshot()
                .validated_options()
                .bandwidth_limit_kib_per_second(),
            Some(512)
        );
        assert!(claim
            .snapshot()
            .authorizations()
            .allow_unattended_destructive());
        assert_eq!(
            store
                .load_profile(persisted.id())
                .expect("current profile")
                .expect("profile")
                .profile()
                .options()
                .bandwidth_limit_kib_per_second,
            Some(1024)
        );
    }

    #[test]
    fn scheduled_ssh_run_missing_saved_credential_is_blocked_before_remote_work() {
        let root = fixture_root();
        fs::create_dir_all(&root).expect("fixture root");
        let source = root.join("source");
        fs::create_dir_all(&source).expect("source");
        fs::write(source.join("must-remain.txt"), b"source data").expect("source file");
        let reference = SavedSecretReference::new("missing-ssh-password").expect("reference");
        let remote = SshPeer::new(
            "backup.example.test",
            "sync-user",
            2222,
            None,
            SshAuthentication::SavedPassword(reference),
            "/srv/sync",
        )
        .expect("SSH peer");
        let profile = SyncProfile::new(
            "scheduled SSH profile",
            Peer::new("source", source.clone()),
            Peer::from_ssh("destination", remote.clone()),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");
        let claim = BackgroundScheduler::with_clock(FixedClock(100))
            .poll_due(&mut store)
            .expect("due poll")
            .pop()
            .expect("claim");

        let trust_store = RunEvidenceStore::open_in_memory().expect("trust store");
        let mut trust = crate::SshHostTrustController::new(trust_store);
        let decision = trust
            .inspect(&remote, &FixedHostProbe)
            .expect("host inspection");
        trust
            .approve(&remote, &decision, crate::HostTrustMode::Interactive)
            .expect("host approval");
        let host_permit = trust
            .pre_mutation_permit(&remote, &FixedHostProbe)
            .expect("host permit");
        let credential = ResolvedSshCredential::Password {
            source: PasswordSource::SavedSecret,
            secret: SecretValue::new("test-only-secret"),
        };
        let (_, request) = RemotePrecheckRequest::from_profile(&profile).expect("SSH request");
        let precheck = SshRemotePrecheck::check(
            &remote,
            &credential,
            &host_permit,
            &request,
            &PassingRemoteProbe,
        )
        .expect("precheck");
        let precheck = precheck.require_passed().expect("passing precheck");
        let workflow = crate::RunWorkflow::new(RecoveryMethod::trash(root.join("trash")));
        let result = claim.execute_ssh(
            &workflow,
            &CredentialResolver::new(MissingSecretStore),
            &host_permit,
            &precheck,
            &UnusedSshBackend,
            &mut store,
            || false,
        );

        assert!(result.is_err(), "missing unattended credential must block the run");
        assert!(source.join("must-remain.txt").exists());
        assert_eq!(
            store.load_report(claim.run_id()).expect("report").status(),
            RunReportStatus::Blocked
        );
        assert!(store.list_scheduler_events().expect("events").iter().any(|event| {
            event.run_id() == claim.run_id() && event.kind() == SchedulerEventKind::BlockedPreflight
        }));
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn scheduler_notification_uses_only_a_safe_report_intent() {
        let root = fixture_root();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).expect("source");
        fs::create_dir_all(&destination).expect("destination");
        fs::write(source.join("scheduled.txt"), b"scheduled data").expect("source file");
        let profile = SyncProfile::new(
            "notification profile",
            Peer::new("source", source.clone()),
            Peer::new("destination", destination),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");
        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        let claim = scheduler
            .poll_due(&mut store)
            .expect("due poll")
            .pop()
            .expect("claim");
        let workflow = crate::RunWorkflow::new(RecoveryMethod::trash(root.join("trash")));
        claim
            .execute(&workflow, &LocalPrecheckProbe::default(), &mut store, || false)
            .expect("scheduled run");

        let event = store
            .list_scheduler_events()
            .expect("events")
            .into_iter()
            .find(|event| event.kind() == SchedulerEventKind::Completed)
            .expect("completed event");
        let notification = event.notification();
        assert_eq!(notification.event_id(), event.event_id());
        assert_eq!(notification.action(), crate::SchedulerNotificationAction::OpenReport(claim.run_id()));
        assert!(!notification.reason().is_empty());
        assert!(!notification.next_action().is_empty());
        assert!(!notification.reason().contains("scheduled data"));
        assert!(!notification.next_action().contains("scheduled data"));

        struct FailingSink;
        impl SchedulerNotificationSink for FailingSink {
            fn deliver(
                &mut self,
                _notification: &crate::SchedulerNotification,
            ) -> Result<(), crate::NotificationDeliveryError> {
                Err(crate::NotificationDeliveryError::Unavailable)
            }
        }
        let report_before = store.load_report(claim.run_id()).expect("report before delivery");
        assert!(store
            .deliver_scheduler_notification(event.event_id(), &mut FailingSink)
            .is_err());
        assert_eq!(
            store.load_report(claim.run_id()).expect("report after delivery").status(),
            report_before.status()
        );
        assert!(store
            .list_scheduler_events()
            .expect("events after delivery")
            .iter()
            .any(|candidate| candidate.event_id() == event.event_id()));
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn unattended_destructive_schedule_requires_explicit_authorization() {
        let root = fixture_root();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).expect("source");
        fs::create_dir_all(&destination).expect("destination");
        fs::write(source.join("must-remain.txt"), b"source data").expect("source file");
        let profile = SyncProfile::new(
            "destructive scheduled profile",
            Peer::new("source", source.clone()),
            Peer::new("destination", destination),
        )
        .with_options(SyncOptions {
            safe_delete: true,
            deletion_method: Some(DeletionMethod::Trash),
            ..SyncOptions::default()
        });
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");
        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        let claim = scheduler
            .poll_due(&mut store)
            .expect("due poll")
            .pop()
            .expect("claim");
        let workflow = crate::RunWorkflow::new(RecoveryMethod::trash(root.join("trash")));
        assert!(claim
            .execute(&workflow, &LocalPrecheckProbe::default(), &mut store, || false)
            .is_err());
        let report = store.load_report(claim.run_id()).expect("report");
        assert_eq!(report.status(), RunReportStatus::Blocked);
        let blocked_reason = report.blocked_reason().expect("blocked reason");
        assert!(blocked_reason.contains("Sync Profile 'destructive scheduled profile'"));
        assert!(blocked_reason.contains("source"));
        assert!(blocked_reason.contains(source.to_string_lossy().as_ref()));
        assert!(blocked_reason.contains("Next action:"));
        assert!(!blocked_reason.contains("source data"));
        assert!(source.join("must-remain.txt").exists());
        let events = store.list_scheduler_events().expect("scheduler events");
        assert!(events.iter().any(|event| {
            event.run_id() == claim.run_id() && event.kind() == SchedulerEventKind::BlockedPreflight
        }));
        let missed = events
            .iter()
            .find(|event| event.run_id() == claim.run_id() && event.kind() == SchedulerEventKind::Missed)
            .expect("missed event");
        assert_eq!(
            missed.notification().action(),
            crate::SchedulerNotificationAction::StartInteractiveCatchUp(
                store
                    .list_missed_schedule_notices()
                    .expect("missed notices")
                    .first()
                    .expect("notice")
                    .notice_id()
            )
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn overlapping_scheduled_run_is_recorded_as_skipped_without_mutation() {
        let root = fixture_root();
        let active_source = root.join("active-source");
        let scheduled_source = active_source.join("nested");
        let scheduled_destination = root.join("scheduled-destination");
        fs::create_dir_all(&scheduled_source).expect("scheduled source");
        fs::create_dir_all(&scheduled_destination).expect("scheduled destination");
        fs::write(scheduled_source.join("must-remain.txt"), b"source data").expect("source file");

        let profile = SyncProfile::new(
            "overlapping scheduled profile",
            Peer::new("source", scheduled_source.clone()),
            Peer::new("destination", scheduled_destination.clone()),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");
        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        let claim = scheduler
            .poll_due(&mut store)
            .expect("due poll")
            .pop()
            .expect("claim");

        let registry = PeerScopeLockRegistry::new();
        let _active_lock = registry
            .acquire(
                ScopeLockOwner::new("active profile", RunId::new(900)),
                [PeerScope::new(&active_source)],
            )
            .expect("active scope lock");
        let workflow = crate::RunWorkflow::with_scope_lock_registry(
            ProcessSupervisor::default(),
            RecoveryMethod::trash(root.join("trash")),
            registry,
        );

        let error = claim
            .execute(&workflow, &LocalPrecheckProbe::default(), &mut store, || false)
            .expect_err("an overlapping scheduled run must be skipped");
        assert!(matches!(error, crate::WorkflowError::Precheck(crate::PrecheckFailure::ScopeLocked(_))));
        let report = store.load_report(claim.run_id()).expect("blocked report");
        assert_eq!(report.status(), RunReportStatus::Blocked);
        let reason = report.blocked_reason().expect("skip reason");
        assert!(reason.contains("Scheduled Run skipped"), "reason: {reason}");
        assert!(reason.contains("active profile"), "reason: {reason}");
        assert!(!scheduled_destination.join("must-remain.txt").exists());
        assert!(scheduled_source.join("must-remain.txt").exists());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn unavailable_scheduled_runs_create_one_coalesced_missed_notice() {
        let root = fixture_root();
        let source = root.join("source-that-is-unavailable");
        let destination = root.join("destination");
        fs::create_dir_all(&destination).expect("destination");
        let profile = SyncProfile::new(
            "missed schedule profile",
            Peer::new("source", source.clone()),
            Peer::new("destination", destination),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");
        let workflow = crate::RunWorkflow::new(RecoveryMethod::trash(root.join("trash")));

        for (now, expected_scheduled_at) in [(100, 100), (160, 160)] {
            let scheduler = BackgroundScheduler::with_clock(FixedClock(now));
            let claim = scheduler
                .poll_due(&mut store)
                .expect("due poll")
                .pop()
                .expect("claim");
            assert_eq!(claim.scheduled_at_unix_seconds(), expected_scheduled_at);
            assert!(claim
                .execute(&workflow, &LocalPrecheckProbe::default(), &mut store, || false)
                .is_err());
        }

        let notices = store
            .list_missed_schedule_notices()
            .expect("missed notices");
        assert_eq!(notices.len(), 1);
        let notice = &notices[0];
        assert_eq!(notice.decision(), MissedScheduleDecision::Pending);
        assert_eq!(notice.missed_count(), 2);
        assert_eq!(notice.latest_scheduled_at_unix_seconds(), 160);
        assert!(notice.reason().contains("source-that-is-unavailable"));
        assert!(notice.reason().contains("Next action:"));
        store
            .mark_missed_schedule_decision(notice.notice_id(), MissedScheduleDecision::NotNow)
            .expect("Not Now decision");
        assert_eq!(
            store
                .load_missed_schedule_notice(notice.notice_id())
                .expect("notice lookup")
                .expect("notice remains visible")
                .decision(),
            MissedScheduleDecision::NotNow
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn run_now_uses_a_new_interactive_run_and_current_profile() {
        let root = fixture_root();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&destination).expect("destination");
        let profile = SyncProfile::new(
            "interactive catch-up profile",
            Peer::new("source", source.clone()),
            Peer::new("destination", destination.clone()),
        );
        let mut store = RunEvidenceStore::open_in_memory().expect("store");
        let persisted = store.create_profile(&profile).expect("profile");
        let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
            .expect("schedule");
        store
            .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
            .expect("schedule update");
        let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
        let claim = scheduler
            .poll_due(&mut store)
            .expect("due poll")
            .pop()
            .expect("claim");
        let workflow = crate::RunWorkflow::new(RecoveryMethod::trash(root.join("trash")));
        assert!(claim
            .execute(&workflow, &LocalPrecheckProbe::default(), &mut store, || false)
            .is_err());
        let notice = store
            .list_missed_schedule_notices()
            .expect("missed notices")
            .pop()
            .expect("notice");

        fs::create_dir_all(&source).expect("source becomes available");
        fs::write(source.join("catch-up.txt"), b"fresh catch-up data").expect("source file");
        let current_profile = store
            .load_profile(persisted.id())
            .expect("current profile lookup")
            .expect("current profile");
        let confirmation_called = std::cell::Cell::new(false);
        let report = notice
            .run_now(
                &workflow,
                &current_profile,
                &LocalPrecheckProbe::default(),
                |_| {
                    confirmation_called.set(true);
                    true
                },
                &mut store,
                || false,
            )
            .expect("interactive catch-up");

        assert!(confirmation_called.get(), "normal confirmation must run");
        assert_ne!(report.run_id(), claim.run_id());
        assert_eq!(report.status(), RunReportStatus::Completed);
        assert_eq!(
            fs::read(destination.join("catch-up.txt")).expect("catch-up destination"),
            b"fresh catch-up data"
        );
        assert_eq!(
            store
                .load_missed_schedule_notice(notice.notice_id())
                .expect("notice lookup")
                .expect("notice remains visible")
                .decision(),
            MissedScheduleDecision::RunNow
        );
        assert_eq!(
            store.load_report(claim.run_id()).expect("old report").status(),
            RunReportStatus::Blocked
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
