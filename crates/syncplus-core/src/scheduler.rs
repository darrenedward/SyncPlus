use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::storage::{ClaimedScheduledRun, SyncProfileId};
use crate::{
    CredentialResolver, PrecheckProbe, RemotePrecheckPermit,
    RunEvidenceStore, RunReport, RunSnapshot, RunWorkflow, SecretStore, SshHostTrustPermit,
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
        workflow.execute_unattended(
            self.run_id,
            self.snapshot.profile(),
            self.snapshot.authorizations(),
            probe,
            store,
            should_cancel,
        )
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
                return Err(error);
            }
            (Some(_), Some(_)) => {
                let error = WorkflowError::InvalidRun(
                    "scheduled SSH execution does not support two SSH peers".to_owned(),
                );
                mark_unattended_blocked(store, self.run_id, self.snapshot().profile(), &error)?;
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
                return Err(error);
            }
        };
        workflow.execute_ssh_unattended(
            self.run_id,
            self.snapshot().profile(),
            self.snapshot().authorizations(),
            &credential,
            host_permit,
            precheck,
            backend,
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
        ApplicationMode, DeletionMethod, LocalPrecheckProbe, Peer, RecoveryMethod,
        PeerScope, PeerScopeLockRegistry, ProcessSupervisor, RunEvidenceStore, RunId,
        RunReportStatus, ScopeLockOwner, SyncOptions, SyncProfile,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(i64);

    impl SchedulerClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<i64, SchedulerError> {
            Ok(self.0)
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
}
