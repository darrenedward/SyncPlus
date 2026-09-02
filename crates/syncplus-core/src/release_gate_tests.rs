use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    ApplicationMode, AuthorizationSnapshot, BackgroundScheduler, CompletionReconciliation,
    DeletionMethod, DestinationNamingPolicy, FreshAnalysis, LocalPrecheckProbe, OneWaySource,
    Peer, RecoveryMethod, RunEvidenceStore, RunId, RunReportStatus, RunWorkflow, SchedulerClock,
    SchedulerError, SourceDrainStatus, SyncOptions, SyncProfile, PrecheckProbe,
};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
struct FixedClock(i64);

impl SchedulerClock for FixedClock {
    fn now_unix_seconds(&self) -> Result<i64, SchedulerError> {
        Ok(self.0)
    }
}

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    recovery: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "syncplus-release-gate-{}",
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let source = root.join("source");
        let destination = root.join("destination");
        let recovery = root.join("recovery");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::create_dir_all(&recovery).unwrap();
        Self {
            root,
            source,
            destination,
            recovery,
        }
    }

    fn profile(&self) -> SyncProfile {
        SyncProfile::new(
            "release gate",
            Peer::new("source", self.source.clone()),
            Peer::new("destination", self.destination.clone()),
        )
            .with_source(OneWaySource::PeerA)
            .with_options(SyncOptions {
                safe_delete: true,
                deletion_method: Some(DeletionMethod::Trash),
                ..SyncOptions::default()
            })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn local_safe_delete_runs_through_real_rsync_and_recovery() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("report.txt"), b"release-gate").unwrap();
    let profile = fixture.profile();
    let probe = LocalPrecheckProbe::default();
    assert!(fixture.source.is_dir());
    assert!(fixture.destination.is_dir());
    assert!(crate::PrecheckProbe::peer_available(&probe, &fixture.source, false).unwrap());
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let report = RunWorkflow::new(RecoveryMethod::trash(fixture.recovery.clone()))
        .execute(RunId::new(1), &profile, &probe, |_| true, &mut store, || false)
        .expect("real local Safe Delete should complete");
    assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
    assert!(!fixture.source.join("report.txt").exists());
    assert_eq!(fs::read(fixture.destination.join("report.txt")).unwrap(), b"release-gate");
    assert!(fixture.recovery.join("report.txt").exists());
}

#[test]
fn scheduled_recoverable_safe_delete_requires_authorization_and_persists_recovery() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("scheduled-safe-delete.txt"), b"scheduled recovery").unwrap();
    let profile = fixture.profile();
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let persisted = store
        .create_profile_with_authorizations(&profile, AuthorizationSnapshot::new(true, false))
        .unwrap();
    let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
        .unwrap();
    store
        .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
        .unwrap();

    let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
    let claim = scheduler.poll_due(&mut store).unwrap().pop().unwrap();
    let report = claim
        .execute(
            &RunWorkflow::new(RecoveryMethod::trash(fixture.recovery.clone())),
            &LocalPrecheckProbe::default(),
            &mut store,
            || false,
        )
        .expect("authorized scheduled Safe Delete should complete");

    assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
    assert!(!fixture.source.join("scheduled-safe-delete.txt").exists());
    assert_eq!(
        fs::read(fixture.destination.join("scheduled-safe-delete.txt")).unwrap(),
        b"scheduled recovery"
    );
    assert!(fixture.recovery.join("scheduled-safe-delete.txt").exists());
    assert!(store
        .load_snapshot(claim.run_id())
        .unwrap()
        .authorizations()
        .allow_unattended_destructive());
    assert!(store
        .list_scheduler_events()
        .unwrap()
        .iter()
        .any(|event| event.run_id() == claim.run_id()
            && event.kind() == crate::SchedulerEventKind::Completed));
}

#[test]
fn scheduled_destination_cleanup_keeps_unverified_orphan_for_review() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("current.txt"), b"current source").unwrap();
    fs::write(fixture.destination.join("orphan.txt"), b"destination orphan").unwrap();
    let profile = fixture.profile().with_options(SyncOptions {
        safe_delete: false,
        destination_cleanup: true,
        deletion_method: Some(DeletionMethod::Trash),
        ..SyncOptions::default()
    });
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let persisted = store
        .create_profile_with_authorizations(&profile, AuthorizationSnapshot::new(true, false))
        .unwrap();
    let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
        .unwrap();
    store
        .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
        .unwrap();
    let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
    let claim = scheduler.poll_due(&mut store).unwrap().pop().unwrap();

    let report = claim
        .execute(
            &RunWorkflow::new(RecoveryMethod::trash(fixture.recovery.clone())),
            &LocalPrecheckProbe::default(),
            &mut store,
            || false,
        )
        .expect("authorized scheduled Destination Cleanup should complete");

    assert_eq!(
        report.status(),
        RunReportStatus::CompletedWithReviewRequired,
        "report: {report:?}"
    );
    assert!(fixture.source.join("current.txt").exists());
    assert_eq!(
        fs::read(fixture.destination.join("current.txt")).unwrap(),
        b"current source"
    );
    assert!(fixture.destination.join("orphan.txt").exists());
    assert!(!fixture.recovery.join("orphan.txt").exists());
}

#[test]
fn scheduled_permanent_removal_requires_separate_authorization() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("permanent-removal.txt"), b"must remain").unwrap();
    let profile = SyncProfile::new(
        "release gate permanent removal",
        Peer::new("source", fixture.source.clone()),
        Peer::new("destination", fixture.destination.clone()),
    )
    .with_source(OneWaySource::PeerA)
    .with_options(SyncOptions {
        safe_delete: true,
        deletion_method: Some(DeletionMethod::PermanentRemoval),
        ..SyncOptions::default()
    });
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let persisted = store
        .create_profile_with_authorizations(&profile, AuthorizationSnapshot::new(true, false))
        .unwrap();
    let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
        .unwrap();
    store
        .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
        .unwrap();
    let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
    let claim = scheduler.poll_due(&mut store).unwrap().pop().unwrap();

    let error = claim
        .execute(
            &RunWorkflow::new(RecoveryMethod::permanent_removal()),
            &LocalPrecheckProbe::default(),
            &mut store,
            || false,
        )
        .expect_err("Permanent Removal needs its separate unattended authorization");
    assert!(error
        .to_string()
        .contains("scheduled Permanent Removal requires separate explicit authorization"));
    assert!(fixture.source.join("permanent-removal.txt").exists());
    assert_eq!(
        store.load_report(claim.run_id()).unwrap().status(),
        RunReportStatus::Blocked
    );
}

#[test]
fn scheduled_offline_peer_is_blocked_without_mutation() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("offline-peer.txt"), b"must remain").unwrap();
    let profile = fixture.profile();
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let persisted = store
        .create_profile_with_authorizations(&profile, AuthorizationSnapshot::new(true, false))
        .unwrap();
    let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
        .unwrap();
    store
        .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
        .unwrap();
    let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
    let claim = scheduler.poll_due(&mut store).unwrap().pop().unwrap();

    fs::remove_dir_all(&fixture.source).unwrap();
    assert!(claim
        .execute(
            &RunWorkflow::new(RecoveryMethod::trash(fixture.recovery.clone())),
            &LocalPrecheckProbe::default(),
            &mut store,
            || false,
        )
        .is_err());
    assert_eq!(
        store.load_report(claim.run_id()).unwrap().status(),
        RunReportStatus::Blocked
    );
    assert!(store
        .list_scheduler_events()
        .unwrap()
        .iter()
        .any(|event| event.run_id() == claim.run_id()
            && event.kind() == crate::SchedulerEventKind::Missed));
    assert!(!fixture.destination.join("offline-peer.txt").exists());
}

#[test]
fn scheduled_destination_disconnect_preserves_source() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("destination-disconnect.txt"), b"must remain").unwrap();
    let profile = fixture.profile();
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let persisted = store
        .create_profile_with_authorizations(&profile, AuthorizationSnapshot::new(true, false))
        .unwrap();
    let schedule = crate::ScheduleDefinition::new_with_next_run_at(1, "UTC", true, Some(100))
        .unwrap();
    store
        .update_schedule_at(persisted.id(), Some(schedule), ApplicationMode::Advanced, 100)
        .unwrap();
    let scheduler = BackgroundScheduler::with_clock(FixedClock(100));
    let claim = scheduler.poll_due(&mut store).unwrap().pop().unwrap();

    fs::remove_dir_all(&fixture.destination).unwrap();
    assert!(claim
        .execute(
            &RunWorkflow::new(RecoveryMethod::trash(fixture.recovery.clone())),
            &LocalPrecheckProbe::default(),
            &mut store,
            || false,
        )
        .is_err());
    assert!(fixture.source.join("destination-disconnect.txt").exists());
    assert_eq!(
        store.load_report(claim.run_id()).unwrap().status(),
        RunReportStatus::Blocked
    );
}

#[cfg(unix)]
#[test]
#[ignore = "release gate: requires a mounted case-insensitive or restricted filesystem"]
fn disposable_external_filesystem_detects_collisions_before_mutation() {
    let filesystem_root = std::env::var_os("SYNCPLUS_EXTERNAL_FILESYSTEM_ROOT")
        .map(PathBuf::from)
        .or_else(|| {
            [PathBuf::from("/mnt/elements"), PathBuf::from("/media")]
                .into_iter()
                .find(|path| path.is_dir())
        })
        .expect("release gate requires a mounted external filesystem");
    let fixture_root = filesystem_root.join(format!(
        ".syncplus-release-gate-{}-{}",
        std::process::id(),
        NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&fixture_root).expect("external fixture should be creatable");
    struct ExternalFixture(PathBuf);
    impl Drop for ExternalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _fixture = ExternalFixture(fixture_root.clone());
    let source = fixture_root.join("source");
    let destination = fixture_root.join("destination");
    fs::create_dir_all(&source).expect("external source");
    fs::create_dir_all(&destination).expect("external destination");
    fs::write(source.join("Report.txt"), b"source").expect("source collision");
    fs::write(source.join("bad:name"), b"invalid name").expect("source invalid name");
    fs::write(destination.join("report.txt"), b"existing").expect("destination collision");

    let conflicts = LocalPrecheckProbe::new(DestinationNamingPolicy::windows_compatible())
        .naming_conflicts(&source, &destination, &[])
        .expect("external naming precheck should complete");
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::CaseInsensitiveCollision));
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::InvalidCharacter));
    assert_eq!(fs::read(destination.join("report.txt")).unwrap(), b"existing");
}

#[test]
fn excluded_source_items_keep_source_not_empty_in_real_reconciliation() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("keep.tmp"), b"excluded").unwrap();
    let profile = fixture.profile().with_exclusions(["*.tmp".to_owned()]);
    let analysis = FreshAnalysis::analyze(&profile).unwrap();
    let inventory = crate::SourceInventorySnapshot::from_inventory(analysis.source_inventory());
    let reconciliation = CompletionReconciliation::reconcile(&profile, &inventory, &analysis, &[]);
    assert_eq!(reconciliation.source_drain_status(), SourceDrainStatus::NotEmpty);
    let finding = reconciliation.findings().iter().find(|finding| finding.relative_path() == PathBuf::from("keep.tmp")).expect("excluded item should be reported");
    assert!(matches!(finding.reason(), crate::ReconciliationReason::Excluded));
}
