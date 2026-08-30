use std::{fs, path::PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    ActionOutcome, ActionReason, AuthorizationSnapshot, DeletionMethod, FileIdentity, ItemType,
    JournalEvent, OneWaySource, Peer, PeerSide, PlanActionKind, PreActionState, RecoveryEvidence,
    RecoveryResolution, RunEvidenceStore, RunExecutionResult, RunId, RunLifecycle, RunReportStatus,
    RunSnapshot, SyncOptions, SyncProfile, SyncRun,
};

fn profile() -> SyncProfile {
    SyncProfile::new(
        "evidence profile",
        Peer::new("local", PathBuf::from("/source")),
        Peer::new("backup", PathBuf::from("/destination")),
    )
    .with_source(OneWaySource::PeerA)
    .with_exclusions(["*.tmp", "private/"])
}

fn snapshot(run_id: u64) -> RunSnapshot {
    RunSnapshot::from_profile(
        RunId::new(run_id),
        &profile(),
        AuthorizationSnapshot::new(false, false),
    )
    .expect("test profile should produce a valid snapshot")
}

fn action(action_id: u64) -> crate::PlanRecord {
    crate::PlanRecord::new(
        action_id,
        PathBuf::from(format!("file-{action_id}.txt")),
        PlanActionKind::CopyToDestination,
        PeerSide::PeerA,
        Some(42),
        PreActionState::new(
            ItemType::RegularFile,
            42,
            Some(7),
            Some(FileIdentity::new(1, 2)),
            None,
        ),
    )
}

fn recovery_evidence() -> RecoveryEvidence {
    RecoveryEvidence::new(
        99,
        Some(PathBuf::from("/recovery/file-1.txt")),
        true,
        true,
        false,
        Some(42),
        Some(42),
        None,
        None,
    )
}

#[test]
fn persisted_snapshot_remains_unchanged_when_the_profile_is_edited() {
    let path = TestDatabase::new();
    let original = snapshot(1);
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&original).expect("persist snapshot");

    let edited = SyncProfile::new(
        "edited profile",
        Peer::new("new source", PathBuf::from("/changed-source")),
        Peer::new("new destination", PathBuf::from("/changed-destination")),
    )
    .with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
    });
    assert_ne!(edited, *original.profile());

    let restored = store.load_snapshot(RunId::new(1)).expect("load snapshot");
    assert_eq!(restored, original);
    assert_eq!(restored.profile().name(), "evidence profile");
    assert_eq!(restored.profile().exclusions(), &["*.tmp", "private/"]);
}

#[test]
fn active_sync_run_owns_validated_options_and_authorizations_from_start() {
    let profile = profile().with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
    });
    let run = SyncRun::new_with_authorizations(
        RunId::new(5),
        &profile,
        AuthorizationSnapshot::new(true, false),
    )
    .expect("valid profile");
    assert_eq!(run.snapshot().validated_options().safe_delete(), true);
    assert_eq!(
        run.snapshot().authorizations().allow_unattended_destructive(),
        true
    );
    assert_eq!(run.snapshot().profile(), &profile);
}

#[test]
fn each_action_boundary_is_durable_and_filesystem_uncertainty_becomes_recovery_review() {
    let path = TestDatabase::new();
    let run = snapshot(2);
    {
        let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
        store.begin_run(&run).expect("persist snapshot");
        store
            .append_event(RunId::new(2), JournalEvent::Planned { action: action(1) })
            .expect("persist planned boundary");
        store
            .append_event(RunId::new(2), JournalEvent::Started { action_id: 1 })
            .expect("persist started boundary");
        store
            .append_event(
                RunId::new(2),
                JournalEvent::Progress {
                    action_id: 1,
                    completed_bytes: 21,
                },
            )
            .expect("persist progress boundary");
    }

    let mut reopened = RunEvidenceStore::open(path.path()).expect("reopen evidence store");
    reopened
        .append_event(
            RunId::new(2),
            JournalEvent::RecoveryReview {
                action_id: 1,
                reason: ActionReason::FilesystemUncertain,
                evidence: recovery_evidence(),
            },
        )
        .expect("persist recovery review after restart");
    let report = reopened.load_report(RunId::new(2)).expect("load report");

    assert_eq!(report.status(), RunReportStatus::RecoveryReview);
    assert_eq!(report.items().len(), 1);
    assert_eq!(report.items()[0].progress_bytes(), 21);
    assert!(matches!(
        report.items()[0].outcome(),
        ActionOutcome::RecoveryReview(ActionReason::FilesystemUncertain)
    ));
    assert_eq!(
        report.items()[0]
            .journal()
            .recovery_evidence()
            .expect("recovery evidence")
            .recovery_target(),
        Some(std::path::Path::new("/recovery/file-1.txt"))
    );
}

#[test]
fn simulated_crash_after_each_boundary_keeps_the_last_durable_journal_state() {
    for index in 0..4 {
        let path = TestDatabase::new();
        let run_id = RunId::new(20 + index as u64);
        let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
        store
            .begin_run(&RunSnapshot::from_profile(
                run_id,
                &profile(),
                AuthorizationSnapshot::new(false, false),
            )
            .expect("create snapshot"))
            .expect("persist snapshot");
        for event in [
            JournalEvent::Planned { action: action(1) },
            JournalEvent::Started { action_id: 1 },
            JournalEvent::Progress {
                action_id: 1,
                completed_bytes: 10,
            },
            JournalEvent::Unresolved {
                action_id: 1,
                reason: ActionReason::PermissionDenied,
            },
        ]
        .into_iter()
        .take(index + 1)
        {
            store
                .append_event(run_id, event)
                .expect("persist boundary");
        }
        drop(store);

        let reopened = RunEvidenceStore::open(path.path()).expect("reopen evidence store");
        let journal = reopened.load_journal(run_id).expect("load journal");
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].progress_bytes().len(), if index >= 2 { 1 } else { 0 });
        if index == 3 {
            assert!(matches!(journal[0].outcome(), ActionOutcome::Unresolved(_)));
        }
    }
}

#[test]
fn report_distinguishes_every_required_item_outcome_and_keeps_review_work_visible() {
    let path = TestDatabase::new();
    let run = snapshot(3);
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&run).expect("persist snapshot");
    let terminal_events = [
        JournalEvent::Completed { action_id: 1 },
        JournalEvent::Failed {
            action_id: 2,
            reason: ActionReason::TransferFailed,
        },
        JournalEvent::Cancelled { action_id: 3 },
        JournalEvent::Deferred { action_id: 4 },
        JournalEvent::Unresolved {
            action_id: 5,
            reason: ActionReason::PermissionDenied,
        },
        JournalEvent::RecoveryReview {
            action_id: 6,
            reason: ActionReason::InterruptedBoundary,
            evidence: recovery_evidence(),
        },
    ];
    for (index, event) in terminal_events.into_iter().enumerate() {
        let action_id = index as u64 + 1;
        store
            .append_event(RunId::new(3), JournalEvent::Planned { action: action(action_id) })
            .expect("persist plan");
        store
            .append_event(RunId::new(3), JournalEvent::Started { action_id })
            .expect("persist start");
        store
            .append_event(RunId::new(3), event)
            .expect("persist outcome");
    }

    let report = store.load_report(RunId::new(3)).expect("load report");
    assert_eq!(report.status(), RunReportStatus::RecoveryReview);
    assert_eq!(report.items().len(), 6);
    assert!(report
        .items()
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Completed)));
    assert!(report
        .items()
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Failed(ActionReason::TransferFailed))));
    assert!(report
        .items()
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Cancelled)));
    assert!(report
        .items()
        .iter()
        .any(|item| matches!(item.outcome(), ActionOutcome::Deferred)));
    assert!(report.items().iter().any(|item| matches!(
        item.outcome(),
        ActionOutcome::Unresolved(ActionReason::PermissionDenied)
    )));
    assert!(report.items().iter().any(|item| matches!(
        item.outcome(),
        ActionOutcome::RecoveryReview(ActionReason::InterruptedBoundary)
    )));
}

#[test]
fn recovery_review_can_only_be_cleared_after_explicit_reinspection_resolution() {
    let path = TestDatabase::new();
    let run = snapshot(7);
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&run).expect("persist snapshot");
    store
        .append_event(RunId::new(7), JournalEvent::Planned { action: action(1) })
        .expect("persist plan");
    store
        .append_event(RunId::new(7), JournalEvent::Started { action_id: 1 })
        .expect("persist start");
    store
        .append_event(
            RunId::new(7),
            JournalEvent::RecoveryReview {
                action_id: 1,
                reason: ActionReason::InterruptedBoundary,
                evidence: recovery_evidence(),
            },
        )
        .expect("persist review");
    store
        .append_event(
            RunId::new(7),
            JournalEvent::RecoveryResolved {
                action_id: 1,
                resolution: RecoveryResolution::Completed {
                    evidence: RecoveryEvidence::new(
                        100,
                        Some(PathBuf::from("/recovery/file-1.txt")),
                        true,
                        true,
                        false,
                        Some(42),
                        Some(42),
                        None,
                        None,
                    ),
                },
            },
        )
        .expect("persist reviewed resolution");
    let unresolved = store.load_report(RunId::new(7)).expect("load report");
    assert_eq!(unresolved.execution_result(), RunExecutionResult::Succeeded);
    assert_eq!(unresolved.lifecycle(), RunLifecycle::Open);
    assert!(unresolved.can_mark_review_cleared());

    store
        .mark_review_cleared(RunId::new(7))
        .expect("explicit completion acknowledgement");
    let cleared = store.load_report(RunId::new(7)).expect("load cleared report");
    assert_eq!(cleared.status(), RunReportStatus::ReviewCleared);
    assert_eq!(cleared.lifecycle(), RunLifecycle::ReviewCleared);
    assert!(!cleared.can_mark_review_cleared());
}

#[test]
fn action_settlement_requires_start_and_preserves_plan_order() {
    let path = TestDatabase::new();
    let run = snapshot(9);
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&run).expect("persist snapshot");
    store
        .append_event(RunId::new(9), JournalEvent::Planned { action: action(1) })
        .expect("persist first plan");
    let error = store
        .append_event(RunId::new(9), JournalEvent::Completed { action_id: 1 })
        .expect_err("an action cannot settle before it starts");
    assert!(matches!(error, crate::StorageError::InvalidEvent(_)));

    store
        .append_event(RunId::new(9), JournalEvent::Started { action_id: 1 })
        .expect("persist first start");
    store
        .append_event(RunId::new(9), JournalEvent::Planned { action: action(2) })
        .expect("persist second plan");
    let error = store
        .append_event(RunId::new(9), JournalEvent::Completed { action_id: 2 })
        .expect_err("a later action cannot settle before the first action");
    assert!(matches!(error, crate::StorageError::InvalidEvent(_)));
}

#[test]
fn recovery_completion_requires_newer_reinspection_evidence() {
    let path = TestDatabase::new();
    let run = snapshot(10);
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&run).expect("persist snapshot");
    store
        .append_event(RunId::new(10), JournalEvent::Planned { action: action(1) })
        .expect("persist plan");
    store
        .append_event(RunId::new(10), JournalEvent::Started { action_id: 1 })
        .expect("persist start");
    store
        .append_event(
            RunId::new(10),
            JournalEvent::RecoveryReview {
                action_id: 1,
                reason: ActionReason::InterruptedBoundary,
                evidence: recovery_evidence(),
            },
        )
        .expect("persist review");

    let stale = store
        .append_event(
            RunId::new(10),
            JournalEvent::RecoveryResolved {
                action_id: 1,
                resolution: RecoveryResolution::Completed {
                    evidence: recovery_evidence(),
                },
            },
        )
        .expect_err("stale evidence cannot clear uncertainty");
    assert!(matches!(stale, crate::StorageError::InvalidEvent(_)));
}

#[test]
fn unresolved_work_survives_restart_and_database_bytes_contain_no_fixture_content() {
    let path = TestDatabase::new();
    let run = snapshot(8);
    {
        let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
        store.begin_run(&run).expect("persist snapshot");
        store
            .append_event(RunId::new(8), JournalEvent::Planned { action: action(1) })
            .expect("persist plan");
        store
            .append_event(RunId::new(8), JournalEvent::Started { action_id: 1 })
            .expect("persist start");
        store
            .append_event(
                RunId::new(8),
                JournalEvent::Unresolved {
                    action_id: 1,
                    reason: ActionReason::PermissionDenied,
                },
            )
            .expect("persist unresolved work");
    }
    let bytes = fs::read(path.path()).expect("read database fixture");
    assert!(!bytes
        .windows(b"PRIVATE_FILE_CONTENT".len())
        .any(|window| window == b"PRIVATE_FILE_CONTENT"));
    assert!(!bytes
        .windows(b"password=secret".len())
        .any(|window| window == b"password=secret"));

    let reopened = RunEvidenceStore::open(path.path()).expect("reopen evidence store");
    let report = reopened.load_report(RunId::new(8)).expect("load retained report");
    assert_eq!(report.status(), RunReportStatus::CompletedWithReviewRequired);
    assert!(matches!(
        report.items()[0].outcome(),
        ActionOutcome::Unresolved(ActionReason::PermissionDenied)
    ));
}

#[test]
fn snapshot_and_journal_types_cannot_capture_passwords_or_file_contents() {
    let snapshot = RunSnapshot::from_profile(
        RunId::new(4),
        &profile(),
        AuthorizationSnapshot::new(true, false),
    )
    .expect("valid snapshot");
    let planned = action(1);
    let rendered = format!("{snapshot:?}{planned:?}");
    assert!(!rendered.contains("password"));
    assert!(!rendered.contains("PRIVATE_FILE_CONTENT"));
    assert_eq!(snapshot.authorizations().allow_unattended_destructive(), true);
}

struct TestDatabase(PathBuf);

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

impl TestDatabase {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "syncplus-evidence-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(self.0.with_extension("sqlite-wal"));
        let _ = fs::remove_file(self.0.with_extension("sqlite-shm"));
    }
}
