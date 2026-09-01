use std::{fs, path::PathBuf, time::Duration};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{params, Connection};

use crate::{
    ActionOutcome, ActionReason, AuthorizationSnapshot, DeletionMethod, FileIdentity, ItemType,
    JournalEvent, OneWaySource, Peer, PeerSide, PlanActionKind, PlanRecord, PreActionState, RecoveryEvidence,
    PartialTransferPolicy, RecoveryResolution, RetryPolicy, RunEvidenceStore, RunExecutionResult,
    RunId, RunLifecycle, RunReport, RunReportStatus, RunSnapshot, SyncOptions, SyncProfile, SyncRun,
    ConflictResolution, MetadataRequirements, MirrorResolutionOutcome, MirrorResolutionReportItem,
    MirrorResolutionReviewState, ResolutionOperation, SpecialistMetadataRequirements, SyncMode,
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
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    });
    assert_ne!(edited, *original.profile());

    let restored = store.load_snapshot(RunId::new(1)).expect("load snapshot");
    assert_eq!(restored, original);
    assert_eq!(restored.profile().name(), "evidence profile");
    assert_eq!(restored.profile().exclusions(), &["*.tmp", "private/"]);
}

#[test]
fn persisted_snapshot_round_trips_all_named_metadata_requirements_after_restart() {
    let path = TestDatabase::new();
    let metadata = MetadataRequirements::new(true, true, true, true)
        .with_specialist_metadata(SpecialistMetadataRequirements::new(true, true, true));
    let profile = profile().with_options(SyncOptions {
        metadata,
        ..SyncOptions::default()
    });
    let original = RunSnapshot::from_profile(RunId::new(2), &profile, AuthorizationSnapshot::default())
        .expect("profile should produce a snapshot");
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&original).expect("persist snapshot");
    drop(store);

    let reopened = RunEvidenceStore::open(path.path()).expect("reopen evidence store");
    let restored = reopened.load_snapshot(RunId::new(2)).expect("load snapshot");
    assert_eq!(restored.profile().options().metadata, metadata);
}

#[test]
fn active_sync_run_owns_validated_options_and_authorizations_from_start() {
    let profile = profile().with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
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
fn interrupted_action_is_durable_and_remains_open_for_resume() {
    let path = TestDatabase::new();
    let run_id = RunId::new(14);
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store
        .begin_run(&RunSnapshot::from_profile(
            run_id,
            &profile(),
            AuthorizationSnapshot::default(),
        )
        .expect("snapshot"))
        .expect("persist snapshot");
    store
        .append_event(run_id, JournalEvent::Planned { action: action(1) })
        .expect("persist plan");
    store
        .append_event(run_id, JournalEvent::Started { action_id: 1 })
        .expect("persist start");
    store
        .append_event(
            run_id,
            JournalEvent::Progress {
                action_id: 1,
                completed_bytes: 21,
            },
        )
        .expect("persist progress");
    store
        .append_event(run_id, JournalEvent::Interrupted { action_id: 1 })
        .expect("persist interruption");

    let report = store.load_report(run_id).expect("load interrupted report");
    assert_eq!(report.status(), RunReportStatus::Interrupted);
    assert_eq!(report.execution_result(), RunExecutionResult::Interrupted);
    assert_eq!(report.items()[0].progress_bytes(), 21);
    assert_eq!(report.items()[0].journal().last_phase(), "interrupted");
    assert!(matches!(
        report.items()[0].outcome(),
        ActionOutcome::Interrupted
    ));
}

#[test]
fn retry_and_partial_policies_are_frozen_in_the_run_snapshot() {
    let path = TestDatabase::new();
    let options = SyncOptions {
        partial_transfer_policy: PartialTransferPolicy::KeepPartialForResume,
        retry_policy: RetryPolicy::new(5, Duration::from_millis(250)),
        ..SyncOptions::default()
    };
    let original = SyncProfile::new(
        "policy profile",
        Peer::new("source", PathBuf::from("/source")),
        Peer::new("destination", PathBuf::from("/destination")),
    )
    .with_options(options);
    let snapshot = RunSnapshot::from_profile(
        RunId::new(15),
        &original,
        AuthorizationSnapshot::default(),
    )
    .expect("policy profile should be valid");
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&snapshot).expect("persist snapshot");

    let restored = store.load_snapshot(RunId::new(15)).expect("restore snapshot");
    assert_eq!(restored, snapshot);
    assert_eq!(
        restored
            .validated_options()
            .partial_transfer_policy(),
        PartialTransferPolicy::KeepPartialForResume
    );
    assert_eq!(restored.validated_options().retry_policy(), options.retry_policy);
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
fn mirror_resolution_evidence_is_durable_and_blocks_review_clear() {
    let path = TestDatabase::new();
    let mirror_profile = profile().with_mode(SyncMode::Mirror);
    let run = RunSnapshot::from_profile(
        RunId::new(31),
        &mirror_profile,
        AuthorizationSnapshot::default(),
    )
    .expect("Mirror snapshot");
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&run).expect("persist snapshot");
    store
        .record_mirror_resolutions(
            RunId::new(31),
            &[
                MirrorResolutionReportItem::new(
                    "conflict.txt",
                    Some("conflict (Peer A).txt"),
                    ConflictResolution::PreserveBoth,
                    ResolutionOperation::PreserveBoth,
                    Some(PeerSide::PeerA),
                    Some(PeerSide::PeerB),
                    MirrorResolutionOutcome::Completed,
                    MirrorResolutionReviewState::ReviewLater,
                ),
                MirrorResolutionReportItem::new(
                    "deferred.txt",
                    None::<&str>,
                    ConflictResolution::Defer,
                    ResolutionOperation::Defer,
                    None,
                    None,
                    MirrorResolutionOutcome::Deferred,
                    MirrorResolutionReviewState::ReviewLater,
                ),
                MirrorResolutionReportItem::new(
                    "failed.txt",
                    None::<&str>,
                    ConflictResolution::KeepPeerA,
                    ResolutionOperation::CopyWholeFile,
                    Some(PeerSide::PeerA),
                    Some(PeerSide::PeerB),
                MirrorResolutionOutcome::Failed(ActionReason::VerificationMismatch),
                    MirrorResolutionReviewState::Settled,
                ),
                MirrorResolutionReportItem::new(
                    "malformed-preserve.txt",
                    None::<&str>,
                    ConflictResolution::PreserveBoth,
                    ResolutionOperation::PreserveBoth,
                    None,
                    None,
                    MirrorResolutionOutcome::Completed,
                    MirrorResolutionReviewState::Settled,
                ),
            ],
        )
        .expect("persist Mirror resolution evidence");

    let report = store.load_report(RunId::new(31)).expect("load report");
    assert_eq!(report.mirror_resolutions().len(), 4);
    assert_eq!(
        report.mirror_resolutions()[0].generated_path(),
        Some(std::path::Path::new("conflict (Peer A).txt"))
    );
    assert!(report.mirror_resolutions().iter().any(|item| {
        matches!(
            item.outcome(),
            MirrorResolutionOutcome::Failed(ActionReason::VerificationMismatch)
        )
    }));
    let malformed = report
        .mirror_resolutions()
        .iter()
        .find(|item| item.original_path() == std::path::Path::new("malformed-preserve.txt"))
        .expect("malformed preserve evidence should remain visible");
    assert_eq!(
        malformed.review_state(),
        MirrorResolutionReviewState::ReviewLater
    );
    assert!(malformed.requires_review());
    assert_eq!(report.status(), RunReportStatus::Failed);
    assert!(!report.can_mark_review_cleared());
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
fn run_report_metadata_actions_are_status_guarded_and_filesystem_neutral() {
    let source = tempfile_dir("report-source");
    let destination = tempfile_dir("report-destination");
    fs::create_dir_all(&source).expect("source directory");
    fs::create_dir_all(&destination).expect("destination directory");
    fs::write(source.join("keep.txt"), b"source fixture").expect("source fixture");
    fs::write(destination.join("keep.txt"), b"destination fixture").expect("destination fixture");

    let mut store = RunEvidenceStore::open_in_memory().expect("database");
    let completed_run = RunId::new(30);
    let completed_snapshot = RunSnapshot::from_profile(
        completed_run,
        &SyncProfile::new(
            "completed report",
            Peer::new("source", source.clone()),
            Peer::new("destination", destination.clone()),
        ),
        AuthorizationSnapshot::default(),
    )
    .expect("completed snapshot");
    store.begin_run(&completed_snapshot).expect("snapshot");
    store
        .append_event(completed_run, JournalEvent::Planned { action: action(1) })
        .expect("plan");
    store
        .append_event(completed_run, JournalEvent::Started { action_id: 1 })
        .expect("start");
    store
        .append_event(completed_run, JournalEvent::Completed { action_id: 1 })
        .expect("complete");

    let unresolved_run = RunId::new(31);
    store
        .begin_run(&snapshot(unresolved_run.value()))
        .expect("unresolved snapshot");
    store
        .append_event(unresolved_run, JournalEvent::Planned { action: action(1) })
        .expect("unresolved plan");
    store
        .append_event(unresolved_run, JournalEvent::Started { action_id: 1 })
        .expect("unresolved start");
    store
        .append_event(
            unresolved_run,
            JournalEvent::Unresolved {
                action_id: 1,
                reason: ActionReason::PermissionDenied,
            },
        )
        .expect("unresolved outcome");

    let reports = store.list_run_reports().expect("list reports");
    assert_eq!(reports.iter().map(RunReport::run_id).collect::<Vec<_>>(), vec![unresolved_run, completed_run]);
    assert!(matches!(
        store
            .remove_completed_report(unresolved_run)
            .expect_err("unresolved work needs its separate discard action"),
        crate::StorageError::ReportActionNotAllowed {
            action: "Remove Completed Report",
            ..
        }
    ));
    assert!(matches!(
        store
            .discard_unresolved_run(completed_run)
            .expect_err("completed reports need their separate remove action"),
        crate::StorageError::ReportActionNotAllowed {
            action: "Discard Unresolved Run",
            ..
        }
    ));

    store
        .remove_completed_report(completed_run)
        .expect("remove completed metadata");
    assert!(store.load_report(completed_run).is_err());
    assert!(source.join("keep.txt").is_file());
    assert!(destination.join("keep.txt").is_file());

    store
        .discard_unresolved_run(unresolved_run)
        .expect("discard unresolved metadata");
    assert!(store.list_run_reports().expect("list after discard").is_empty());
    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(destination);
}

fn tempfile_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    std::env::temp_dir().join(format!(
        "syncplus-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
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
    let error = store
        .append_event(RunId::new(9), JournalEvent::Started { action_id: 2 })
        .expect_err("a later action cannot start before the first action");
    assert!(matches!(error, crate::StorageError::InvalidEvent(_)));
}

#[test]
fn safe_delete_actions_cannot_settle_through_generic_completed_event() {
    let path = TestDatabase::new();
    let safe_profile = profile().with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    });
    let run_id = RunId::new(11);
    let snapshot = RunSnapshot::from_profile(
        run_id,
        &safe_profile,
        AuthorizationSnapshot::default(),
    )
    .expect("safe-delete snapshot");
    let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
    store.begin_run(&snapshot).expect("persist snapshot");
    store
        .append_event(
            run_id,
            JournalEvent::Planned {
                action: PlanRecord::new(
                    1,
                    PathBuf::from("source.txt"),
                    PlanActionKind::RemoveSourceAfterVerification,
                    PeerSide::PeerA,
                    Some(1),
                    PreActionState::new(ItemType::RegularFile, 1, None, None, None),
                ),
            },
        )
        .expect("persist removal plan");
    store
        .append_event(run_id, JournalEvent::Started { action_id: 1 })
        .expect("persist removal start");

    let error = store
        .append_event(run_id, JournalEvent::Completed { action_id: 1 })
        .expect_err("generic completion must not authorize source removal");
    assert!(matches!(error, crate::StorageError::InvalidEvent(_)));
}

#[test]
fn journal_replay_rejects_corrupt_generic_completion_for_safe_delete() {
    let path = TestDatabase::new();
    let safe_profile = profile().with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    });
    let run_id = RunId::new(12);
    let snapshot = RunSnapshot::from_profile(
        run_id,
        &safe_profile,
        AuthorizationSnapshot::default(),
    )
    .expect("safe-delete snapshot");
    {
        let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
        store.begin_run(&snapshot).expect("persist snapshot");
        store
            .append_event(
                run_id,
                JournalEvent::Planned {
                    action: PlanRecord::new(
                        1,
                        PathBuf::from("source.txt"),
                        PlanActionKind::RemoveSourceAfterVerification,
                        PeerSide::PeerA,
                        Some(1),
                        PreActionState::new(ItemType::RegularFile, 1, None, None, None),
                    ),
                },
            )
            .expect("persist removal plan");
        store
            .append_event(run_id, JournalEvent::Started { action_id: 1 })
            .expect("persist removal start");
        store
            .append_event(
                run_id,
                JournalEvent::Unresolved {
                    action_id: 1,
                    reason: ActionReason::PermissionDenied,
                },
            )
            .expect("persist unresolved boundary");
    }
    let connection = Connection::open(path.path()).expect("open database for corruption fixture");
    connection
        .execute(
            "UPDATE action_events SET phase = 'completed', reason = NULL
             WHERE run_id = ?1 AND action_id = 1 AND phase = 'unresolved'",
            params![run_id.value()],
        )
        .expect("corrupt completion phase");

    let store = RunEvidenceStore::open(path.path()).expect("reopen evidence store");
    let error = store
        .load_journal(run_id)
        .expect_err("corrupt Safe Delete completion must not replay as success");
    assert!(matches!(error, crate::StorageError::CorruptEvidence(_)));
}

#[test]
fn journal_replay_rejects_corrupt_recovery_completion_for_safe_delete() {
    let path = TestDatabase::new();
    let safe_profile = profile().with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    });
    let run_id = RunId::new(13);
    let snapshot = RunSnapshot::from_profile(
        run_id,
        &safe_profile,
        AuthorizationSnapshot::default(),
    )
    .expect("safe-delete snapshot");
    {
        let mut store = RunEvidenceStore::open(path.path()).expect("open evidence store");
        store.begin_run(&snapshot).expect("persist snapshot");
        store
            .append_event(
                run_id,
                JournalEvent::Planned {
                    action: PlanRecord::new(
                        1,
                        PathBuf::from("source.txt"),
                        PlanActionKind::RemoveSourceAfterVerification,
                        PeerSide::PeerA,
                        Some(42),
                        PreActionState::new(ItemType::RegularFile, 42, None, None, None),
                    ),
                },
            )
            .expect("persist removal plan");
        store
            .append_event(run_id, JournalEvent::Started { action_id: 1 })
            .expect("persist removal start");
        store
            .append_event(
                run_id,
                JournalEvent::RecoveryReview {
                    action_id: 1,
                    reason: ActionReason::InterruptedBoundary,
                    evidence: recovery_evidence(),
                },
            )
            .expect("persist recovery review");
        store
            .append_event(
                run_id,
                JournalEvent::RecoveryResolved {
                    action_id: 1,
                    resolution: RecoveryResolution::Unresolved(ActionReason::FilesystemUncertain),
                },
            )
            .expect("persist unresolved recovery resolution");
    }
    let connection = Connection::open(path.path()).expect("open database for corruption fixture");
    connection
        .execute(
            "UPDATE action_events SET resolution = 'completed',
                    recovery_observed_at_unix_nanos = 100,
                    recovery_target = ?1,
                    recovery_source_present = 1,
                    recovery_destination_present = 1,
                    recovery_present = 0,
                    recovery_source_size = 42,
                    recovery_destination_size = 42
             WHERE run_id = ?2 AND action_id = 1 AND phase = 'recovery_resolved'",
            params![b"/recovery/source.txt".as_slice(), run_id.value()],
        )
        .expect("corrupt recovery resolution");

    let store = RunEvidenceStore::open(path.path()).expect("reopen evidence store");
    let error = store
        .load_journal(run_id)
        .expect_err("corrupt Safe Delete recovery completion must not replay as success");
    assert!(matches!(error, crate::StorageError::CorruptEvidence(_)));
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
