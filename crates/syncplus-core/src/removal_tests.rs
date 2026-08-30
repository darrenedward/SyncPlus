use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    AuthorizationSnapshot, DeletionMethod, FreshAnalysis, JournalEvent, OneWaySource, Peer,
    PlanActionKind, PlanRecord, PreActionState, RecoveryMethod, RunEvidenceStore, RunId,
    SafeDeleteExecutor, SyncOptions, SyncProfile,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let suffix = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "syncplus-removal-{label}-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be creatable");
        Self { path }
    }

    fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn profile(source: &TestDirectory, destination: &TestDirectory) -> SyncProfile {
    SyncProfile::new(
        "Safe Delete test",
        Peer::new("Source", source.path.clone()),
        Peer::new("Destination", destination.path.clone()),
    )
    .with_source(OneWaySource::PeerA)
    .with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
    })
}

fn record_started(
    store: &mut RunEvidenceStore,
    run_id: RunId,
    action: &crate::PlanAction,
    replacement: &crate::VerifiedReplacement,
) {
    let source_observation = replacement.proof().source_after();
    let source_content = source_observation.content();
    let source_metadata = source_observation.metadata();
    store
        .append_event(
            run_id,
            JournalEvent::Planned {
                action: PlanRecord::new(
                    action.action_id(),
                    action.relative_path().to_path_buf(),
                    action.kind(),
                    action.source_side(),
                    action.size(),
                    PreActionState::new(
                        source_metadata.item_type(),
                        source_content.size(),
                        source_metadata.modified_at_unix_nanos(),
                        source_metadata.identity(),
                        Some(*source_content.sha256()),
                    ),
                ),
            },
        )
        .expect("plan boundary should persist");
    store
        .append_event(
            run_id,
            JournalEvent::Started {
                action_id: action.action_id(),
            },
        )
        .expect("start boundary should persist");
}

fn begin_store(
    run_id: RunId,
    source: &TestDirectory,
    destination: &TestDirectory,
) -> RunEvidenceStore {
    let snapshot = crate::RunSnapshot::from_profile(
        run_id,
        &profile(source, destination),
        AuthorizationSnapshot::default(),
    )
    .expect("test snapshot should be valid");
    let mut store = RunEvidenceStore::open_in_memory().expect("journal should open");
    store.begin_run(&snapshot).expect("snapshot should persist");
    store
}

#[test]
fn verified_source_is_moved_to_recovery_and_journaled_before_next_item() {
    let source = TestDirectory::new("source");
    let destination = TestDirectory::new("destination");
    let recovery = TestDirectory::new("recovery");
    fs::write(source.join("item.txt"), b"verified source").expect("source should be writable");

    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("safe-delete plan should contain a source removal action");
    let source_path = source.join("item.txt");
    let destination_path = destination.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination_path,
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("destination should be independently verified");
    let source_identity = crate::FileMetadataProof::capture(&source_path)
        .expect("source metadata")
        .identity();
    let run_id = RunId::new(101);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, action, &replacement);

    let receipt = SafeDeleteExecutor::new(RecoveryMethod::trash(recovery.path.clone()))
        .settle_one(run_id, analysis.plan(), action, &replacement, &mut store)
        .expect("verified source should settle");

    assert_eq!(receipt.action_id(), action.action_id());
    assert_eq!(receipt.deletion_method(), DeletionMethod::Trash);
    assert!(!source_path.exists());
    assert_eq!(fs::read(recovery.join("item.txt")).expect("recovery item"), b"verified source");
    assert_eq!(
        crate::FileMetadataProof::capture(&recovery.join("item.txt"))
            .expect("recovery metadata")
            .identity(),
        source_identity,
        "same-filesystem recovery should atomically move the original inode"
    );
    assert_eq!(fs::read(destination_path).expect("installed destination"), b"verified source");
    let report = store.load_report(run_id).expect("report should load");
    assert!(matches!(
        report.items()[0].outcome(),
        crate::ActionOutcome::Completed
    ));
    assert!(report.items()[0].journal().proof_boundary().is_some());
    assert!(report.items()[0].journal().removal_result().is_some());
}

#[test]
fn unavailable_recovery_preserves_source_and_records_unresolved() {
    let source = TestDirectory::new("unavailable-source");
    let destination = TestDirectory::new("unavailable-destination");
    let recovery_parent = TestDirectory::new("unavailable-recovery-parent");
    fs::write(source.join("item.txt"), b"keep me").expect("source should be writable");
    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("removal action");
    let source_path = source.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination.join("item.txt"),
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("transfer proof");
    let run_id = RunId::new(102);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, action, &replacement);

    let missing_recovery = recovery_parent.join("missing");
    let error = SafeDeleteExecutor::new(RecoveryMethod::trash(missing_recovery))
        .settle_one(run_id, analysis.plan(), action, &replacement, &mut store)
        .expect_err("unavailable recovery must stop removal");

    assert!(matches!(error, crate::SafeDeleteError::RecoveryUnavailable(_)));
    assert_eq!(fs::read(&source_path).expect("source remains"), b"keep me");
    let report = store.load_report(run_id).expect("report should load");
    assert!(matches!(
        report.items()[0].outcome(),
        crate::ActionOutcome::Unresolved(crate::ActionReason::DestinationUnavailable)
    ));
}

#[test]
fn source_change_after_transfer_proof_preserves_source_and_marks_unresolved() {
    let source = TestDirectory::new("changed-source");
    let destination = TestDirectory::new("changed-destination");
    let recovery = TestDirectory::new("changed-recovery");
    fs::write(source.join("item.txt"), b"original").expect("source should be writable");
    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("removal action");
    let source_path = source.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination.join("item.txt"),
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("transfer proof");
    fs::write(&source_path, b"changed").expect("source mutation");
    let run_id = RunId::new(103);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, action, &replacement);

    let error = SafeDeleteExecutor::new(RecoveryMethod::trash(recovery.path.clone()))
        .settle_one(run_id, analysis.plan(), action, &replacement, &mut store)
        .expect_err("changed source must not be removed");

    assert!(matches!(
        error,
        crate::SafeDeleteError::Verification(crate::VerificationError::SourceChanged)
    ));
    assert_eq!(fs::read(&source_path).expect("source remains"), b"changed");
    assert!(!recovery.join("item.txt").exists());
    let report = store.load_report(run_id).expect("report should load");
    assert!(matches!(
        report.items()[0].outcome(),
        crate::ActionOutcome::Unresolved(crate::ActionReason::SourceChanged)
    ));
}

#[test]
fn transfer_proof_for_one_action_cannot_remove_another_action() {
    let source = TestDirectory::new("isolation-source");
    let destination = TestDirectory::new("isolation-destination");
    let recovery = TestDirectory::new("isolation-recovery");
    fs::write(source.join("first.txt"), b"first").expect("first source");
    fs::write(source.join("second.txt"), b"second").expect("second source");
    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let removal_actions: Vec<_> = analysis
        .plan()
        .actions()
        .iter()
        .filter(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .collect();
    assert_eq!(removal_actions.len(), 2);
    let first_source = source.join("first.txt");
    let first_destination = destination.join("first.txt");
    let first_replacement = crate::replacement::perform_verified_replacement(
        &first_source,
        &first_destination,
        |temporary| {
            fs::copy(&first_source, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("first transfer proof");
    let run_id = RunId::new(108);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, removal_actions[0], &first_replacement);
    SafeDeleteExecutor::new(RecoveryMethod::trash(recovery.path.clone()))
        .settle_one(
            run_id,
            analysis.plan(),
            removal_actions[0],
            &first_replacement,
            &mut store,
        )
        .expect("the first item should settle before the second item");

    let error = SafeDeleteExecutor::new(RecoveryMethod::trash(recovery.path.clone()))
        .settle_one(
            run_id,
            analysis.plan(),
            removal_actions[1],
            &first_replacement,
            &mut store,
        )
        .expect_err("an action cannot use another action's transfer proof");

    assert!(matches!(error, crate::SafeDeleteError::InvalidAction(_)));
    assert!(!source.join("first.txt").exists());
    assert!(source.join("second.txt").exists());
    assert!(recovery.join("first.txt").exists());
    assert!(!recovery.join("second.txt").exists());
}

#[test]
fn destination_mismatch_after_transfer_proof_preserves_source_and_is_unresolved() {
    let source = TestDirectory::new("destination-mismatch-source");
    let destination = TestDirectory::new("destination-mismatch-destination");
    let recovery = TestDirectory::new("destination-mismatch-recovery");
    fs::write(source.join("item.txt"), b"source bytes").expect("source should be writable");
    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("removal action");
    let source_path = source.join("item.txt");
    let destination_path = destination.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination_path,
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("transfer proof");
    fs::write(&destination_path, b"changed destination").expect("destination mutation");
    let run_id = RunId::new(107);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, action, &replacement);

    let error = SafeDeleteExecutor::new(RecoveryMethod::trash(recovery.path.clone()))
        .settle_one(run_id, analysis.plan(), action, &replacement, &mut store)
        .expect_err("destination mismatch must stop removal");

    assert!(matches!(
        error,
        crate::SafeDeleteError::Verification(crate::VerificationError::SizeMismatch { .. })
    ));
    assert!(source_path.exists());
    assert!(matches!(
        store.load_report(run_id).expect("report").items()[0].outcome(),
        crate::ActionOutcome::Unresolved(crate::ActionReason::VerificationMismatch)
    ));
}

#[test]
fn recovery_root_cannot_be_the_selected_source_root() {
    let source = TestDirectory::new("root-guard-source");
    let destination = TestDirectory::new("root-guard-destination");
    fs::write(source.join("item.txt"), b"root guard").expect("source should be writable");
    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("removal action");
    let source_path = source.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination.join("item.txt"),
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("transfer proof");
    let run_id = RunId::new(104);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, action, &replacement);

    SafeDeleteExecutor::new(RecoveryMethod::trash(source.path.clone()))
        .settle_one(run_id, analysis.plan(), action, &replacement, &mut store)
        .expect_err("source root cannot be a recovery target");

    assert!(source_path.exists());
    assert!(store.load_report(run_id).expect("report").items()[0]
        .outcome()
        .eq(&crate::ActionOutcome::Unresolved(
            crate::ActionReason::DestinationUnavailable,
        )));
}

#[cfg(unix)]
#[test]
fn cross_filesystem_recovery_verifies_copy_before_source_removal() {
    use std::os::unix::fs::MetadataExt;

    let source = TestDirectory::new("cross-source");
    let destination = TestDirectory::new("cross-destination");
    let recovery_root = Path::new("/dev/shm");
    let source_device = fs::symlink_metadata(&source.path)
        .expect("source metadata")
        .dev();
    let recovery_device = fs::symlink_metadata(recovery_root)
        .expect("Linux cross-filesystem test requires /dev/shm")
        .dev();
    assert_ne!(
        source_device, recovery_device,
        "Linux cross-filesystem test requires /dev/shm on another filesystem"
    );
    let recovery = TestDirectory {
        path: recovery_root.join(format!(
            "syncplus-cross-recovery-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        )),
    };
    fs::create_dir_all(&recovery.path).expect("cross-filesystem recovery should be creatable");
    let contents = vec![b'x'; 128 * 1024];
    fs::write(source.join("item.txt"), &contents).expect("source should be writable");

    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("removal action");
    let source_path = source.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination.join("item.txt"),
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("transfer proof");
    let run_id = RunId::new(105);
    let mut store = begin_store(run_id, &source, &destination);
    record_started(&mut store, run_id, action, &replacement);

    SafeDeleteExecutor::new(RecoveryMethod::trash(recovery.path.clone()))
        .settle_one(run_id, analysis.plan(), action, &replacement, &mut store)
        .expect("cross-filesystem recovery should settle");

    assert!(!source_path.exists());
    assert_eq!(fs::read(recovery.join("item.txt")).expect("recovery item"), contents);
    assert!(store.load_report(run_id).expect("report").items()[0]
        .journal()
        .removal_result()
        .is_some());
}

#[test]
fn interruption_after_removal_start_requires_recovery_review() {
    let source = TestDirectory::new("boundary-source");
    let destination = TestDirectory::new("boundary-destination");
    let recovery = TestDirectory::new("boundary-recovery");
    fs::write(source.join("item.txt"), b"boundary").expect("source should be writable");
    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("test peers should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.kind() == PlanActionKind::RemoveSourceAfterVerification)
        .expect("removal action");
    let source_path = source.join("item.txt");
    let replacement = crate::replacement::perform_verified_replacement(
        &source_path,
        &destination.join("item.txt"),
        |temporary| {
            fs::copy(&source_path, temporary)
                .map(|_| ())
                .map_err(|error| crate::ReplacementError::Io(error.to_string()))
        },
    )
    .expect("transfer proof");
    let proof = replacement.proof();
    let run_id = RunId::new(106);
    let database = TestDirectory::new("boundary-database");
    let snapshot = crate::RunSnapshot::from_profile(
        run_id,
        &profile(&source, &destination),
        AuthorizationSnapshot::default(),
    )
    .expect("test snapshot should be valid");
    let database_path = database.join("run.db");
    let mut store = RunEvidenceStore::open(&database_path).expect("journal should open");
    store.begin_run(&snapshot).expect("snapshot should persist");
    record_started(&mut store, run_id, action, &replacement);
    let evidence = crate::RecoveryEvidence::new(
        100,
        None,
        true,
        true,
        false,
        Some(proof.source_after().content().size()),
        Some(proof.installed_destination().size()),
        Some(*proof.source_after().content().sha256()),
        Some(*proof.installed_destination().sha256()),
    );
    store
        .append_event(
            run_id,
            JournalEvent::ProofBoundary {
                action_id: action.action_id(),
                deletion_method: DeletionMethod::Trash,
                evidence,
                metadata_verified: true,
            },
        )
        .expect("proof boundary");
    store
        .append_event(
            run_id,
            JournalEvent::RemovalStarted {
                action_id: action.action_id(),
                deletion_method: DeletionMethod::Trash,
            },
        )
        .expect("removal start boundary");
    fs::rename(&source_path, recovery.join("item.txt")).expect("simulate atomic recovery move");
    drop(store);
    let reopened = RunEvidenceStore::open(&database_path).expect("journal should reopen");
    let report = reopened.load_report(run_id).expect("report should load");
    assert!(matches!(
        report.items()[0].outcome(),
        crate::ActionOutcome::RecoveryReview(crate::ActionReason::InterruptedBoundary)
    ));
    assert!(!source_path.exists());
    assert_eq!(fs::read(recovery.join("item.txt")).expect("recovered item"), b"boundary");
}
