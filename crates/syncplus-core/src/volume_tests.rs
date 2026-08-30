use std::{
    fs,
    os::unix::fs::symlink,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    LocalPrecheckProbe, Peer, PrecheckBlockerKind, PrecheckProbe, RecoveryMethod,
    RunEvidenceStore, RunId, RunPrecheck, RunReportStatus, RunSnapshot, RunWorkflow, SyncProfile,
    VolumeIdentity,
};

fn test_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "syncplus-volume-{label}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos()
    ))
}

#[test]
fn local_volume_identity_is_stable_and_root_symlinks_are_not_followed() {
    let root = std::env::temp_dir().join(format!(
        "syncplus-volume-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos()
    ));
    let nested = root.join("nested");
    fs::create_dir_all(&nested).expect("volume test root should be creatable");
    let link = root.join("root-link");
    symlink(&nested, &link).expect("volume test symlink should be creatable");

    let probe = LocalPrecheckProbe::default();
    let root_identity = probe
        .volume_identity(&root)
        .expect("volume identity probe should succeed")
        .expect("a local directory should have a volume identity");
    let nested_identity = probe
        .volume_identity(&nested)
        .expect("volume identity probe should succeed")
        .expect("a nested local directory should have a volume identity");

    assert_eq!(root_identity, nested_identity);
    assert!(probe.volume_identity(&link).is_err());

    fs::remove_dir_all(&root).expect("volume test root should be removable");
}

#[test]
fn precheck_blocks_when_a_resumed_peer_has_a_different_volume_identity() {
    let root = test_root("mismatch");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "volume mismatch",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination.clone()),
    );
    let probe = LocalPrecheckProbe::default();
    let observed = probe
        .volume_identity(&source)
        .expect("volume identity probe should succeed")
        .expect("source should have a volume identity");

    let result = RunPrecheck::check_with_expected_volumes(
        &profile,
        &probe,
        Some(VolumeIdentity::new(observed.device().saturating_add(1))),
        None,
    )
    .expect("precheck should return a blocked result");

    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::VolumeIdentityMismatch));
    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.requirement().contains("expected")
            || blocker.requirement().contains("filesystem device")));
    assert!(source.exists());
    assert!(destination.exists());

    fs::remove_dir_all(&root).expect("volume mismatch fixture should be removable");
}

#[test]
fn precheck_detects_an_actual_different_filesystem_when_available() {
    let root = test_root("resume-different-filesystem");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");

    let alternate_root = Path::new("/dev/shm").join(format!(
        "syncplus-volume-alternate-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos()
    ));
    if fs::create_dir_all(&alternate_root).is_err() {
        fs::remove_dir_all(&root).expect("volume fixture should be removable");
        return;
    }

    let alternate_source = alternate_root.join("source");
    fs::create_dir_all(&alternate_source).expect("alternate source should be creatable");
    let probe = LocalPrecheckProbe::default();
    let expected = probe
        .volume_identity(&alternate_source)
        .expect("alternate volume identity probe should succeed")
        .expect("alternate filesystem should have an identity");
    let observed = probe
        .volume_identity(&source)
        .expect("source volume identity probe should succeed")
        .expect("source should have an identity");
    if expected == observed {
        fs::remove_dir_all(&alternate_root).expect("alternate fixture should be removable");
        fs::remove_dir_all(&root).expect("volume fixture should be removable");
        return;
    }

    let profile = SyncProfile::new(
        "different filesystem",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination),
    );
    let result = RunPrecheck::check_with_expected_volumes(&profile, &probe, Some(expected), None)
        .expect("precheck should return a blocked result");
    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::VolumeIdentityMismatch));

    fs::remove_dir_all(&alternate_root).expect("alternate fixture should be removable");
    fs::remove_dir_all(&root).expect("volume fixture should be removable");
}

#[test]
fn volume_identities_are_persisted_with_the_run_snapshot() {
    let root = test_root("snapshot");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "volume snapshot",
        Peer::new("source", source),
        Peer::new("destination", destination),
    );
    let original = RunSnapshot::from_profile_with_volume_identities(
        RunId::new(1),
        &profile,
        Default::default(),
        Some(VolumeIdentity::new(11)),
        Some(VolumeIdentity::new(22)),
    )
    .expect("snapshot should be valid");
    let mut store = RunEvidenceStore::open_in_memory().expect("evidence store should open");
    store.begin_run(&original).expect("snapshot should persist");

    let restored = store.load_snapshot(RunId::new(1)).expect("snapshot should reload");
    assert_eq!(restored.peer_a_volume_identity(), Some(VolumeIdentity::new(11)));
    assert_eq!(restored.peer_b_volume_identity(), Some(VolumeIdentity::new(22)));

    fs::remove_dir_all(&root).expect("volume snapshot fixture should be removable");
}

#[test]
fn workflow_captures_local_volume_identities_in_its_run_snapshot() {
    let root = test_root("workflow");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "workflow volume",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination.clone()),
    );
    let probe = LocalPrecheckProbe::default();
    let source_identity = probe
        .volume_identity(&source)
        .expect("volume identity probe should succeed")
        .expect("source should have a volume identity");
    let destination_identity = probe
        .volume_identity(&destination)
        .expect("volume identity probe should succeed")
        .expect("destination should have a volume identity");
    let database = root.join("evidence.db");
    let mut store = RunEvidenceStore::open(&database).expect("evidence store should open");

    let report = RunWorkflow::new(RecoveryMethod::trash(root.join("trash")))
        .execute(RunId::new(1), &profile, &probe, |_| true, &mut store, || false)
        .expect("an empty local workflow should complete");

    assert_eq!(report.status(), RunReportStatus::Completed);
    assert_eq!(report.snapshot().peer_a_volume_identity(), Some(source_identity));
    assert_eq!(report.snapshot().peer_b_volume_identity(), Some(destination_identity));

    fs::remove_dir_all(&root).expect("workflow fixture should be removable");
}

#[test]
fn resume_blocks_before_mutation_when_the_recorded_volume_is_replaced() {
    let root = test_root("resume-mismatch");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "resume volume mismatch",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination),
    );
    let probe = LocalPrecheckProbe::default();
    let current_source_identity = probe
        .volume_identity(&source)
        .expect("volume identity probe should succeed")
        .expect("source should have a volume identity");
    let mut store = RunEvidenceStore::open(&root.join("evidence.db"))
        .expect("evidence store should open");
    let snapshot = RunSnapshot::from_profile_with_volume_identities(
        RunId::new(1),
        &profile,
        Default::default(),
        Some(VolumeIdentity::new(current_source_identity.device().saturating_add(1))),
        Some(current_source_identity),
    )
    .expect("snapshot should be valid");
    store.begin_run(&snapshot).expect("snapshot should persist");
    store
        .mark_blocked(RunId::new(1), "simulated interrupted precheck")
        .expect("incomplete run should be blockable");

    let error = RunWorkflow::new(RecoveryMethod::trash(root.join("trash")))
        .resume(RunId::new(1), &probe, |_| true, &mut store, || false)
        .expect_err("a replacement volume must block resume");
    assert!(matches!(error, crate::WorkflowError::Precheck(_)));
    assert!(source.exists());
    let blocked = store
        .load_report(RunId::new(2))
        .expect("blocked resume report should persist");
    assert_eq!(blocked.status(), RunReportStatus::Blocked);
    let reason = blocked
        .blocked_reason()
        .expect("blocked report should explain the reason");
    assert!(reason.contains("filesystem device"));
    assert!(reason.contains(source.to_string_lossy().as_ref()));

    let second_error = RunWorkflow::new(RecoveryMethod::trash(root.join("trash-2")))
        .resume(RunId::new(2), &probe, |_| true, &mut store, || false)
        .expect_err("a replacement volume must remain blocked on a follow-up resume");
    assert!(matches!(second_error, crate::WorkflowError::Precheck(_)));
    assert_eq!(
        store
            .load_report(RunId::new(3))
            .expect("second blocked resume report should persist")
            .status(),
        RunReportStatus::Blocked
    );

    fs::remove_dir_all(&root).expect("resume mismatch fixture should be removable");
}

#[test]
fn replacement_resume_requires_and_honors_explicit_authorization() {
    let root = test_root("resume-authorized-replacement");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "authorized replacement volume",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination.clone()),
    );
    let probe = LocalPrecheckProbe::default();
    let current_source_identity = probe
        .volume_identity(&source)
        .expect("volume identity probe should succeed")
        .expect("source should have a volume identity");
    let current_destination_identity = probe
        .volume_identity(&destination)
        .expect("volume identity probe should succeed")
        .expect("destination should have a volume identity");
    let mut store = RunEvidenceStore::open(&root.join("evidence.db"))
        .expect("evidence store should open");
    let snapshot = RunSnapshot::from_profile_with_volume_identities(
        RunId::new(1),
        &profile,
        Default::default(),
        Some(VolumeIdentity::new(current_source_identity.device().saturating_add(1))),
        Some(current_destination_identity),
    )
    .expect("snapshot should be valid");
    store.begin_run(&snapshot).expect("snapshot should persist");
    store
        .mark_blocked(RunId::new(1), "simulated replacement volume")
        .expect("run should be blockable");

    let report = RunWorkflow::new(RecoveryMethod::trash(root.join("trash")))
        .resume_with_replacement_confirmation(
            RunId::new(1),
            &probe,
            |blocked| blocked.is_replacement_only(),
            |_| true,
            &mut store,
            || false,
        )
        .expect("an explicitly authorized replacement should resume");

    assert_eq!(report.status(), RunReportStatus::Completed);
    assert_eq!(report.snapshot().peer_a_volume_identity(), Some(current_source_identity));
    assert_eq!(
        report.snapshot().peer_b_volume_identity(),
        Some(current_destination_identity)
    );
    assert!(source.exists());
    assert!(destination.exists());

    fs::remove_dir_all(&root).expect("authorized replacement fixture should be removable");
}

#[test]
fn resume_reports_a_missing_recorded_volume_before_running_other_probes() {
    let root = test_root("resume-missing");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "resume missing volume",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination),
    );
    let probe = LocalPrecheckProbe::default();
    let source_identity = probe
        .volume_identity(&source)
        .expect("volume identity probe should succeed")
        .expect("source should have a volume identity");
    let mut store = RunEvidenceStore::open(&root.join("evidence.db"))
        .expect("evidence store should open");
    let snapshot = RunSnapshot::from_profile_with_volume_identities(
        RunId::new(1),
        &profile,
        Default::default(),
        Some(source_identity),
        Some(source_identity),
    )
    .expect("snapshot should be valid");
    store.begin_run(&snapshot).expect("snapshot should persist");
    store
        .mark_blocked(RunId::new(1), "simulated disconnected volume")
        .expect("incomplete run should be blockable");
    fs::remove_dir(&source).expect("source should simulate a missing volume");

    let error = RunWorkflow::new(RecoveryMethod::trash(root.join("trash")))
        .resume(RunId::new(1), &probe, |_| true, &mut store, || false)
        .expect_err("a missing recorded volume must block resume");
    assert!(matches!(error, crate::WorkflowError::Precheck(_)));
    let blocked = store
        .load_report(RunId::new(2))
        .expect("blocked resume report should persist");
    let reason = blocked
        .blocked_reason()
        .expect("blocked report should explain the reason");
    assert!(reason.contains("no volume identity was detected"));
    assert!(reason.contains("filesystem device"));
    assert!(!source.exists());

    fs::remove_dir_all(&root).expect("missing volume fixture should be removable");
}

#[test]
fn resume_blocks_legacy_local_runs_without_a_recorded_volume_identity() {
    let root = test_root("resume-legacy");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).expect("source should be creatable");
    fs::create_dir_all(&destination).expect("destination should be creatable");
    let profile = SyncProfile::new(
        "legacy resume volume",
        Peer::new("source", source.clone()),
        Peer::new("destination", destination),
    );
    let mut store = RunEvidenceStore::open(&root.join("evidence.db"))
        .expect("evidence store should open");
    let legacy_snapshot = RunSnapshot::from_profile(RunId::new(1), &profile, Default::default())
        .expect("legacy snapshot should be valid");
    store
        .begin_run(&legacy_snapshot)
        .expect("legacy snapshot should persist");
    store
        .mark_blocked(RunId::new(1), "legacy run without volume identity")
        .expect("legacy run should be blockable");

    let error = RunWorkflow::new(RecoveryMethod::trash(root.join("trash")))
        .resume(
            RunId::new(1),
            &LocalPrecheckProbe::default(),
            |_| true,
            &mut store,
            || false,
        )
        .expect_err("legacy local run must not resume without an identity baseline");
    assert!(matches!(error, crate::WorkflowError::Precheck(_)));
    let blocked = store
        .load_report(RunId::new(2))
        .expect("legacy blocked resume report should persist");
    assert_eq!(blocked.status(), RunReportStatus::Blocked);
    assert!(blocked
        .blocked_reason()
        .expect("legacy block should explain the reason")
        .contains("no recorded volume identity"));
    assert!(source.exists());

    fs::remove_dir_all(&root).expect("legacy volume fixture should be removable");
}
