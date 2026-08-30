use std::{fs, path::PathBuf};

use crate::{
    AccessSnapshot, DestinationNamingPolicy, DeletionMethod, Peer,
    PeerScopeLockRegistry, PrecheckBlockerKind, PrecheckFailure, PrecheckProbe, RunId,
    RunPrecheck, ScopeLockOwner, SyncOptions, SyncProfile,
};

#[derive(Clone)]
struct FakeProbe {
    source: AccessSnapshot,
    destination: AccessSnapshot,
    available_space: u64,
    required_space: u64,
    naming_conflicts: Vec<crate::NamingConflict>,
    probe_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PrecheckProbe for FakeProbe {
    fn source_access(
        &self,
        _path: &std::path::Path,
    ) -> Result<AccessSnapshot, crate::PrecheckError> {
        self.probe_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.source)
    }

    fn destination_access(
        &self,
        _path: &std::path::Path,
    ) -> Result<AccessSnapshot, crate::PrecheckError> {
        self.probe_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.destination)
    }

    fn available_space(
        &self,
        _path: &std::path::Path,
    ) -> Result<u64, crate::PrecheckError> {
        Ok(self.available_space)
    }

    fn required_space(
        &self,
        _source: &std::path::Path,
        _destination: &std::path::Path,
        _options: crate::ValidatedSyncOptions,
        _exclusions: &[String],
    ) -> Result<u64, crate::PrecheckError> {
        Ok(self.required_space)
    }

    fn naming_conflicts(
        &self,
        _source: &std::path::Path,
        _destination: &std::path::Path,
        _exclusions: &[String],
    ) -> Result<Vec<crate::NamingConflict>, crate::PrecheckError> {
        Ok(self.naming_conflicts.clone())
    }
}

fn profile(source: PathBuf, destination: PathBuf) -> SyncProfile {
    SyncProfile::new("precheck profile", Peer::new("source", source), Peer::new("destination", destination))
}

fn passing_probe() -> FakeProbe {
    FakeProbe {
        source: AccessSnapshot::new(true, false, true),
        destination: AccessSnapshot::new(true, true, true),
        available_space: 100,
        required_space: 10,
        naming_conflicts: Vec::new(),
        probe_calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    }
}

#[test]
fn blocked_precheck_reports_plain_language_remediation_and_no_execution_permit() {
    let mut probe = passing_probe();
    probe.source = AccessSnapshot::new(false, false, false);
    probe.destination = AccessSnapshot::new(true, false, true);
    probe.available_space = 1;
    probe.required_space = 10;

    let result = RunPrecheck::check(&profile(PathBuf::from("/source"), PathBuf::from("/destination")), &probe)
        .expect("valid profile should produce a precheck result");

    assert!(!result.can_execute());
    assert!(result.require_passed().is_err());
    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::SourceUnreadable));
    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::DestinationNotWritable));
    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::InsufficientSpace));
    assert!(result.blockers().iter().all(|blocker| {
        !blocker.path().as_os_str().is_empty()
            && !blocker.requirement().is_empty()
            && !blocker.remediation().is_empty()
    }));
}

#[test]
fn overlap_is_hard_blocked_before_probe_or_execution() {
    let probe = passing_probe();
    let calls = probe.probe_calls.clone();
    let result = RunPrecheck::check(
        &profile(PathBuf::from("/data/source"), PathBuf::from("/data/source/backup")),
        &probe,
    )
    .expect("valid profile should produce a precheck result");

    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::PeerScopeOverlap));
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn path_warning_is_advisory_and_only_safe_delete_receives_it() {
    let source = PathBuf::from("/home");
    let destination = PathBuf::from("/backup");
    let probe = passing_probe();

    let ordinary = RunPrecheck::check(&profile(source.clone(), destination.clone()), &probe)
        .expect("ordinary profile should precheck");
    assert!(ordinary.warnings().is_empty());
    assert!(ordinary.can_execute());

    let safe_delete = profile(source, destination).with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
    });
    let result = RunPrecheck::check(&safe_delete, &probe).expect("safe delete should precheck");
    assert_eq!(result.warnings().len(), 1);
    assert_eq!(result.warnings()[0].level(), crate::PathRiskLevel::High);
    assert!(result.can_execute(), "warnings must remain advisory");
}

#[test]
fn naming_conflicts_block_the_affected_action() {
    let mut probe = passing_probe();
    probe.naming_conflicts = vec![crate::NamingConflict::new(
        PathBuf::from("Report.txt"),
        PathBuf::from("report.txt"),
        None,
        crate::NamingRule::CaseInsensitiveCollision,
    )];
    let result = RunPrecheck::check(
        &profile(PathBuf::from("/source"), PathBuf::from("/destination")),
        &probe,
    )
    .expect("valid profile should precheck");

    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::DestinationNamingConflict));
    assert!(result.blockers().iter().any(|blocker| blocker
        .requirement()
        .contains("destination naming")));
}

#[test]
fn blocked_precheck_does_not_acquire_a_peer_scope_lock() {
    let registry = PeerScopeLockRegistry::new();
    let owner = ScopeLockOwner::new("profile", RunId::new(1));
    let mut probe = passing_probe();
    probe.destination = AccessSnapshot::new(true, false, true);
    let failure = RunPrecheck::check_and_lock(
        &profile(PathBuf::from("/source"), PathBuf::from("/destination")),
        &probe,
        &registry,
        owner,
    )
    .expect_err("writability blocker should prevent a lock");
    assert!(matches!(failure, PrecheckFailure::Blocked(_)));

    let later = registry.acquire(
        ScopeLockOwner::new("later", RunId::new(2)),
        [crate::PeerScope::new("/source"), crate::PeerScope::new("/destination")],
    );
    assert!(later.is_ok());
}

#[test]
fn local_probe_names_are_checked_without_following_symlinks() {
    let root = TestTree::new();
    fs::write(root.path().join("visible.txt"), b"contents").expect("write fixture");
    #[cfg(unix)] std::os::unix::fs::symlink(root.path().join("visible.txt"), root.path().join("link"))
        .expect("create symlink fixture");

    let probe = crate::LocalPrecheckProbe::new(DestinationNamingPolicy::case_insensitive());
    let conflicts = probe
        .naming_conflicts(root.path(), &root.path().join("destination"), &[])
        .expect("local naming probe should succeed");
    assert!(conflicts.is_empty(), "a symlink target is not traversed as a file");
}

#[test]
fn local_probe_detects_case_collisions_against_an_existing_destination_name() {
    let source = TestTree::new();
    let destination = TestTree::new();
    fs::write(source.path().join("Report.txt"), b"source").expect("write source fixture");
    fs::write(destination.path().join("report.txt"), b"destination")
        .expect("write destination fixture");

    let probe = crate::LocalPrecheckProbe::new(DestinationNamingPolicy::case_insensitive());
    let conflicts = probe
        .naming_conflicts(source.path(), destination.path(), &[])
        .expect("local naming probe should succeed");
    assert!(conflicts.iter().any(|conflict| {
        conflict.rule() == crate::NamingRule::CaseInsensitiveCollision
            && conflict.related_path().is_some()
    }));
}

#[test]
fn a_passing_precheck_lease_holds_the_lock_for_the_execution_permit() {
    let registry = PeerScopeLockRegistry::new();
    let probe = passing_probe();
    let lease = RunPrecheck::check_and_lock(
        &profile(PathBuf::from("/source"), PathBuf::from("/destination")),
        &probe,
        &registry,
        ScopeLockOwner::new("profile", RunId::new(1)),
    )
    .expect("passing precheck should acquire a lease");
    assert_eq!(lease.permit().source(), std::path::Path::new("/source"));
    assert!(registry
        .acquire(
            ScopeLockOwner::new("later", RunId::new(2)),
            [crate::PeerScope::new("/source")],
        )
        .is_err());
    drop(lease);
    assert!(registry
        .acquire(
            ScopeLockOwner::new("later", RunId::new(2)),
            [crate::PeerScope::new("/source")],
        )
        .is_ok());
}

struct TestTree(PathBuf);

impl TestTree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "syncplus-precheck-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create test tree");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
