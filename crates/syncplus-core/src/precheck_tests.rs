use std::{fs, path::PathBuf};

use crate::{
    AccessSnapshot, DestinationNamingPolicy, DeletionMethod, Peer,
    PeerScopeLockRegistry, PrecheckBlockerKind, PrecheckFailure, PrecheckProbe, RunId,
    RemoteAccessRequirements, RemotePrecheckBlockerKind, RemotePrecheckObservation,
    RemotePrecheckRequest, RemoteRsyncCapability, RemoteSha256Capability,
    RemoteTrashCapability, ResolvedSshCredential, RunEvidenceStore, RunPrecheck,
    ScopeLockOwner, SshHostFingerprint, SshHostIdentityError, SshHostIdentityProbe,
    SshHostTrustController, SshPeer, SshRemotePrecheck, SshRemotePrecheckProbe,
    SyncMode, SyncOptions, SyncProfile,
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
    fn volume_identity(
        &self,
        _path: &std::path::Path,
    ) -> Result<Option<crate::VolumeIdentity>, crate::PrecheckError> {
        Ok(None)
    }

    fn requires_volume_identity(&self) -> bool {
        false
    }

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

struct FixedHostProbe(SshHostFingerprint);

impl SshHostIdentityProbe for FixedHostProbe {
    fn probe(&self, _peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError> {
        Ok(self.0)
    }
}

struct FixedRemoteProbe {
    observation: RemotePrecheckObservation,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl SshRemotePrecheckProbe for FixedRemoteProbe {
    fn probe(
        &self,
        _peer: &SshPeer,
        _credential: &ResolvedSshCredential,
        _host_permit: &crate::SshHostTrustPermit,
        _request: &RemotePrecheckRequest,
    ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.observation.clone())
    }
}

fn remote_peer() -> SshPeer {
    SshPeer::new(
        "backup.example.test",
        "sync-user",
        2222,
        None,
        crate::SshAuthentication::Agent,
        "/srv/sync",
    )
    .expect("SSH fixture should be valid")
}

fn approved_host_permit(peer: &SshPeer) -> crate::SshHostTrustPermit {
    let mut controller = SshHostTrustController::new(
        RunEvidenceStore::open_in_memory().expect("SQLite store should open"),
    );
    let probe = FixedHostProbe(SshHostFingerprint::sha256([7; 32]));
    let decision = controller
        .inspect(peer, &probe)
        .expect("host fingerprint probe should succeed");
    controller
        .approve(peer, &decision, crate::HostTrustMode::Interactive)
        .expect("interactive approval should persist");
    controller
        .pre_mutation_permit(peer, &probe)
        .expect("approved host should provide a permit")
}

#[test]
fn remote_precheck_requires_trusted_authentication_and_all_requested_capabilities() {
    let peer = remote_peer();
    let host_permit = approved_host_permit(&peer);
    let request = RemotePrecheckRequest::new(
        RemoteAccessRequirements::new(false, true, true),
        true,
    );
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let probe = FixedRemoteProbe {
        observation: RemotePrecheckObservation::new(
            true,
            AccessSnapshot::new(true, true, true),
            RemoteRsyncCapability::Compatible,
            RemoteSha256Capability::Available,
            RemoteTrashCapability::verified("/srv/.syncplus-trash")
                .expect("Trash fixture should have a location"),
        ),
        calls: calls.clone(),
    };

    let result = SshRemotePrecheck::check(
        &peer,
        &ResolvedSshCredential::Agent,
        &host_permit,
        &request,
        &probe,
    )
    .expect("remote capability probe should complete");

    assert!(result.can_execute());
    assert_eq!(result.account(), "sync-user");
    assert_eq!(result.path(), std::path::Path::new("/srv/sync"));
    assert_eq!(result.trash_location(), Some(std::path::Path::new("/srv/.syncplus-trash")));
    let permit = result
        .require_passed()
        .expect("all remote capabilities should yield a precheck permit");
    assert_eq!(permit.host(), host_permit.host());
    assert_eq!(permit.trash_location(), Some(std::path::Path::new("/srv/.syncplus-trash")));
    assert_eq!(permit.access(), request.access());
    assert!(matches!(
        permit.validate_for(
            &peer,
            &ResolvedSshCredential::Agent,
            &host_permit,
            RemotePrecheckRequest::new(RemoteAccessRequirements::new(true, false, false), false),
        ),
        Err(crate::RemotePrecheckError::RequestMismatch)
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn remote_precheck_blocks_without_falling_back_when_capabilities_are_missing() {
    let peer = remote_peer();
    let host_permit = approved_host_permit(&peer);
    let request = RemotePrecheckRequest::new(
        RemoteAccessRequirements::new(true, true, true),
        true,
    );
    let probe = FixedRemoteProbe {
        observation: RemotePrecheckObservation::new(
            false,
            AccessSnapshot::new(false, false, false),
            RemoteRsyncCapability::Missing,
            RemoteSha256Capability::Unavailable,
            RemoteTrashCapability::unavailable(),
        ),
        calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };

    let result = SshRemotePrecheck::check(
        &peer,
        &ResolvedSshCredential::Agent,
        &host_permit,
        &request,
        &probe,
    )
    .expect("missing capabilities should be represented as blockers");

    assert!(!result.can_execute());
    assert_eq!(result.trash_location(), None);
    let blockers = result.blockers().to_vec();
    assert!(result
        .require_passed()
        .expect_err("blocked remote precheck must not provide a mutation permit")
        .blockers()
        .iter()
        .all(|blocker| {
            !blocker.account().is_empty()
                && !blocker.path().as_os_str().is_empty()
                && !blocker.requirement().is_empty()
                && !blocker.reason().is_empty()
                && !blocker.remediation().is_empty()
        }));
    let kinds: Vec<_> = blockers.iter().map(|blocker| blocker.kind()).collect();
    assert!(kinds.contains(&RemotePrecheckBlockerKind::AuthenticationUnavailable));
    assert!(kinds.contains(&RemotePrecheckBlockerKind::AccountPermission));
    assert!(kinds.contains(&RemotePrecheckBlockerKind::RemoteRsyncUnavailable));
    assert!(kinds.contains(&RemotePrecheckBlockerKind::RemoteSha256Unavailable));
    assert!(kinds.contains(&RemotePrecheckBlockerKind::RemoteTrashUnavailable));
}

#[test]
fn remote_precheck_request_derives_directional_access_and_recovery_requirements() {
    let local = Peer::new("local", PathBuf::from("/local"));
    let remote = Peer::from_ssh("remote", remote_peer());
    let push = SyncProfile::new("push", local.clone(), remote.clone());
    let (_, push_request) = RemotePrecheckRequest::from_profile(&push)
        .expect("local-to-SSH profile should derive a request");
    assert_eq!(push_request.access(), RemoteAccessRequirements::new(false, true, false));
    assert!(!push_request.require_recovery());

    let pull = SyncProfile::new("pull", local, remote)
        .with_source(crate::OneWaySource::PeerB)
        .with_options(SyncOptions {
            safe_delete: true,
            deletion_method: Some(DeletionMethod::Trash),
            ..SyncOptions::default()
        });
    let (_, pull_request) = RemotePrecheckRequest::from_profile(&pull)
        .expect("SSH-to-local profile should derive a request");
    assert_eq!(pull_request.access(), RemoteAccessRequirements::new(true, false, true));
    assert!(pull_request.require_recovery());
}

#[test]
fn remote_precheck_rejects_a_mismatched_host_permit_or_credential_before_probing() {
    let peer = remote_peer();
    let host_permit = approved_host_permit(&peer);
    let request = RemotePrecheckRequest::new(
        RemoteAccessRequirements::new(false, true, false),
        false,
    );
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let probe = FixedRemoteProbe {
        observation: RemotePrecheckObservation::new(
            true,
            AccessSnapshot::new(true, true, true),
            RemoteRsyncCapability::Compatible,
            RemoteSha256Capability::Available,
            RemoteTrashCapability::unavailable(),
        ),
        calls: calls.clone(),
    };

    let other_peer = SshPeer::new(
        "other.example.test",
        "sync-user",
        2222,
        None,
        crate::SshAuthentication::Agent,
        "/srv/sync",
    )
    .expect("SSH fixture should be valid");
    assert_eq!(
        SshRemotePrecheck::check(
            &other_peer,
            &ResolvedSshCredential::Agent,
            &host_permit,
            &request,
            &probe,
        ),
        Err(crate::RemotePrecheckError::HostTrustPermitMismatch)
    );
    assert_eq!(
        SshRemotePrecheck::check(
            &peer,
            &ResolvedSshCredential::Password {
                source: crate::PasswordSource::InteractiveAskpass,
                secret: crate::SecretValue::new("not-for-logs"),
            },
            &host_permit,
            &request,
            &probe,
        ),
        Err(crate::RemotePrecheckError::CredentialDoesNotMatchPeer)
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn mirror_precheck_validates_both_transfer_directions() {
    let probe = passing_probe();
    let calls = probe.probe_calls.clone();
    let result = RunPrecheck::check(
        &profile(PathBuf::from("/peer-a"), PathBuf::from("/peer-b"))
            .with_mode(SyncMode::Mirror),
        &probe,
    )
    .expect("Mirror profile should produce a precheck result");

    assert!(result.can_execute());
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        4,
        "Mirror must probe both peers as source and destination"
    );
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
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    });
    let result = RunPrecheck::check(&safe_delete, &probe).expect("safe delete should precheck");
    assert_eq!(result.warnings().len(), 1);
    assert_eq!(result.warnings()[0].level(), crate::PathRiskLevel::High);
    assert!(result.warnings()[0].requires_stronger_confirmation());
    assert!(result.requires_stronger_confirmation());
    assert!(result.can_execute(), "warnings must remain advisory");
    assert!(!result.is_confirmation_sufficient(false));
    assert!(result.is_confirmation_sufficient(true));
    assert!(ordinary.is_confirmation_sufficient(false));
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
    assert_eq!(result.naming_conflicts().len(), 1);
    assert_eq!(result.naming_conflicts()[0].source_path(), PathBuf::from("Report.txt"));
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
fn missing_local_peer_is_reported_as_a_typed_blocker_before_deep_probing() {
    let destination = TestTree::new();
    let profile = profile(
        PathBuf::from("/path/that/is/not-mounted"),
        destination.path().to_path_buf(),
    );

    let result = RunPrecheck::check(&profile, &crate::LocalPrecheckProbe::default())
        .expect("peer availability belongs in the precheck result");

    let blocker = result
        .blockers()
        .iter()
        .find(|blocker| blocker.kind() == PrecheckBlockerKind::PeerUnavailable)
        .expect("missing source should be a peer-availability blocker");
    assert_eq!(blocker.path(), PathBuf::from("/path/that/is/not-mounted"));
    assert!(!blocker.requirement().is_empty());
    assert!(!blocker.reason().is_empty());
    assert!(!blocker.remediation().is_empty());
}

#[cfg(unix)]
#[test]
fn local_precheck_rejects_real_path_aliases_before_access_or_naming_probes() {
    let root = TestTree::new();
    let source = root.path().join("source");
    fs::create_dir_all(&source).expect("create source");
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias).expect("create parent alias");
    let destination = alias.join("source").join("nested");
    fs::create_dir_all(destination.parent().expect("destination parent"))
        .expect("create destination parent");

    let result = RunPrecheck::check(
        &profile(source, destination),
        &crate::LocalPrecheckProbe::default(),
    )
    .expect("real path alias should be represented as a precheck result");

    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::PeerScopeOverlap));
}

#[test]
fn local_naming_precheck_covers_unicode_reserved_invalid_and_total_path_rules() {
    let source = TestTree::new();
    let destination = TestTree::new();
    fs::write(source.path().join("café.txt"), b"composed").expect("write composed name");
    fs::write(source.path().join("cafe\u{301}.txt"), b"decomposed")
        .expect("write decomposed name");
    fs::write(source.path().join("CON.txt"), b"reserved").expect("write reserved name");
    fs::write(source.path().join("bad:name"), b"invalid").expect("write invalid name");
    fs::write(source.path().join("trailing. "), b"trailing").expect("write trailing name");
    fs::write(source.path().join("long-name-that-exceeds"), b"too long for configured path")
        .expect("write long name");

    let policy = DestinationNamingPolicy::windows_compatible()
        .with_unicode_normalization(true)
        .with_max_path_bytes(destination.path().to_string_lossy().len() + 11);
    let conflicts = crate::LocalPrecheckProbe::new(policy)
        .naming_conflicts(source.path(), destination.path(), &[])
        .expect("naming precheck should complete");

    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::UnicodeNormalizationCollision));
    assert!(conflicts.iter().any(|conflict| {
        conflict.rule() == crate::NamingRule::ReservedName
            && conflict.source_path() == PathBuf::from("CON.txt")
    }));
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::InvalidCharacter));
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::TrailingDotOrSpace));
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::PathTooLong));
}

#[cfg(unix)]
#[test]
fn actual_restricted_filesystem_is_checked_before_mutation_when_available() {
    let Some(filesystem_root) = [PathBuf::from("/mnt/elements"), PathBuf::from("/media")]
        .into_iter()
        .find(|path| path.is_dir())
    else {
        return;
    };
    let fixture_root = filesystem_root.join(format!(
        ".syncplus-precheck-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    if fs::create_dir_all(&fixture_root).is_err() {
        return;
    }
    struct ExternalFixture(PathBuf);
    impl Drop for ExternalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _fixture = ExternalFixture(fixture_root.clone());
    let source = TestTree::new();
    let destination = fixture_root.join("destination");
    fs::create_dir(&destination).expect("create restricted destination");
    fs::write(source.path().join("Report.txt"), b"source").expect("write source collision");
    fs::write(source.path().join("bad:name"), b"source invalid name")
        .expect("write source invalid name");
    fs::write(destination.join("report.txt"), b"existing").expect("write destination collision");

    let conflicts = crate::LocalPrecheckProbe::default()
        .naming_conflicts(source.path(), &destination, &[])
        .expect("restricted destination naming precheck should complete");
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::CaseInsensitiveCollision));
    assert!(conflicts
        .iter()
        .any(|conflict| conflict.rule() == crate::NamingRule::InvalidCharacter));
    assert_eq!(fs::read(destination.join("report.txt")).expect("destination remains"), b"existing");
}

#[cfg(unix)]
#[test]
fn real_permission_precheck_reports_effective_access_without_changing_modes() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let source = TestTree::new();
    let destination = TestTree::new();
    fs::write(source.path().join("item.txt"), b"item").expect("write source");
    let original_mode = fs::metadata(destination.path())
        .expect("destination metadata")
        .permissions()
        .mode();
    fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o555))
        .expect("make destination read-only");

    let result = RunPrecheck::check(
        &profile(source.path().to_path_buf(), destination.path().to_path_buf()),
        &crate::LocalPrecheckProbe::default(),
    )
    .expect("permission failure should be a typed precheck blocker");

    let blocker = result
        .blockers()
        .iter()
        .find(|blocker| blocker.kind() == PrecheckBlockerKind::DestinationNotWritable)
        .expect("destination writability should be reported");
    assert_eq!(blocker.path(), destination.path());
    assert!(!blocker.reason().is_empty());
    assert!(!blocker.remediation().is_empty());
    assert_eq!(
        fs::metadata(destination.path())
            .expect("destination metadata remains available")
            .permissions()
            .mode()
            & 0o777,
        0o555
    );
    fs::set_permissions(destination.path(), fs::Permissions::from_mode(original_mode))
        .expect("restore destination mode");
}

#[cfg(unix)]
#[test]
fn unreadable_local_source_is_reported_without_turning_precheck_into_a_probe_error() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let source = TestTree::new();
    let destination = TestTree::new();
    fs::write(source.path().join("item.txt"), b"item").expect("write source");
    fs::set_permissions(source.path(), fs::Permissions::from_mode(0o000))
        .expect("make source unreadable");

    let result = RunPrecheck::check(
        &profile(source.path().to_path_buf(), destination.path().to_path_buf()),
        &crate::LocalPrecheckProbe::default(),
    )
    .expect("unreadable source should be represented in the result");

    assert!(result
        .blockers()
        .iter()
        .any(|blocker| blocker.kind() == PrecheckBlockerKind::SourceUnreadable));
    fs::set_permissions(source.path(), fs::Permissions::from_mode(0o755))
        .expect("restore source mode");
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
