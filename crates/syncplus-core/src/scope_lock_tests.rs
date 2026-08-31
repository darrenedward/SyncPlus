use crate::{Peer, PeerScope, PeerScopeLockRegistry, RunId, ScopeLockError, ScopeLockOwner, SshAuthentication, SshPeer};

#[test]
fn normalized_equal_parent_and_child_scopes_are_overlapping() {
    let equal = PeerScope::new("/data/./profile/../profile");
    let parent = PeerScope::new("/data");
    let child = PeerScope::new("/data/profile/files");

    assert_eq!(equal.path(), std::path::Path::new("/data/profile"));
    assert!(equal.overlaps(&parent));
    assert!(parent.overlaps(&child));
    assert!(!PeerScope::new("/other").overlaps(&child));
}

#[test]
fn later_profile_is_blocked_until_the_first_scope_lock_is_released() {
    let registry = PeerScopeLockRegistry::new();
    let first = registry
        .acquire(
            ScopeLockOwner::new("first", RunId::new(1)),
            [PeerScope::new("/data/source"), PeerScope::new("/data/destination")],
        )
        .expect("first profile should acquire both scopes");

    let conflict = registry
        .acquire(
            ScopeLockOwner::new("second", RunId::new(2)),
            [PeerScope::new("/data"), PeerScope::new("/elsewhere")],
        )
        .expect_err("parent scope must be blocked");
    assert!(matches!(conflict, ScopeLockError::Conflict(_)));

    drop(first);
    registry
        .acquire(
            ScopeLockOwner::new("second", RunId::new(2)),
            [PeerScope::new("/data"), PeerScope::new("/elsewhere")],
        )
        .expect("scope should be available after release");
}

#[test]
fn empty_scope_sets_are_rejected_without_creating_a_lock() {
    let registry = PeerScopeLockRegistry::new();
    let error = registry
        .acquire(ScopeLockOwner::new("profile", RunId::new(1)), [])
        .expect_err("empty scope sets cannot protect a run");
    assert!(matches!(error, ScopeLockError::EmptyScopes));
}

#[test]
fn remote_scope_identity_includes_the_ssh_endpoint() {
    let first = Peer::from_ssh(
        "remote one",
        SshPeer::new(
            "one.example.test",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        )
        .expect("first SSH peer should be valid"),
    );
    let second = Peer::from_ssh(
        "remote two",
        SshPeer::new(
            "two.example.test",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        )
        .expect("second SSH peer should be valid"),
    );

    assert!(!PeerScope::for_peer(&first).overlaps(&PeerScope::for_peer(&second)));
}
