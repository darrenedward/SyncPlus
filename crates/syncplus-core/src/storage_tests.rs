use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

use rusqlite::params;

use crate::{
    ApplicationMode, ApplicationSettings, AuthorizationSnapshot, HostTrustError, Peer,
    RunEvidenceStore, RunId, RunSnapshot, SavedSecretReference, ScheduleDefinition,
    SshAuthentication, SshHost, SshHostFingerprint, SyncMode,
    SyncProfile, StorageError, ThemePreference,
};

fn profile() -> SyncProfile {
    SyncProfile::new(
        "work files",
        Peer::new("source", PathBuf::from("/source")),
        Peer::ssh(
            "remote",
            "backup.example.com",
            "sync-user",
            22,
            Some(PathBuf::from("/home/sync-user/.ssh/id_ed25519")),
            SshAuthentication::SavedPassword(
                SavedSecretReference::new("remote-password").expect("valid secret reference"),
            ),
            "/srv/backup",
        )
        .expect("valid SSH peer"),
    )
    .with_exclusions(["*.tmp", "private/"])
}

fn database() -> TestDatabase {
    TestDatabase::new()
}

#[test]
fn application_settings_survive_restart() {
    let database = database();
    {
        let mut store = RunEvidenceStore::open(database.path()).expect("open database");
        assert_eq!(store.load_settings().expect("default settings"), ApplicationSettings::default());
        store
            .save_settings(&ApplicationSettings::new(
                ApplicationMode::Advanced,
                ThemePreference::Dark,
            ))
            .expect("save settings");
    }

    let reopened = RunEvidenceStore::open(database.path()).expect("reopen database");
    assert_eq!(
        reopened.load_settings().expect("load settings"),
        ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Dark)
    );
}

#[test]
fn profiles_round_trip_with_validated_endpoints_and_safe_defaults() {
    let database = database();
    let original = profile();
    let edited = original
        .clone()
        .with_mode(SyncMode::Mirror)
        .with_exclusion("cache/");
    let profile_id;
    {
        let mut store = RunEvidenceStore::open(database.path()).expect("open database");
        let persisted = store.create_profile(&original).expect("create profile");
        profile_id = persisted.id();
        assert_eq!(persisted.profile(), &original);
        assert_eq!(persisted.profile().mode(), SyncMode::OneWay);
        assert!(!persisted.profile().options().safe_delete);
        assert!(!persisted.profile().options().destination_cleanup);
        assert!(!persisted.schedule_enabled());
        assert!(!persisted.authorizations().allow_unattended_destructive());
        assert!(!persisted.authorizations().allow_unattended_permanent_removal());

        store
            .update_profile(profile_id, &edited)
            .expect("update profile");
    }

    let mut reopened = RunEvidenceStore::open(database.path()).expect("reopen database");
    let loaded = reopened
        .load_profile(profile_id)
        .expect("load profile")
        .expect("profile exists");
    assert_eq!(loaded.profile(), &edited);
    assert_eq!(reopened.list_profiles().expect("list profiles").len(), 1);

    assert!(reopened.remove_profile(profile_id).expect("remove profile"));
    assert!(reopened
        .load_profile(profile_id)
        .expect("load removed profile")
        .is_none());
}

#[test]
fn invalid_profiles_are_rejected_before_persistence() {
    let database = database();
    let invalid = SyncProfile::new(
        "",
        Peer::new("source", PathBuf::new()),
        Peer::new("destination", PathBuf::from("/destination")),
    );
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");

    assert!(store.create_profile(&invalid).is_err());
    assert!(store.list_profiles().expect("list profiles").is_empty());
}

#[test]
fn duplicate_endpoint_pairs_are_rejected_independently_of_profile_name() {
    let database = database();
    let first = profile();
    let second = SyncProfile::new(
        "another name",
        Peer::new("different source label", PathBuf::from("/source")),
        Peer::ssh(
            "different remote label",
            "backup.example.com",
            "sync-user",
            22,
            Some(PathBuf::from("/different/identity")),
            SshAuthentication::Agent,
            "/srv/backup",
        )
        .expect("valid SSH peer"),
    );
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");
    store.create_profile(&first).expect("first profile");

    assert!(matches!(
        store.create_profile(&second),
        Err(StorageError::DuplicateEndpointPair)
    ));
}

#[test]
fn explicitly_created_authorizations_round_trip_separately_from_profile_fields() {
    let database = database();
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");
    let profile = profile().with_options(crate::SyncOptions {
        safe_delete: true,
        deletion_method: Some(crate::DeletionMethod::PermanentRemoval),
        ..crate::SyncOptions::default()
    });
    let id = store
        .create_profile_with_authorizations(
            &profile,
            AuthorizationSnapshot::new(true, true),
        )
        .expect("create profile")
        .id();

    let loaded = store
        .load_profile(id)
        .expect("load profile")
        .expect("profile exists");
    assert!(loaded.authorizations().allow_unattended_destructive());
    assert!(loaded.authorizations().allow_unattended_permanent_removal());
    assert_eq!(loaded.profile().name(), "work files");
}

#[test]
fn invalid_unattended_authorizations_are_rejected() {
    let database = database();
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");

    assert!(matches!(
        store.create_profile_with_authorizations(
            &profile(),
            AuthorizationSnapshot::new(true, false),
        ),
        Err(StorageError::InvalidAuthorization(_))
    ));

    let safe_delete_profile = profile().with_options(crate::SyncOptions {
        safe_delete: true,
        deletion_method: Some(crate::DeletionMethod::Trash),
        ..crate::SyncOptions::default()
    });
    assert!(matches!(
        store.create_profile_with_authorizations(
            &safe_delete_profile,
            AuthorizationSnapshot::new(false, true),
        ),
        Err(StorageError::InvalidAuthorization(_))
    ));
}

#[test]
fn recurring_schedule_round_trips_and_requires_advanced_mode_to_enable() {
    let database = database();
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");
    let id = store.create_profile(&profile()).expect("create profile").id();
    let disabled = ScheduleDefinition::new(60, "Pacific/Auckland", false).expect("schedule");

    let persisted = store
        .update_schedule(id, Some(disabled.clone()), ApplicationMode::Simple)
        .expect("save disabled schedule");
    assert_eq!(persisted.schedule(), Some(&disabled));
    assert!(!persisted.schedule_enabled());

    let enabled = disabled.with_enabled(true);
    assert!(matches!(
        store.update_schedule(id, Some(enabled.clone()), ApplicationMode::Simple),
        Err(StorageError::ScheduleRequiresAdvanced)
    ));
    let persisted = store
        .update_schedule(id, Some(enabled.clone()), ApplicationMode::Advanced)
        .expect("enable schedule in Advanced Mode");
    assert_eq!(persisted.schedule(), Some(&enabled));
    assert!(persisted.schedule_enabled());

    drop(store);
    let reopened = RunEvidenceStore::open(database.path()).expect("reopen database");
    let loaded = reopened
        .load_profile(id)
        .expect("load profile")
        .expect("profile exists");
    assert_eq!(loaded.schedule(), Some(&enabled));
}

#[test]
fn profile_edits_and_removal_do_not_mutate_a_started_run_snapshot() {
    let database = database();
    let original = profile();
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");
    let persisted = store.create_profile(&original).expect("create profile");
    let run = RunSnapshot::from_profile(
        RunId::new(79),
        persisted.profile(),
        persisted.authorizations(),
    )
    .expect("create run snapshot");
    store.begin_run(&run).expect("persist run snapshot");

    let edited = original.clone().with_mode(SyncMode::Mirror);
    store
        .update_profile(persisted.id(), &edited)
        .expect("edit profile");
    assert!(store.remove_profile(persisted.id()).expect("remove profile"));

    assert_eq!(store.load_snapshot(RunId::new(79)).expect("load snapshot"), run);
}

#[test]
fn stale_profile_revision_cannot_overwrite_a_concurrent_update() {
    let database = database();
    let mut initializer = RunEvidenceStore::open(database.path()).expect("open database");
    let id = initializer.create_profile(&profile()).expect("create profile").id();
    let baseline = initializer.load_profile(id).expect("load profile").expect("profile exists");
    drop(initializer);

    let mut first = RunEvidenceStore::open(database.path()).expect("open first store");
    let mut second = RunEvidenceStore::open(database.path()).expect("open second store");
    let first_profile = baseline.profile().clone().with_mode(SyncMode::Mirror);
    let second_profile = baseline.profile().clone().with_exclusion("later/");
    first
        .update_profile_with_authorizations_if_revision(
            id,
            &first_profile,
            baseline.authorizations(),
            baseline.revision(),
        )
        .expect("first update");
    assert!(matches!(
        second.update_profile_with_authorizations_if_revision(
            id,
            &second_profile,
            baseline.authorizations(),
            baseline.revision(),
        ),
        Err(StorageError::ConcurrentProfileUpdate)
    ));

    let loaded = first.load_profile(id).expect("load profile").expect("profile exists");
    assert_eq!(loaded.profile().mode(), SyncMode::Mirror);
    assert!(!loaded.profile().exclusions().contains(&"later/".to_owned()));
}

#[test]
fn concurrent_run_id_reservations_are_unique_across_database_connections() {
    let database = database();
    RunEvidenceStore::open(database.path()).expect("initialize database");
    let barrier = Arc::new(Barrier::new(6));
    let handles = (0..5)
        .map(|_| {
            let path = database.path().to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = RunEvidenceStore::open(path).expect("open concurrent store");
                barrier.wait();
                store.next_run_id().expect("reserve run id").value()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let mut ids = handles
        .into_iter()
        .map(|handle| handle.join().expect("reservation thread"))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids, vec![1, 2, 3, 4, 5]);
}

#[test]
fn host_fingerprint_persists_across_restart_and_changed_approval_is_rejected() {
    let database = database();
    let peer = Peer::ssh(
        "remote",
        "backup.example.com",
        "sync-user",
        22,
        None,
        SshAuthentication::Agent,
        "/srv/backup",
    )
    .expect("SSH peer");
    let host = SshHost::from_peer(peer.ssh_peer().expect("SSH peer"));
    let original = SshHostFingerprint::sha256([1; 32]);
    let changed = SshHostFingerprint::sha256([2; 32]);
    {
        let mut store = RunEvidenceStore::open(database.path()).expect("open database");
        store
            .approve_ssh_host_fingerprint(&host, &original)
            .expect("persist host fingerprint");
    }
    let reopened = RunEvidenceStore::open(database.path()).expect("reopen database");
    assert_eq!(
        reopened
            .load_ssh_host_fingerprint(&host)
            .expect("load host fingerprint"),
        Some(original)
    );
    let decision = crate::HostTrustDecision::ChangedFingerprint {
        host: host.clone(),
        approved: original,
        observed: changed,
    };
    let mut controller = crate::SshHostTrustController::new(reopened);
    assert_eq!(
        controller.approve(
            peer.ssh_peer().expect("SSH peer"),
            &decision,
            crate::HostTrustMode::Interactive,
        ),
        Err(HostTrustError::ChangedFingerprintRejected)
    );
}

#[test]
fn profile_storage_keeps_secret_values_out_of_schema_and_rows() {
    let database = database();
    let profile = profile();
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");
    let profile_id = store.create_profile(&profile).expect("create profile").id();

    let authentication: String = store
        .connection()
        .query_row(
            "SELECT peer_b_authentication FROM sync_profiles WHERE profile_id = ?1",
            params![profile_id.value() as i64],
            |row| row.get(0),
        )
        .expect("read authentication reference");
    assert_eq!(authentication, "saved_password:remote-password");
    assert!(!authentication.contains("top-secret-password"));

    let columns = store
        .connection()
        .prepare("PRAGMA table_info(sync_profiles)")
        .expect("inspect profile schema")
        .query_map([], |row| row.get::<_, String>(1))
        .expect("read profile columns")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect profile columns");
    assert!(columns.iter().all(|column| {
        !column.contains("password") && !column.contains("passphrase") && !column.contains("secret_value")
    }));
}

#[test]
fn malformed_persisted_profile_fails_without_exposing_the_stored_value() {
    let database = database();
    let mut store = RunEvidenceStore::open(database.path()).expect("open database");
    let profile_id = store.create_profile(&profile()).expect("create profile").id();

    store
        .connection()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE sync_profiles SET mode = 'malformed-secret-value'
             WHERE profile_id = 1;
             PRAGMA ignore_check_constraints = OFF;",
        )
        .expect("write malformed fixture");

    let error = store
        .load_profile(profile_id)
        .err()
        .expect("malformed profile must fail to load");
    assert!(matches!(error, crate::StorageError::CorruptEvidence(ref reason) if reason == "corrupt Sync Profile record"));
    assert!(!error.to_string().contains("malformed-secret-value"));
}

#[test]
fn evidence_and_profiles_share_the_same_application_database() {
    let database = database();
    let run_profile = SyncProfile::new(
        "evidence profile",
        Peer::new("source", PathBuf::from("/source")),
        Peer::new("destination", PathBuf::from("/destination")),
    );
    let run = RunSnapshot::from_profile(
        RunId::new(44),
        &run_profile,
        AuthorizationSnapshot::default(),
    )
    .expect("valid run snapshot");

    {
        let mut store = RunEvidenceStore::open(database.path()).expect("open database");
        store.begin_run(&run).expect("persist evidence");
        store
            .create_profile(&profile())
            .expect("persist profile in same database");
    }

    let reopened = RunEvidenceStore::open(database.path()).expect("reopen database");
    assert_eq!(reopened.load_snapshot(RunId::new(44)).expect("load evidence").run_id(), RunId::new(44));
    assert_eq!(reopened.list_profiles().expect("load profiles").len(), 1);
}

#[test]
fn database_enables_foreign_keys_and_uses_the_canonical_test_root() {
    let root = TestDirectory::new();
    let expected = root.path().join("syncplus/syncplus.db");
    let store = RunEvidenceStore::open_at_data_home(root.path()).expect("open canonical test database");

    assert_eq!(RunEvidenceStore::canonical_path_for_data_home(root.path()), expected);
    assert_eq!(
        store
            .connection()
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .expect("read foreign-key setting"),
        1
    );
    assert!(expected.is_file());
    assert!(!root.path().join("peer/syncplus.db").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(fs::metadata(expected.parent().expect("database parent")).expect("metadata").permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(expected).expect("metadata").permissions().mode() & 0o777, 0o600);
    }
}

#[cfg(unix)]
#[test]
fn canonical_database_rejects_a_symlinked_live_file() {
    use std::os::unix::fs::symlink;

    let root = TestDirectory::new();
    let data = root.path().join("syncplus");
    fs::create_dir_all(&data).expect("create data directory");
    let target = root.path().join("peer-database.sqlite");
    fs::write(&target, b"not a SyncPlus database").expect("create target file");
    symlink(&target, data.join("syncplus.db")).expect("create database symlink");

    let error = RunEvidenceStore::open_at_data_home(root.path())
        .err()
        .expect("symlinked database must be rejected");
    assert!(matches!(error, crate::StorageError::UnsafeDatabasePath));
}

#[cfg(unix)]
#[test]
fn canonical_database_rejects_a_symlinked_parent_directory() {
    use std::os::unix::fs::symlink;

    let root = TestDirectory::new();
    let target = root.path().join("real-data");
    fs::create_dir_all(&target).expect("create target data directory");
    symlink(&target, root.path().join("syncplus")).expect("create data directory symlink");

    let error = RunEvidenceStore::open_at_data_home(root.path())
        .err()
        .expect("symlinked database parent must be rejected");
    assert!(matches!(error, crate::StorageError::UnsafeDatabasePath));
}

#[test]
fn canonical_database_rejects_a_relative_data_home() {
    let error = RunEvidenceStore::open_at_data_home(std::path::Path::new("relative-data-home"))
        .err()
        .expect("relative data home must be rejected");
    assert!(matches!(error, crate::StorageError::UnsafeDatabasePath));
}

#[cfg(unix)]
#[test]
fn canonical_database_fails_safely_when_the_data_home_cannot_be_created() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    use std::os::unix::fs::PermissionsExt;

    let root = TestDirectory::new();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o500))
        .expect("restrict test data home");
    assert!(RunEvidenceStore::open_at_data_home(root.path()).is_err());
}

#[test]
fn invalid_sqlite_file_fails_during_database_initialization() {
    let database = database();
    fs::write(database.path(), b"not sqlite").expect("write invalid database");

    assert!(RunEvidenceStore::open(database.path()).is_err());
}

#[test]
fn foreign_key_violation_is_rejected() {
    let database = database();
    let store = RunEvidenceStore::open(database.path()).expect("open database");
    let result = store.connection().execute(
        "INSERT INTO sync_profile_exclusions (profile_id, ordinal, pattern) VALUES (?1, ?2, ?3)",
        params![9_999_i64, 0_i64, "*.tmp"],
    );

    assert!(result.is_err());
}

struct TestDatabase {
    root: PathBuf,
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let root = unique_temp_path("syncplus-profile");
        fs::create_dir_all(&root).expect("create database test directory");
        Self {
            path: root.join("syncplus.db"),
            root,
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = unique_temp_path("syncplus-profile-root");
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ))
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
