use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ApplicationMode, ApplicationSettings, AuthorizationSnapshot, DeletionMethod, Peer,
    RunEvidenceStore, SavedSecretReference, ScheduleDefinition, SshAuthentication, SyncMode,
    SyncOptions, SyncProfile, ThemePreference,
};

fn profile() -> SyncProfile {
    SyncProfile::new(
        "migration profile",
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
    .with_mode(SyncMode::OneWay)
    .with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: true,
        deletion_method: Some(DeletionMethod::PermanentRemoval),
        ..SyncOptions::default()
    })
    .with_exclusions(["*.tmp", "private/"])
}

#[test]
fn export_is_explicit_nonsecret_configuration_and_import_strips_authority() {
    let mut source = RunEvidenceStore::open_in_memory().expect("open source database");
    source
        .save_settings(
            &ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Dark)
                .with_hide_to_tray_on_window_close(false),
        )
        .expect("save settings");
    let profile_id = source
        .create_profile_with_authorizations(&profile(), AuthorizationSnapshot::new(true, true))
        .expect("save profile");
    source
        .update_schedule(
            profile_id.id(),
            Some(ScheduleDefinition::new(60, "Pacific/Auckland", true).expect("schedule")),
            ApplicationMode::Advanced,
        )
        .expect("save schedule");

    let json = source.export_configuration().expect("export configuration");
    assert!(!json.contains("remote-password"));
    assert!(!json.contains("saved_password"));
    assert!(!json.contains("top-secret-password"));
    assert!(!json.contains("run_snapshots"));
    assert!(json.contains("schema_version"));
    assert!(json.contains("\"theme\": \"dark\""));
    assert!(!json.contains("#"));
    assert!(!json.contains("00FF85"));
    assert!(!json.contains("FF0099"));
    assert!(!json.contains("79D2C3"));

    let mut imported = RunEvidenceStore::open_in_memory().expect("open import database");
    let preview = imported
        .preview_configuration_import(&json)
        .expect("preview import");
    assert_eq!(preview.profile_names(), &["migration profile".to_owned()]);
    assert_eq!(preview.profile_count(), 1);
    assert_eq!(preview.schedule_count(), 1);
    assert_eq!(preview.destructive_options_stripped(), 1);
    assert_eq!(preview.credentials_requiring_reconfiguration(), 1);
    assert_eq!(preview.enabled_schedules_disabled(), 1);

    imported
        .import_configuration(&json)
        .expect("import configuration");
    let persisted = imported
        .list_profiles()
        .expect("list imported profiles")
        .pop()
        .expect("imported profile");
    assert!(!persisted.profile().options().safe_delete);
    assert!(!persisted.profile().options().destination_cleanup);
    assert_eq!(persisted.profile().options().deletion_method, None);
    assert!(!persisted.authorizations().allow_unattended_destructive());
    assert!(
        !persisted
            .authorizations()
            .allow_unattended_permanent_removal()
    );
    assert!(!persisted.schedule().expect("schedule").enabled());
    assert_eq!(
        persisted
            .profile()
            .peer_b()
            .ssh_peer()
            .expect("SSH peer")
            .authentication(),
        SshAuthentication::InteractivePassword
    );
}

#[test]
fn malformed_and_incompatible_imports_are_read_only_and_secret_safe() {
    let mut store = RunEvidenceStore::open_in_memory().expect("open database");
    store
        .save_settings(&ApplicationSettings::new(
            ApplicationMode::Simple,
            ThemePreference::Light,
        ))
        .expect("save settings");
    store.create_profile(&profile()).expect("save profile");
    let before = store.export_configuration().expect("export baseline");

    let malformed = before.replacen(
        "\"profiles\": [",
        "\"profiles\": [{\"password\":\"secret-value\"},",
        1,
    );
    let error = store
        .import_configuration(&malformed)
        .expect_err("unknown secret field must be rejected");
    assert!(!error.to_string().contains("secret-value"));
    assert_eq!(
        store
            .export_configuration()
            .expect("export after rejection"),
        before
    );

    let malformed_peer = before.replacen(
        "\"root\": \"/source\"",
        "\"root\": \"/source\", \"password\": \"secret-value\"",
        1,
    );
    let error = store
        .import_configuration(&malformed_peer)
        .expect_err("unknown peer secret field must be rejected");
    assert!(!error.to_string().contains("secret-value"));
    assert_eq!(
        store
            .export_configuration()
            .expect("export after peer rejection"),
        before
    );

    let incompatible = before.replacen("\"schema_version\": 1", "\"schema_version\": 99", 1);
    assert!(matches!(
        store.preview_configuration_import(&incompatible),
        Err(crate::ConfigurationTransferError::UnsupportedSchemaVersion(
            99
        ))
    ));
    assert_eq!(
        store
            .export_configuration()
            .expect("export after version rejection"),
        before
    );
}

#[test]
fn imported_configuration_survives_restart() {
    let root = std::env::temp_dir().join(format!(
        "syncplus-config-transfer-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create test directory");
    let path = root.join("syncplus.db");

    let mut source = RunEvidenceStore::open_in_memory().expect("open source database");
    source
        .save_settings(
            &ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Dark)
                .with_hide_to_tray_on_window_close(false),
        )
        .expect("save settings");
    source.create_profile(&profile()).expect("save profile");
    let json = source.export_configuration().expect("export configuration");

    {
        let mut target = RunEvidenceStore::open(&path).expect("open target database");
        target
            .import_configuration(&json)
            .expect("import configuration");
    }
    let reopened = RunEvidenceStore::open(&path).expect("reopen target database");
    assert_eq!(
        reopened.load_settings().expect("load settings"),
        ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Dark)
            .with_hide_to_tray_on_window_close(false)
    );
    assert_eq!(reopened.list_profiles().expect("load profiles").len(), 1);

    fs::remove_dir_all(root).expect("remove test directory");
}
