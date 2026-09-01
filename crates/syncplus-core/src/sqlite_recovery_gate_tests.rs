use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use flate2::read::GzDecoder;

use crate::{
    ActionReason, ApplicationMode, ApplicationSettings, AuthorizationSnapshot, ContentProof,
    CompletionReconciliation, DatabaseBackupManager, DeletionMethod, FileIdentity, FreshAnalysis,
    CollisionSafeRestore, CredentialResolutionError, CredentialResolver, HostTrustDecision,
    ItemType, JournalEvent, LocalPrecheckProbe, MetadataRequirements, Peer, PeerSide,
    PlanActionKind, PlanRecord, PreActionState, RecoveryEvidence, RecoveryMethod,
    RecoveryProvenance, RunEvidenceStore, RunId, RunReportStatus, RunSnapshot,
    SavedSecretReference, ScheduleDefinition, SecretStore, SecretStoreError, SecretValue,
    SshAuthentication, SshHost, SshHostFingerprint, SshHostIdentityError, SshHostIdentityProbe,
    SshHostTrustController, SshRunMode, SyncMode, SyncOptions, SyncProfile, ThemePreference,
};

const SECRET_FILE_CONTENT: &[u8] = b"private file contents must never become database evidence";
const SECRET_REFERENCE: &str = "keyring-only-secret-reference";
const SECRET_PASSWORD: &str = "password-value-must-not-leak";
const COMPLETED_PHASE: &str = "completed";
const RECOVERY_REVIEW_PHASE: &str = "recovery_review";
const REMOVAL_COMPLETED_PHASE: &str = "removal_completed";

struct MissingSecretStore;

impl SecretStore for MissingSecretStore {
    fn save(
        &self,
        _reference: &SavedSecretReference,
        _secret: &SecretValue,
    ) -> Result<(), SecretStoreError> {
        Ok(())
    }

    fn load(&self, _reference: &SavedSecretReference) -> Result<SecretValue, SecretStoreError> {
        Err(SecretStoreError::Missing)
    }

    fn delete(&self, _reference: &SavedSecretReference) -> Result<(), SecretStoreError> {
        Ok(())
    }
}

struct FixedFingerprint(SshHostFingerprint);

impl SshHostIdentityProbe for FixedFingerprint {
    fn probe(
        &self,
        _peer: &crate::SshPeer,
    ) -> Result<SshHostFingerprint, SshHostIdentityError> {
        Ok(self.0)
    }
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be available")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "syncplus-sqlite-recovery-gate-{label}-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("data")).expect("create fixture root");
        Self { root }
    }

    fn database(&self) -> PathBuf {
        self.root.join("data/syncplus.db")
    }

    fn source(&self) -> PathBuf {
        self.root.join("source")
    }

    fn destination(&self) -> PathBuf {
        self.root.join("destination")
    }

    fn recovery(&self) -> PathBuf {
        self.root.join("recovery")
    }

    fn backup_manager(&self) -> DatabaseBackupManager {
        DatabaseBackupManager::new(
            self.database(),
            self.root.join("backups"),
            self.root.join("quarantine"),
            self.root.join("cache"),
        )
        .expect("fixture paths should be absolute")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn local_profile(name: &str, source: &Path, destination: &Path) -> SyncProfile {
    SyncProfile::new(
        name,
        Peer::new("source", source.to_path_buf()),
        Peer::new("destination", destination.to_path_buf()),
    )
}

fn ssh_profile(name: &str) -> SyncProfile {
    SyncProfile::new(
        name,
        Peer::new("local", PathBuf::from("/source")),
        Peer::ssh(
            "remote",
            "backup.example.com",
            "sync-user",
            22,
            Some(PathBuf::from("/home/sync-user/.ssh/id_ed25519")),
            SshAuthentication::SavedPassword(
                SavedSecretReference::new(SECRET_REFERENCE).expect("secret reference"),
            ),
            "/srv/backup",
        )
        .expect("SSH peer should be valid"),
    )
}

fn safe_delete_profile(name: &str, source: &Path, destination: &Path) -> SyncProfile {
    local_profile(name, source, destination).with_options(SyncOptions {
        safe_delete: true,
        deletion_method: Some(DeletionMethod::Trash),
        ..SyncOptions::default()
    })
}

fn database_sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn secret_content_copy_plan(action_id: u64, relative_path: &str) -> PlanRecord {
    PlanRecord::new(
        action_id,
        PathBuf::from(relative_path),
        PlanActionKind::CopyToDestination,
        PeerSide::PeerA,
        Some(SECRET_FILE_CONTENT.len() as u64),
        PreActionState::new(
            ItemType::RegularFile,
            SECRET_FILE_CONTENT.len() as u64,
            Some(7),
            Some(FileIdentity::new(1, 2)),
            None,
        ),
    )
}

fn recovery_evidence(provenance: RecoveryProvenance, proof: ContentProof) -> RecoveryEvidence {
    RecoveryEvidence::new(
        99,
        Some(PathBuf::from("recovery/secret.txt")),
        true,
        true,
        true,
        Some(SECRET_FILE_CONTENT.len() as u64),
        Some(SECRET_FILE_CONTENT.len() as u64),
        Some(*proof.sha256()),
        Some(*proof.sha256()),
    )
    .with_provenance(provenance)
}

fn assert_bytes_do_not_contain(path: &Path, secret: &[u8]) {
    let bytes = fs::read(path).expect("read privacy boundary");
    assert!(
        !bytes.windows(secret.len()).any(|window| window == secret),
        "secret bytes leaked into {path:?}"
    );
}

fn assert_backup_does_not_contain(backup: &Path, secret: &[u8]) {
    let file = fs::File::open(backup).expect("open compressed backup");
    let mut decoder = GzDecoder::new(file);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .expect("decompress backup for privacy check");
    assert!(
        !bytes.windows(secret.len()).any(|window| window == secret),
        "secret bytes leaked into backup {backup:?}"
    );
}

#[test]
fn sqlite_recovery_gate_round_trips_all_evidence_and_nonsecret_configuration() {
    let fixture = Fixture::new("round-trip");
    fs::create_dir_all(fixture.source()).expect("create source");
    fs::create_dir_all(fixture.destination()).expect("create destination");
    fs::create_dir_all(fixture.recovery()).expect("create recovery");
    fs::write(fixture.source().join("secret.txt"), SECRET_FILE_CONTENT)
        .expect("write source fixture");
    fs::write(fixture.destination().join("secret.txt"), SECRET_FILE_CONTENT)
        .expect("write destination fixture");

    let editable_profile = local_profile("gate profile", &fixture.source(), &fixture.destination());
    let ssh = ssh_profile("SSH profile");
    let mirror_profile = editable_profile.clone().with_mode(SyncMode::Mirror);
    let host = SshHost::from_peer(ssh.peer_b().ssh_peer().expect("SSH peer"));
    let fingerprint = SshHostFingerprint::sha256([0x2a; 32]);
    let run_id = RunId::new(85);

    let mut store = RunEvidenceStore::open(&fixture.database()).expect("open application database");
    store
        .save_settings(&ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Dark))
        .expect("persist settings");
    let profile_id = store
        .create_profile(&editable_profile)
        .expect("persist local Sync Profile")
        .id();
    store.create_profile(&ssh).expect("persist SSH Sync Profile");
    store
        .update_schedule(
            profile_id,
            Some(ScheduleDefinition::new(15, "Pacific/Auckland", true).expect("valid schedule")),
            ApplicationMode::Advanced,
        )
        .expect("persist enabled schedule");
    store
        .approve_ssh_host_fingerprint(&host, &fingerprint)
        .expect("persist approved SSH host fingerprint");
    assert_eq!(
        store
            .load_ssh_host_fingerprint(&host)
            .expect("load SSH host fingerprint"),
        Some(fingerprint)
    );
    let missing_credential = CredentialResolver::new(MissingSecretStore)
        .resolve(
            ssh.peer_b().ssh_peer().expect("SSH peer"),
            SshRunMode::Interactive,
            None,
        )
        .expect_err("missing saved credential must block without fallback");
    assert_eq!(
        missing_credential,
        CredentialResolutionError::SavedSecretUnavailable
    );
    let secret = SecretValue::new(SECRET_PASSWORD);
    assert!(!format!("{secret:?}").contains(SECRET_PASSWORD));
    assert!(!secret.to_string().contains(SECRET_PASSWORD));

    let mut trust_store = RunEvidenceStore::open_in_memory().expect("open trust store");
    trust_store
        .approve_ssh_host_fingerprint(&host, &fingerprint)
        .expect("persist test host approval");
    let changed = SshHostTrustController::new(trust_store)
        .inspect(
            ssh.peer_b().ssh_peer().expect("SSH peer"),
            &FixedFingerprint(SshHostFingerprint::sha256([0x2b; 32])),
        )
        .expect("inspect changed fingerprint");
    assert!(matches!(changed, HostTrustDecision::ChangedFingerprint { .. }));
    assert!(!changed.is_approved());

    let snapshot = RunSnapshot::from_profile(
        run_id,
        &editable_profile,
        AuthorizationSnapshot::default(),
    )
    .expect("freeze profile snapshot");
    store.begin_run(&snapshot).expect("persist Profile Snapshot");

    let edited_profile = editable_profile.clone().with_exclusion("changed-after-run/");
    store
        .update_profile(profile_id, &edited_profile)
        .expect("edit profile after run start");
    assert_eq!(
        store.load_snapshot(run_id).expect("load frozen snapshot").profile(),
        &editable_profile,
        "Profile Snapshot must not follow later UI edits"
    );

    let analysis = FreshAnalysis::analyze(&mirror_profile).expect("analyze both peers");
    let peer_a = crate::SourceInventorySnapshot::from_inventory(analysis.source_inventory());
    let peer_b = crate::SourceInventorySnapshot::from_inventory(analysis.destination_inventory());
    let baseline = crate::SyncBaseline::from_inventories(
        mirror_profile.name(),
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );
    store
        .record_source_inventory(run_id, &peer_a)
        .expect("persist Source Inventory");
    store
        .record_destination_inventory(run_id, &peer_b)
        .expect("persist destination inventory");
    store
        .update_mirror_baseline(&baseline)
        .expect("persist Sync Baseline");

    let recovered = fixture.recovery().join("secret.txt");
    fs::write(&recovered, SECRET_FILE_CONTENT).expect("write recovery item");
    let proof = ContentProof::from_path(&recovered).expect("hash recovery item");
    let provenance = RecoveryProvenance::new_for_action(
        1,
        "source",
        fixture.source(),
        PathBuf::from("secret.txt"),
        run_id,
        DeletionMethod::Trash,
        ItemType::RegularFile,
        Some(proof),
        Some(FileIdentity::new(1, 2)),
    )
    .expect("create recovery provenance");
    let sidecar = provenance
        .write_sidecar_for(&recovered)
        .expect("persist recovery provenance sidecar");
    let sidecar_text = fs::read_to_string(&sidecar).expect("read recovery sidecar");
    assert!(!sidecar_text.contains(std::str::from_utf8(SECRET_FILE_CONTENT).unwrap()));
    assert_eq!(
        RecoveryProvenance::read_sidecar(&sidecar)
            .expect("reload recovery provenance")
            .relative_path(),
        Path::new("secret.txt")
    );
    let tampered_sidecar = fixture.recovery().join("tampered.syncplus-manifest");
    provenance
        .write_sidecar(&tampered_sidecar)
        .expect("write tamper fixture sidecar");
    let mut tampered_bytes = fs::read(&tampered_sidecar).expect("read tamper fixture sidecar");
    tampered_bytes[0] ^= 1;
    fs::write(&tampered_sidecar, tampered_bytes).expect("tamper sidecar");
    assert!(matches!(
        RecoveryProvenance::read_sidecar(&tampered_sidecar),
        Err(crate::RestoreError::SidecarInvalid(_))
    ));

    let collision_recovered = fixture.recovery().join("collision-recovered");
    let collision_destination = fixture.source().join("collision.txt");
    fs::write(&collision_recovered, b"recovered bytes")
        .expect("write collision recovery item");
    fs::write(&collision_destination, b"newer user bytes")
        .expect("write collision target");
    let collision_provenance = RecoveryProvenance::new(
        "source",
        fixture.source(),
        PathBuf::from("collision.txt"),
        run_id,
        ItemType::RegularFile,
        Some(ContentProof::from_path(&collision_recovered).expect("hash collision item")),
        None,
    )
    .expect("create collision provenance");
    let missing_recovered = fixture.recovery().join("missing-recovered");
    assert!(matches!(
        CollisionSafeRestore::restore(&missing_recovered, &collision_provenance, || false),
        Err(crate::RestoreError::Io(_))
    ));
    assert!(matches!(
        CollisionSafeRestore::restore(&collision_recovered, &collision_provenance, || false),
        Err(crate::RestoreError::Collision(_, _))
    ));
    assert_eq!(
        fs::read(&collision_destination).expect("read preserved collision target"),
        b"newer user bytes"
    );

    store
        .append_event(
            run_id,
            JournalEvent::Planned {
                action: secret_content_copy_plan(1, "secret.txt"),
            },
        )
        .expect("persist planned boundary");
    store
        .append_event(run_id, JournalEvent::Started { action_id: 1 })
        .expect("persist started boundary");
    drop(store);
    let mut store = RunEvidenceStore::open(&fixture.database())
        .expect("reopen after durable action boundary");
    store
        .append_event(
            run_id,
            JournalEvent::RecoveryReview {
                action_id: 1,
                reason: ActionReason::FilesystemUncertain,
                evidence: recovery_evidence(provenance, proof),
            },
        )
        .expect("persist Recovery Review");
    let reconciliation = CompletionReconciliation::reconcile(
        &editable_profile,
        &peer_a,
        &analysis,
        &store.load_journal(run_id).expect("load journal for reconciliation"),
    );
    store
        .record_reconciliation(run_id, &reconciliation)
        .expect("persist Completion Reconciliation");

    let report = store.load_report(run_id).expect("load Run Report");
    assert_eq!(report.status(), RunReportStatus::RecoveryReview);
    assert!(!format!("{report:?}").contains(std::str::from_utf8(SECRET_FILE_CONTENT).unwrap()));
    assert!(store.load_reconciliation(run_id).expect("load reconciliation").is_some());
    let journal = store.load_journal(run_id).expect("load journal");
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].last_phase(), RECOVERY_REVIEW_PHASE);

    let exported = store.export_configuration().expect("export configuration");
    assert!(!exported.contains(SECRET_REFERENCE));
    assert!(!exported.contains("saved_password"));
    assert!(!exported.contains("secret.txt"));
    assert!(!exported.contains(std::str::from_utf8(SECRET_FILE_CONTENT).unwrap()));
    let mut imported = RunEvidenceStore::open_in_memory().expect("open import database");
    let preview = imported
        .preview_configuration_import(&exported)
        .expect("preview configuration import");
    assert_eq!(preview.profile_count(), 2);
    assert_eq!(preview.schedule_count(), 1);
    assert_eq!(preview.credentials_requiring_reconfiguration(), 1);
    imported
        .import_configuration(&exported)
        .expect("import nonsecret configuration");
    assert_eq!(imported.list_profiles().expect("list imported profiles").len(), 2);

    let manager = fixture.backup_manager();
    let backup = manager
        .create_validated_backup(store.connection())
        .expect("create validated evidence backup");
    assert_backup_does_not_contain(backup.path(), SECRET_FILE_CONTENT);

    drop(store);
    for suffix in ["-wal", "-shm"] {
        let sidecar_path = database_sidecar(&fixture.database(), suffix);
        if sidecar_path.is_file() {
            assert_bytes_do_not_contain(&sidecar_path, SECRET_FILE_CONTENT);
        }
    }
    let reopened = RunEvidenceStore::open(&fixture.database())
        .expect("reopen application database");
    assert_eq!(
        reopened.load_settings().expect("reload settings"),
        ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Dark)
    );
    assert_eq!(reopened.list_profiles().expect("reload profiles").len(), 2);
    let persisted_profile = reopened
        .load_profile(profile_id)
        .expect("reload local profile")
        .expect("local profile exists");
    assert!(persisted_profile.schedule().expect("schedule").enabled());
    assert_eq!(
        reopened
            .load_ssh_host_fingerprint(&host)
            .expect("reload SSH host fingerprint"),
        Some(fingerprint)
    );
    assert_eq!(
        reopened.load_report(run_id).expect("reload report").status(),
        RunReportStatus::RecoveryReview
    );
    assert_eq!(
        reopened
            .load_mirror_baseline(mirror_profile.name())
            .expect("reload Sync Baseline")
            .expect("Sync Baseline exists")
            .items()
            .len(),
        baseline.items().len()
    );
    assert_bytes_do_not_contain(&fixture.database(), SECRET_FILE_CONTENT);
    assert_bytes_do_not_contain(&sidecar, SECRET_FILE_CONTENT);
}

#[test]
fn sqlite_recovery_gate_quarantines_corruption_and_restores_a_reviewable_database() {
    let fixture = Fixture::new("backup-restore");
    fs::create_dir_all(fixture.source()).expect("create source");
    fs::create_dir_all(fixture.destination()).expect("create destination");

    let profile = local_profile("protected profile", &fixture.source(), &fixture.destination());
    let run_id = RunId::new(8501);
    let snapshot = RunSnapshot::from_profile(run_id, &profile, AuthorizationSnapshot::default())
        .expect("create snapshot");
    let mut store = RunEvidenceStore::open(&fixture.database()).expect("open database");
    store
        .save_settings(&ApplicationSettings::new(ApplicationMode::Advanced, ThemePreference::Light))
        .expect("save settings");
    store.create_profile(&profile).expect("save profile");
    store.begin_run(&snapshot).expect("save snapshot");
    store
        .append_event(
            run_id,
            JournalEvent::Planned {
                action: secret_content_copy_plan(1, "review.txt"),
            },
        )
        .expect("save plan");
    store
        .append_event(run_id, JournalEvent::Started { action_id: 1 })
        .expect("save start");
    store
        .append_event(
            run_id,
            JournalEvent::Unresolved {
                action_id: 1,
                reason: ActionReason::PermissionDenied,
            },
        )
        .expect("save unresolved outcome");

    let manager = fixture.backup_manager();
    let backup = manager
        .create_validated_backup(store.connection())
        .expect("create validated backup");
    assert!(backup.path().is_file());
    assert_eq!(manager.list_validated_backups().expect("list backups").len(), 1);
    let invalid_backup = fixture.root.join("backups/syncplus-invalid.sqlite.gz");
    fs::write(&invalid_backup, b"not a SQLite backup").expect("write invalid backup");
    assert_eq!(manager.list_validated_backups().expect("filter invalid backup").len(), 1);
    assert!(invalid_backup.is_file(), "invalid evidence must remain available for diagnosis");
    drop(store);

    fs::write(fixture.database(), b"corrupt live SQLite database")
        .expect("simulate corrupt live database");
    let restored_path = manager
        .restore_validated_backup(backup.path())
        .expect("explicit restore should quarantine then install backup");
    assert_eq!(restored_path, fixture.database());
    assert!(fixture.database().is_file());
    let quarantined = fs::read_dir(fixture.root.join("quarantine"))
        .expect("read quarantine")
        .map(|entry| entry.expect("quarantine entry").path())
        .collect::<Vec<_>>();
    assert!(
        quarantined.iter().any(|path| path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("syncplus-corrupt-"))),
        "the corrupt live database must be retained in quarantine"
    );
    assert_eq!(manager.list_validated_backups().expect("protected backups").len(), 1);

    let reopened = RunEvidenceStore::open(&fixture.database()).expect("open restored database");
    assert_eq!(reopened.list_profiles().expect("restored profiles").len(), 1);
    assert_eq!(
        reopened.load_report(run_id).expect("restored report").status(),
        RunReportStatus::CompletedWithReviewRequired
    );
    assert!(fixture.database().metadata().expect("database metadata").len() > 0);
    assert_bytes_do_not_contain(&fixture.database(), SECRET_FILE_CONTENT);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&fixture.database())
                .expect("database metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(fixture.root.join("backups"))
                .expect("backup directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn sqlite_recovery_gate_preserves_concurrent_records_and_filesystem_boundary_uncertainty() {
    let fixture = Fixture::new("concurrency");
    fs::create_dir_all(fixture.source()).expect("create source");
    fs::create_dir_all(fixture.destination()).expect("create destination");
    fs::create_dir_all(fixture.recovery()).expect("create recovery");

    let workers = 4;
    {
        let store = RunEvidenceStore::open(&fixture.database())
            .expect("initialize concurrent database");
        drop(store);
    }
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();
    for worker in 0..workers {
        let barrier = Arc::clone(&barrier);
        let database = fixture.database();
        let source = fixture.root.join(format!("worker-{worker}-source"));
        let destination = fixture.root.join(format!("worker-{worker}-destination"));
        fs::create_dir_all(&source).expect("create worker source");
        fs::create_dir_all(&destination).expect("create worker destination");
        handles.push(thread::spawn(move || {
            let profile = local_profile(
                &format!("scheduler profile {worker}"),
                &source,
                &destination,
            );
            let mut store = RunEvidenceStore::open(&database).expect("open concurrent database");
            barrier.wait();
            let profile_id = store
                .create_profile(&profile)
                .expect("persist concurrent profile")
                .id();
            store
                .update_schedule(
                    profile_id,
                    Some(
                        ScheduleDefinition::new(5 + worker as u32, "Pacific/Auckland", true)
                            .expect("valid concurrent schedule"),
                    ),
                    ApplicationMode::Advanced,
                )
                .expect("persist concurrent schedule");
            let run_id = store.next_run_id().expect("reserve concurrent run id");
            let snapshot = RunSnapshot::from_profile(
                run_id,
                &profile,
                AuthorizationSnapshot::default(),
            )
            .expect("freeze concurrent snapshot");
            store.begin_run(&snapshot).expect("persist concurrent snapshot");
            store
                .append_event(
                    run_id,
                    JournalEvent::Planned {
                        action: secret_content_copy_plan(1, "worker.txt"),
                    },
                )
                .expect("persist concurrent plan");
            store
                .append_event(run_id, JournalEvent::Started { action_id: 1 })
                .expect("persist concurrent start");
            store
                .append_event(
                    run_id,
                    JournalEvent::RecoveryReview {
                        action_id: 1,
                        reason: ActionReason::InterruptedBoundary,
                        evidence: RecoveryEvidence::new(
                            1, None, true, false, false, None, None, None, None,
                        ),
                    },
                )
                .expect("persist concurrent recovery review");
            run_id
        }));
    }
    let run_ids = handles
        .into_iter()
        .map(|handle| handle.join().expect("concurrent worker should finish"))
        .collect::<Vec<_>>();

    let store = RunEvidenceStore::open(&fixture.database()).expect("reopen concurrent database");
    assert_eq!(
        store.list_profiles().expect("list concurrent profiles").len(),
        workers
    );
    assert_eq!(
        store.list_run_reports().expect("list concurrent reports").len(),
        workers
    );
    assert!(store
        .list_profiles()
        .expect("reload concurrent profiles")
        .iter()
        .all(|profile| profile.schedule().is_some_and(|schedule| schedule.enabled())));
    for run_id in run_ids {
        let report = store.load_report(run_id).expect("load concurrent report");
        assert_eq!(report.status(), RunReportStatus::RecoveryReview);
        let journal = store.load_journal(run_id).expect("load concurrent journal");
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].last_phase(), RECOVERY_REVIEW_PHASE);
        assert!(report.items()[0].journal().recovery_evidence().is_some());
    }
    drop(store);

    let source_file = fixture.source().join("filesystem-boundary.txt");
    let destination_file = fixture.destination().join("filesystem-boundary.txt");
    fs::write(&source_file, b"filesystem operation completed before the journal failed")
        .expect("write boundary source");
    let boundary_profile = local_profile(
        "boundary profile",
        &fixture.source(),
        &fixture.destination(),
    );
    let boundary_run = RunId::new(8510);
    let mut boundary_store = RunEvidenceStore::open(&fixture.database())
        .expect("open boundary database");
    boundary_store.fail_next_event_phase_for_test(COMPLETED_PHASE);
    let error = crate::RunWorkflow::new(RecoveryMethod::trash(fixture.recovery()))
        .execute(
            boundary_run,
            &boundary_profile,
            &LocalPrecheckProbe::default(),
            |_| true,
            &mut boundary_store,
            || false,
        )
        .expect_err("journal failure after filesystem install must be surfaced");
    assert!(matches!(error, crate::WorkflowError::Storage(_)));
    assert!(source_file.is_file(), "source remains after uncertain completion");
    assert!(destination_file.is_file(), "destination install already happened");
    assert_eq!(
        boundary_store
            .load_report(boundary_run)
            .expect("load uncertain boundary report")
            .status(),
        RunReportStatus::RecoveryReview
    );

    let safe_fixture = Fixture::new("safe-delete-boundary");
    fs::create_dir_all(safe_fixture.source()).expect("create Safe Delete source");
    fs::create_dir_all(safe_fixture.destination()).expect("create Safe Delete destination");
    fs::create_dir_all(safe_fixture.recovery()).expect("create Safe Delete recovery");
    let safe_delete_source = safe_fixture.source().join("safe-delete-boundary.txt");
    let safe_delete_recovery = safe_fixture.recovery().join("safe-delete-boundary.txt");
    fs::write(&safe_delete_source, b"verified removal before journal failure")
        .expect("write Safe Delete source");
    let safe_delete_profile = safe_delete_profile(
        "Safe Delete boundary",
        &safe_fixture.source(),
        &safe_fixture.destination(),
    );
    let safe_delete_run = RunId::new(8511);
    let mut safe_delete_store = RunEvidenceStore::open(&safe_fixture.database())
        .expect("open Safe Delete boundary database");
    safe_delete_store.fail_next_event_phase_for_test(REMOVAL_COMPLETED_PHASE);
    let safe_delete_report = crate::RunWorkflow::new(RecoveryMethod::trash(safe_fixture.recovery()))
        .execute(
            safe_delete_run,
            &safe_delete_profile,
            &LocalPrecheckProbe::default(),
            |_| true,
            &mut safe_delete_store,
            || false,
        )
        .expect("removal uncertainty must become a reviewable report");
    assert!(!safe_delete_source.exists(), "verified removal already happened");
    assert!(safe_delete_recovery.is_file(), "recovery item must remain available");
    assert_eq!(
        fs::read(&safe_delete_recovery).expect("read recovered Safe Delete item"),
        b"verified removal before journal failure"
    );
    assert_eq!(safe_delete_report.status(), RunReportStatus::RecoveryReview);
    assert!(safe_delete_report.items().iter().any(|item| {
        item.relative_path() == Path::new("safe-delete-boundary.txt")
            && matches!(
                item.outcome(),
                crate::ActionOutcome::RecoveryReview(ActionReason::InterruptedBoundary)
            )
    }));
}
