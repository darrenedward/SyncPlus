use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};
use crate::{CollisionSafeRestore, ContentProof, ItemType, RecoveryProvenance, RestoreError, RunId};
use sha2::{Digest, Sha256};

fn temp_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!("syncplus-restore-test-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir_all(&path).unwrap(); path
}

#[test]
fn restore_refuses_different_existing_destination() {
    let root = temp_dir(); let recovered = root.join("recovered"); let destination = root.join("target");
    fs::write(&recovered, b"recovered").unwrap(); fs::write(&destination, b"newer work").unwrap();
    let provenance = RecoveryProvenance::new("local", root.clone(), PathBuf::from("target"), RunId::new(7), ItemType::RegularFile, Some(ContentProof::from_path(&recovered).unwrap()), None).unwrap();
    let result = CollisionSafeRestore::restore(&recovered, &provenance, || false);
    assert!(matches!(result, Err(RestoreError::Collision(_, _))));
    assert_eq!(fs::read(&destination).unwrap(), b"newer work");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restore_cancellation_leaves_destination_absent_and_no_temporary() {
    let root = temp_dir(); let recovered = root.join("recovered");
    fs::write(&recovered, b"recovered").unwrap();
    let provenance = RecoveryProvenance::new("local", root.clone(), PathBuf::from("target"), RunId::new(8), ItemType::RegularFile, Some(ContentProof::from_path(&recovered).unwrap()), None).unwrap();
    assert!(matches!(CollisionSafeRestore::restore(&recovered, &provenance, || true), Err(RestoreError::Cancelled)));
    assert!(!root.join("target").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn sidecar_tampering_is_rejected_before_restore() {
    let root = temp_dir(); let sidecar = root.join("item.manifest");
    let provenance = RecoveryProvenance::new("local", root.clone(), PathBuf::from("target"), RunId::new(9), ItemType::RegularFile, None, None).unwrap();
    provenance.write_sidecar(&sidecar).unwrap();
    let mut bytes = fs::read(&sidecar).unwrap(); bytes[0] = b'X'; fs::write(&sidecar, bytes).unwrap();
    assert!(matches!(RecoveryProvenance::read_sidecar(&sidecar), Err(RestoreError::SidecarInvalid(_))));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn sidecar_round_trip_preserves_remote_recovery_provenance_and_digest() {
    let root = temp_dir();
    let sidecar = root.join("item.manifest");
    let content = ContentProof::new(11, [7; 32]);
    let provenance = RecoveryProvenance::new(
        "sync-user@backup.example.test:2222",
        PathBuf::from("/srv/sync"),
        PathBuf::from("nested/report.txt"),
        RunId::new(10),
        ItemType::RegularFile,
        Some(content),
        Some(crate::FileIdentity::new(42, 99)),
    )
    .unwrap();
    provenance.write_sidecar(&sidecar).unwrap();

    let loaded = RecoveryProvenance::read_sidecar(&sidecar).unwrap();
    assert_eq!(loaded.peer(), provenance.peer());
    assert_eq!(loaded.original_root(), provenance.original_root());
    assert_eq!(loaded.relative_path(), provenance.relative_path());
    assert_eq!(loaded.run_id(), provenance.run_id());
    assert_eq!(loaded.item_type(), ItemType::RegularFile);
    assert_eq!(loaded.content(), Some(content));
    assert_eq!(loaded.source_identity(), provenance.source_identity());
    assert_eq!(loaded.removed_at_unix_nanos(), provenance.removed_at_unix_nanos());
    assert_eq!(loaded.recovery_method(), crate::DeletionMethod::Trash);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restore_from_sidecar_rejects_a_missing_manifest() {
    let root = temp_dir();
    let recovered = root.join("recovered");
    fs::write(&recovered, b"recovered").unwrap();
    let sidecar = RecoveryProvenance::sidecar_path(&recovered).unwrap();

    assert!(matches!(
        CollisionSafeRestore::restore_from_sidecar(&recovered, &sidecar, || false),
        Err(RestoreError::SidecarInvalid(_))
    ));
    assert!(!root.join("target").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restore_from_sidecar_rejects_the_wrong_recovered_item() {
    let root = temp_dir();
    let recovered = root.join("recovered");
    let sidecar = root.join("recovered.syncplus-manifest");
    fs::write(&recovered, b"actual item").unwrap();
    let provenance = RecoveryProvenance::new(
        "local",
        root.clone(),
        PathBuf::from("target"),
        RunId::new(12),
        ItemType::RegularFile,
        Some(ContentProof::new(8, [1; 32])),
        None,
    )
    .unwrap();
    provenance.write_sidecar(&sidecar).unwrap();

    assert!(matches!(
        CollisionSafeRestore::restore_from_sidecar(&recovered, &sidecar, || false),
        Err(RestoreError::Verification(_))
    ));
    assert!(!root.join("target").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn sidecar_rejects_duplicate_or_missing_required_fields() {
    let root = temp_dir();
    let sidecar = root.join("item.manifest");
    let provenance = RecoveryProvenance::new(
        "sync-user@backup.example.test:2222",
        PathBuf::from("/srv/sync"),
        PathBuf::from("report.txt"),
        RunId::new(11),
        ItemType::RegularFile,
        None,
        None,
    )
    .unwrap();
    provenance.write_sidecar(&sidecar).unwrap();
    let original = fs::read_to_string(&sidecar).unwrap();
    let payload = original
        .split_once("\nchecksum=")
        .unwrap()
        .0
        .to_owned()
        + "\n";

    let duplicate = format!("{payload}peer_hex=73796e63\n");
    write_sidecar_payload(&sidecar, &duplicate);
    assert!(matches!(
        RecoveryProvenance::read_sidecar(&sidecar),
        Err(RestoreError::SidecarInvalid(_))
    ));

    let missing_peer = payload
        .lines()
        .filter(|line| !line.starts_with("peer_hex="))
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    write_sidecar_payload(&sidecar, &missing_peer);
    assert!(matches!(
        RecoveryProvenance::read_sidecar(&sidecar),
        Err(RestoreError::SidecarInvalid(_))
    ));
    let _ = fs::remove_dir_all(root);
}

fn write_sidecar_payload(path: &std::path::Path, payload: &str) {
    let mut digest = Sha256::new();
    digest.update(payload.as_bytes());
    let checksum = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    fs::write(path, format!("{payload}checksum={checksum}\n")).unwrap();
}
