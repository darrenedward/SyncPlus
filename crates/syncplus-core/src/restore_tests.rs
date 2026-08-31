use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};
use crate::{CollisionSafeRestore, ContentProof, ItemType, RecoveryProvenance, RestoreError, RunId};

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
