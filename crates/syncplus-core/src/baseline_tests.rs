use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    ActionReason, AnalysisOutcome, CompletionReconciliation, InventorySnapshotItem, ItemType,
    MetadataRequirements, MirrorEquality, ReconciliationReason, SourceInventorySnapshot,
    RunEvidenceStore, SyncBaseline, SyncBaselineItemStatus,
};

fn file(path: &str, hash: u8, modified_at: i64) -> InventorySnapshotItem {
    InventorySnapshotItem::from_parts_with_permissions(
        PathBuf::from(path),
        ItemType::RegularFile,
        AnalysisOutcome::Included,
        4,
        Some(modified_at),
        false,
        Some(0o644),
        None,
        Some([hash; 32]),
    )
}

fn inventory(name: &str, items: Vec<InventorySnapshotItem>) -> SourceInventorySnapshot {
    SourceInventorySnapshot::from_parts(name.to_owned(), PathBuf::from(format!("/{name}")), items)
}

#[test]
fn mirror_equality_uses_only_enabled_metadata() {
    let left = file("same.txt", 1, 10);
    let right = file("same.txt", 1, 20);

    assert!(MirrorEquality::new(MetadataRequirements::default()).equal(&left, &right));
    assert!(!MirrorEquality::new(MetadataRequirements::new(true, true, true, true))
        .equal(&left, &right));
}

#[test]
fn baseline_comparison_reports_new_changed_absent_and_unchanged_per_peer() {
    let baseline = SyncBaseline::from_inventories(
        "profile",
        &inventory("a", vec![file("unchanged", 1, 1), file("absent", 2, 1)]),
        &inventory("b", vec![file("unchanged", 1, 1), file("changed", 3, 1)]),
        MetadataRequirements::default(),
    );
    let current_a = inventory("a", vec![file("unchanged", 1, 1), file("new", 4, 1)]);
    let current_b = inventory("b", vec![file("unchanged", 1, 1), file("changed", 9, 1)]);

    let comparisons = baseline.compare(&current_a, &current_b);

    assert_eq!(
        comparisons
            .iter()
            .find(|item| item.relative_path() == PathBuf::from("unchanged"))
            .unwrap()
            .peer_a(),
        SyncBaselineItemStatus::Unchanged
    );
    assert_eq!(
        comparisons
            .iter()
            .find(|item| item.relative_path() == PathBuf::from("new"))
            .unwrap()
            .peer_a(),
        SyncBaselineItemStatus::New
    );
    assert_eq!(
        comparisons
            .iter()
            .find(|item| item.relative_path() == PathBuf::from("changed"))
            .unwrap()
            .peer_b(),
        SyncBaselineItemStatus::Changed
    );
    assert_eq!(
        comparisons
            .iter()
            .find(|item| item.relative_path() == PathBuf::from("absent"))
            .unwrap()
            .peer_a(),
        SyncBaselineItemStatus::Absent
    );
}

#[test]
fn unresolved_paths_are_not_added_to_a_baseline_candidate() {
    let peer_a = inventory("a", vec![file("ok", 1, 1), file("failed", 2, 1)]);
    let peer_b = inventory("b", vec![file("ok", 1, 1), file("failed", 2, 1)]);
    let reconciliation = CompletionReconciliation::from_parts(
        crate::SourceDrainStatus::NotApplicable,
        vec![crate::ReconciliationFinding::from_parts(
            PathBuf::from("failed"),
            ReconciliationReason::Failed(ActionReason::TransferFailed),
        )],
    );

    let baseline = SyncBaseline::from_reconciled_inventories(
        "profile",
        &peer_a,
        &peer_b,
        &[],
        &reconciliation,
        MetadataRequirements::default(),
    );

    assert!(baseline.item("ok").is_some());
    assert!(baseline.item("failed").is_none());
}

#[test]
fn baseline_is_durable_and_merges_only_settled_updates() {
    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "syncplus-baseline-{}-{}.sqlite",
        std::process::id(),
        NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut store = RunEvidenceStore::open(&path).expect("baseline store should open");
    let initial = SyncBaseline::from_inventories(
        "profile",
        &inventory("a", vec![file("settled", 1, 1)]),
        &inventory("b", vec![file("settled", 1, 1)]),
        MetadataRequirements::default(),
    );
    store
        .update_mirror_baseline(&initial)
        .expect("initial baseline should persist");

    let update = SyncBaseline::from_inventories(
        "profile",
        &inventory("a", vec![file("new-settled", 2, 1)]),
        &inventory("b", vec![file("new-settled", 2, 1)]),
        MetadataRequirements::default(),
    );
    store
        .update_mirror_baseline(&update)
        .expect("settled update should persist");
    drop(store);

    let store = RunEvidenceStore::open(&path).expect("baseline store should reopen");
    let loaded = store
        .load_mirror_baseline("profile")
        .expect("baseline should load")
        .expect("baseline should exist");
    assert!(loaded.item("settled").is_some());
    assert!(loaded.item("new-settled").is_some());
    drop(store);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = fs::remove_file(path.with_extension("sqlite-shm"));
}
