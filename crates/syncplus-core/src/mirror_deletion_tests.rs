use std::path::PathBuf;

use super::{
    AnalysisOutcome, InventorySnapshotItem, ItemType, MirrorDeletionChoice, MirrorDeletionDecision,
    MirrorDeletionError, MirrorDeletionOutcome, PeerSide, SourceInventorySnapshot, SyncBaseline,
};

fn file(path: &str, hash: u8) -> InventorySnapshotItem {
    InventorySnapshotItem::from_parts_with_permissions(
        PathBuf::from(path),
        ItemType::RegularFile,
        AnalysisOutcome::Included,
        4,
        Some(1),
        false,
        Some(0o644),
        None,
        Some([hash; 32]),
    )
}

fn inventory(name: &str, items: Vec<InventorySnapshotItem>) -> SourceInventorySnapshot {
    SourceInventorySnapshot::from_parts(name.to_owned(), PathBuf::from(format!("/{name}")), items)
}

fn settled_baseline() -> SyncBaseline {
    SyncBaseline::from_inventories(
        "profile",
        &inventory("A", vec![file("gone.txt", 1)]),
        &inventory("B", vec![file("gone.txt", 1)]),
        Default::default(),
    )
}

#[test]
fn absence_without_baseline_evidence_never_creates_a_deletion_candidate() {
    let baseline = SyncBaseline::from_inventories(
        "profile",
        &inventory("A", Vec::new()),
        &inventory("B", Vec::new()),
        Default::default(),
    );
    let current_a = inventory("A", Vec::new());
    let current_b = inventory("B", vec![file("gone.txt", 1)]);

    assert!(baseline.deletion_candidates(&current_a, &current_b).is_empty());
}

#[test]
fn unchanged_remaining_peer_produces_a_baseline_backed_candidate_with_evidence() {
    let baseline = settled_baseline();
    let current_a = inventory("A", Vec::new());
    let current_b = inventory("B", vec![file("gone.txt", 1)]);
    let candidates = baseline.deletion_candidates(&current_a, &current_b);

    let candidate = candidates.first().expect("baseline-backed deletion candidate");
    assert_eq!(candidate.relative_path(), PathBuf::from("gone.txt"));
    assert_eq!(candidate.missing_peer(), PeerSide::PeerA);
    assert_eq!(candidate.affected_peer(), PeerSide::PeerB);
    assert_eq!(candidate.baseline_missing_state().content_fingerprint(), Some(&[1; 32]));
    assert_eq!(candidate.remaining_state().content_fingerprint(), Some(&[1; 32]));
}

#[test]
fn changed_remaining_peer_is_not_safe_deletion_evidence() {
    let baseline = settled_baseline();
    let current_a = inventory("A", Vec::new());
    let current_b = inventory("B", vec![file("gone.txt", 2)]);

    assert!(baseline.deletion_candidates(&current_a, &current_b).is_empty());
}

#[test]
fn divergent_two_sided_baseline_is_not_deletion_evidence() {
    let baseline = SyncBaseline::from_inventories(
        "profile",
        &inventory("A", vec![file("gone.txt", 2)]),
        &inventory("B", vec![file("gone.txt", 1)]),
        Default::default(),
    );
    let current_a = inventory("A", Vec::new());
    let current_b = inventory("B", vec![file("gone.txt", 1)]);

    assert!(baseline.deletion_candidates(&current_a, &current_b).is_empty());
}

#[test]
fn an_excluded_current_path_is_not_treated_as_a_deletion() {
    let baseline = settled_baseline();
    let excluded = InventorySnapshotItem::from_parts_with_permissions(
        PathBuf::from("gone.txt"),
        ItemType::RegularFile,
        AnalysisOutcome::Excluded,
        4,
        Some(1),
        false,
        Some(0o644),
        None,
        Some([1; 32]),
    );
    let current_a = inventory("A", vec![excluded]);
    let current_b = inventory("B", Vec::new());

    assert!(baseline.deletion_candidates(&current_a, &current_b).is_empty());
}

#[test]
fn deletion_requires_each_path_decision_and_final_execution_confirmation() {
    let baseline = settled_baseline();
    let review = baseline.deletion_review(
        &inventory("A", Vec::new()),
        &inventory("B", vec![file("gone.txt", 1)]),
    );

    assert!(matches!(
        review.resolve([]),
        Err(MirrorDeletionError::MissingDecision { .. })
    ));
    let plan = review
        .resolve([MirrorDeletionDecision::new(
            "gone.txt",
            MirrorDeletionChoice::DeleteCounterpart,
        )])
        .expect("candidate should accept its explicit deletion decision");
    assert!(matches!(
        plan.confirm(false),
        Err(MirrorDeletionError::FinalConfirmationRequired)
    ));
    let confirmed = plan.confirm(true).expect("explicit final confirmation");
    assert!(confirmed.is_finally_confirmed());
    assert_eq!(confirmed.deletion_actions().len(), 1);
}

#[test]
fn preserve_and_defer_are_non_destructive_review_decisions() {
    let baseline = settled_baseline();
    let review = baseline.deletion_review(
        &inventory("A", Vec::new()),
        &inventory("B", vec![file("gone.txt", 1)]),
    );

    for decision in [
        MirrorDeletionChoice::PreserveRemaining,
        MirrorDeletionChoice::Defer,
    ] {
        let confirmed = review
            .resolve([MirrorDeletionDecision::new("gone.txt", decision)])
            .unwrap()
            .confirm(true)
            .unwrap();
        assert!(confirmed.deletion_actions().is_empty());
        assert!(confirmed.requires_review());
    }
}

#[test]
fn failed_deletion_preserves_the_remaining_copy_and_keeps_the_invariant_unresolved() {
    let baseline = settled_baseline();
    let confirmed = baseline
        .deletion_review(
            &inventory("A", Vec::new()),
            &inventory("B", vec![file("gone.txt", 1)]),
        )
        .resolve([MirrorDeletionDecision::new(
            "gone.txt",
            MirrorDeletionChoice::DeleteCounterpart,
        )])
        .unwrap()
        .confirm(true)
        .unwrap();
    let result = confirmed.deletion_actions()[0].failed_preserving_remaining();

    assert_eq!(result.outcome(), MirrorDeletionOutcome::FailedPreserved);
    assert!(result.preserves_remaining_copy());
    assert!(!result.mirror_invariant_restored());
    assert!(result.requires_review());
}

#[test]
fn duplicate_and_unknown_decisions_are_rejected() {
    let baseline = settled_baseline();
    let review = baseline.deletion_review(
        &inventory("A", Vec::new()),
        &inventory("B", vec![file("gone.txt", 1)]),
    );

    assert!(matches!(
        review.resolve([MirrorDeletionDecision::new("unknown.txt", MirrorDeletionChoice::Defer)]),
        Err(MirrorDeletionError::UnknownCandidate { .. })
    ));
    assert!(matches!(
        review.resolve([
            MirrorDeletionDecision::new("gone.txt", MirrorDeletionChoice::Defer),
            MirrorDeletionDecision::new("gone.txt", MirrorDeletionChoice::Defer),
        ]),
        Err(MirrorDeletionError::DuplicateDecision { .. })
    ));
}
