use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    AnalysisOutcome, ConflictDecision, ConflictResolution, ConflictReview, ConflictResolutionError,
    FileReviewClassification, InventorySnapshotItem, ItemType, MetadataRequirements, PeerSide,
    ResolutionOperation, SourceInventorySnapshot,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "syncplus-resolution-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("test directory should be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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

fn conflict_review() -> ConflictReview {
    let roots = TestDirectory::new();
    let peer_a = SourceInventorySnapshot::from_parts(
        "A".to_owned(),
        roots.path().to_path_buf(),
        vec![file("same.txt", 1)],
    );
    let peer_b = SourceInventorySnapshot::from_parts(
        "B".to_owned(),
        roots.path().to_path_buf(),
        vec![file("same.txt", 2)],
    );
    // The review owns only immutable evidence, so keeping the roots alive for
    // this constructor is sufficient even though the helper drops them after
    // classification.
    ConflictReview::from_inventories(&peer_a, &peer_b, MetadataRequirements::default())
}

#[test]
fn every_conflict_exposes_the_five_explicit_resolution_choices() {
    let review = conflict_review();
    let entry = review.entries().first().expect("conflict should exist");

    assert_eq!(entry.available_resolutions(), ConflictResolution::all());
    assert_eq!(ConflictResolution::all().len(), 5);
    assert!(entry.is_read_only());
}

#[test]
fn resolution_requires_complete_unique_per_path_decisions_and_final_confirmation() {
    let review = conflict_review();
    let decision = ConflictDecision::new("same.txt", ConflictResolution::KeepPeerA);
    let plan = review
        .resolve([decision])
        .expect("complete resolution should build");

    assert!(!plan.is_finally_confirmed());
    assert!(matches!(
        plan.confirm(false),
        Err(ConflictResolutionError::FinalConfirmationRequired)
    ));
    let confirmed = plan.confirm(true).expect("final confirmation should unlock plan");
    assert!(confirmed.is_finally_confirmed());
}

#[test]
fn keep_peer_resolutions_are_whole_file_operations_with_an_explicit_direction() {
    let review = conflict_review();
    let peer_a_plan = review
        .resolve([ConflictDecision::new(
            "same.txt",
            ConflictResolution::KeepPeerA,
        )])
        .unwrap()
        .confirm(true)
        .unwrap();
    let action = peer_a_plan.actions().first().expect("copy action should exist");

    assert_eq!(action.operation(), ResolutionOperation::CopyWholeFile);
    assert_eq!(action.source_side(), Some(PeerSide::PeerA));
    assert_eq!(action.target_side(), Some(PeerSide::PeerB));
    assert!(!peer_a_plan.requires_review());
}

#[test]
fn preserve_both_rename_and_defer_never_choose_a_winner_or_merge_content() {
    for resolution in [
        ConflictResolution::PreserveBoth,
        ConflictResolution::RenamePreserveForReview,
        ConflictResolution::Defer,
    ] {
        let confirmed = conflict_review()
            .resolve([ConflictDecision::new("same.txt", resolution)])
            .unwrap()
            .confirm(true)
            .unwrap();
        let action = confirmed.actions().first().unwrap();

        assert_eq!(action.source_side(), None);
        assert_eq!(action.target_side(), None);
        assert_ne!(action.operation(), ResolutionOperation::CopyWholeFile);
        assert!(confirmed.requires_review());
    }
}

#[test]
fn missing_unknown_and_duplicate_decisions_are_rejected() {
    let review = conflict_review();
    assert!(matches!(
        review.resolve([]),
        Err(ConflictResolutionError::MissingDecision { .. })
    ));
    assert!(matches!(
        review.resolve([ConflictDecision::new("unknown.txt", ConflictResolution::Defer)]),
        Err(ConflictResolutionError::UnknownConflict { .. })
    ));
    assert!(matches!(
        review.resolve([
            ConflictDecision::new("same.txt", ConflictResolution::Defer),
            ConflictDecision::new("same.txt", ConflictResolution::KeepPeerA),
        ]),
        Err(ConflictResolutionError::DuplicateDecision { .. })
    ));
}

#[test]
fn resolution_does_not_depend_on_file_classification_or_edit_file_contents() {
    let review = conflict_review();
    let confirmed = review
        .resolve([ConflictDecision::new(
            "same.txt",
            ConflictResolution::KeepPeerB,
        )])
        .unwrap()
        .confirm(true)
        .unwrap();

    assert_eq!(
        confirmed.actions()[0].operation(),
        ResolutionOperation::CopyWholeFile
    );
    assert_eq!(
        review.entries()[0].evidence()[0].classification(),
        FileReviewClassification::Unreadable
    );
    assert!(review.is_read_only());
}

#[test]
fn rename_and_compatibility_reviews_only_allow_preservation_or_deferral() {
    let roots = TestDirectory::new();
    let peer_a = SourceInventorySnapshot::from_parts(
        "A".to_owned(),
        roots.path().to_path_buf(),
        vec![file("old.txt", 1)],
    );
    let peer_b = SourceInventorySnapshot::from_parts(
        "B".to_owned(),
        roots.path().to_path_buf(),
        vec![file("new.txt", 1)],
    );
    let rename_review = ConflictReview::from_inventories(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );
    let rename = rename_review.entries().first().expect("rename candidate");
    assert_eq!(rename.available_resolutions().len(), 3);
    assert!(matches!(
        rename_review.resolve([ConflictDecision::for_entry(
            rename,
            ConflictResolution::KeepPeerA,
        )]),
        Err(ConflictResolutionError::UnavailableResolution { .. })
    ));

    let compatibility_review = ConflictReview::from_inventories_with_compatibility_conflicts(
        &SourceInventorySnapshot::from_parts("A".to_owned(), roots.path().to_path_buf(), Vec::new()),
        &SourceInventorySnapshot::from_parts("B".to_owned(), roots.path().to_path_buf(), Vec::new()),
        MetadataRequirements::default(),
        &[super::NamingConflict::new(
            "report.txt",
            "REPORT.txt",
            None,
            super::NamingRule::CaseInsensitiveCollision,
        )],
    );
    let compatibility = compatibility_review
        .entries()
        .first()
        .expect("compatibility conflict");
    assert!(compatibility.available_resolutions().is_empty());
    assert!(matches!(
        compatibility_review.resolve([ConflictDecision::for_entry(
            compatibility,
            ConflictResolution::KeepPeerB,
        )]),
        Err(ConflictResolutionError::UnavailableResolution { .. })
    ));
}

#[test]
fn same_path_and_rename_entries_have_distinct_decision_identity() {
    let roots = TestDirectory::new();
    let peer_a = SourceInventorySnapshot::from_parts(
        "A".to_owned(),
        roots.path().to_path_buf(),
        vec![file("a.txt", 1), file("z.txt", 1)],
    );
    let peer_b = SourceInventorySnapshot::from_parts(
        "B".to_owned(),
        roots.path().to_path_buf(),
        vec![file("a.txt", 2)],
    );
    let review = ConflictReview::from_inventories(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );
    let same_path = review
        .entries()
        .iter()
        .find(|entry| entry.kind() == super::ConflictKind::SamePath)
        .expect("same-path conflict");
    let rename = review
        .entries()
        .iter()
        .find(|entry| {
            entry.kind() == super::ConflictKind::PossibleDuplicateOrRename
                && entry.relative_path() == same_path.relative_path()
        })
        .expect("same-path rename candidate");

    assert_ne!(same_path.key(), rename.key());
    let plan = review
        .resolve([
            ConflictDecision::for_entry(same_path, ConflictResolution::Defer),
            ConflictDecision::for_entry(rename, ConflictResolution::Defer),
        ])
        .expect("both distinct review rows should be resolvable");
    assert_eq!(plan.action_count(), 2);
    assert_eq!(plan.actions()[0].key(), &same_path.key());
    assert_eq!(plan.actions()[1].key(), &rename.key());
}
