use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    AnalysisOutcome, ConflictKind, ConflictReview, FileReviewClassification, InventorySnapshotItem,
    ItemType, MetadataRequirements, NamingConflict, NamingRule, PeerSide, SourceInventorySnapshot,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "syncplus-conflict-{}-{}",
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

fn file(path: &str, size: u64, hash: Option<u8>) -> InventorySnapshotItem {
    InventorySnapshotItem::from_parts_with_permissions(
        PathBuf::from(path),
        ItemType::RegularFile,
        AnalysisOutcome::Included,
        size,
        Some(1),
        false,
        Some(0o644),
        None,
        hash.map(|hash| [hash; 32]),
    )
}

fn inventory(name: &str, root: &Path, items: Vec<InventorySnapshotItem>) -> SourceInventorySnapshot {
    SourceInventorySnapshot::from_parts(name.to_owned(), root.to_path_buf(), items)
}

#[test]
fn same_path_differences_are_read_only_conflicts_with_both_versions() {
    let roots = TestDirectory::new();
    let peer_a = inventory("A", roots.path(), vec![file("same.txt", 4, Some(1))]);
    let peer_b = inventory("B", roots.path(), vec![file("same.txt", 4, Some(2))]);

    let review = ConflictReview::from_inventories(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );

    let conflict = review
        .entries()
        .iter()
        .find(|entry| entry.kind() == ConflictKind::SamePath)
        .expect("same-path difference should be reviewed");
    assert!(conflict.is_read_only());
    assert_eq!(conflict.evidence().len(), 2);
    assert!(conflict.evidence().iter().any(|e| e.side() == PeerSide::PeerA));
    assert!(conflict.evidence().iter().any(|e| e.side() == PeerSide::PeerB));
}

#[test]
fn enabled_metadata_difference_is_a_conflict_even_when_content_matches() {
    let roots = TestDirectory::new();
    let peer_a = inventory("A", roots.path(), vec![file("same.sh", 4, Some(1))]);
    let peer_b = inventory(
        "B",
        roots.path(),
        vec![InventorySnapshotItem::from_parts_with_permissions(
            PathBuf::from("same.sh"),
            ItemType::RegularFile,
            AnalysisOutcome::Included,
            4,
            Some(1),
            false,
            Some(0o755),
            None,
            Some([1; 32]),
        )],
    );

    let review = ConflictReview::from_inventories(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );

    let conflict = review
        .entries()
        .iter()
        .find(|entry| entry.relative_path() == Path::new("same.sh"))
        .expect("enabled executable metadata difference should be reviewed");
    assert_eq!(conflict.evidence()[0].permissions(), Some(0o644));
    assert_eq!(conflict.evidence()[1].permissions(), Some(0o755));
}

#[test]
fn review_classifies_text_binary_large_and_unreadable_files_safely() {
    let roots = TestDirectory::new();
    fs::write(roots.path().join("text.txt"), b"left\nright\n").expect("text file");
    fs::write(roots.path().join("binary.bin"), [0, 1, 2, 3]).expect("binary file");
    fs::write(roots.path().join("large.bin"), vec![b'x'; 1_048_577]).expect("large file");
    let peer_a = inventory(
        "A",
        roots.path(),
        vec![
            file("text.txt", 11, Some(1)),
            file("binary.bin", 4, Some(2)),
            file("large.bin", 1_048_577, Some(3)),
            file("unreadable.bin", 9, None),
        ],
    );
    let peer_b = inventory(
        "B",
        roots.path(),
        vec![
            file("text.txt", 11, Some(4)),
            file("binary.bin", 4, Some(5)),
            file("large.bin", 1_048_577, Some(6)),
            file("unreadable.bin", 9, None),
        ],
    );

    let review = ConflictReview::from_inventories(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );

    for (path, expected) in [
        ("text.txt", FileReviewClassification::Text),
        ("binary.bin", FileReviewClassification::Binary),
        ("large.bin", FileReviewClassification::Large),
        ("unreadable.bin", FileReviewClassification::Unreadable),
    ] {
        let entry = review
            .entries()
            .iter()
            .find(|entry| entry.relative_path() == Path::new(path))
            .expect("same-path conflict should be present");
        assert!(entry.evidence().iter().all(|e| e.classification() == expected));
    }
}

#[test]
fn same_hash_at_different_paths_is_only_a_duplicate_or_rename_candidate() {
    let roots = TestDirectory::new();
    let peer_a = inventory("A", roots.path(), vec![file("old.txt", 4, Some(1))]);
    let peer_b = inventory("B", roots.path(), vec![file("new.txt", 4, Some(1))]);

    let review = ConflictReview::from_inventories(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
    );

    let candidate = review
        .entries()
        .iter()
        .find(|entry| entry.kind() == ConflictKind::PossibleDuplicateOrRename)
        .expect("same hash at different paths should be review evidence");
    assert!(candidate.is_read_only());
    assert_eq!(candidate.related_path(), Some(Path::new("new.txt")));
}

#[test]
fn destination_compatibility_uses_the_same_read_only_review_boundary() {
    let roots = TestDirectory::new();
    let peer_a = inventory("A", roots.path(), Vec::new());
    let peer_b = inventory("B", roots.path(), Vec::new());
    let conflict = NamingConflict::new(
        "report.txt",
        "REPORT.txt",
        Some(PathBuf::from("report.TXT")),
        NamingRule::CaseInsensitiveCollision,
    );

    let review = ConflictReview::from_inventories_with_compatibility_conflicts(
        &peer_a,
        &peer_b,
        MetadataRequirements::default(),
        &[conflict],
    );

    let entry = review
        .entries()
        .iter()
        .find(|entry| entry.kind() == ConflictKind::DestinationCompatibility)
        .expect("destination compatibility should be reviewable");
    assert!(entry.is_read_only());
    assert_eq!(entry.compatibility_rule(), Some(NamingRule::CaseInsensitiveCollision));
}
