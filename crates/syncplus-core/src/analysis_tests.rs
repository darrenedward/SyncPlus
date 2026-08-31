use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::symlink;

use crate::{
    AnalysisError, AnalysisOutcome, DeletionMethod, FreshAnalysis, ItemType, OneWaySource,
    Peer, PeerSide, PlanActionKind, SyncMode, SyncOptions, SyncProfile,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let suffix = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "syncplus-analysis-{label}-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be creatable");
        Self { path }
    }

    fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn profile(source: &TestDirectory, destination: &TestDirectory) -> SyncProfile {
    SyncProfile::new(
        "Analysis test",
        Peer::new("Source", source.path.clone()),
        Peer::new("Destination", destination.path.clone()),
    )
    .with_source(OneWaySource::PeerA)
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("test parent should be creatable");
    }
    fs::write(path, contents).expect("test file should be writable");
}

#[test]
fn mirror_first_run_plans_one_sided_items_in_both_directions_without_deletion() {
    let peer_a = TestDirectory::new("mirror-a");
    let peer_b = TestDirectory::new("mirror-b");
    write_file(&peer_a.join("from-a.txt"), b"a");
    write_file(&peer_b.join("from-b.txt"), b"b");
    let profile = profile(&peer_a, &peer_b).with_mode(SyncMode::Mirror);

    let analysis = FreshAnalysis::analyze(&profile).expect("Mirror peers should be analyzable");
    assert_eq!(analysis.specification().mode(), SyncMode::Mirror);
    assert_eq!(analysis.plan().actions().len(), 2);
    assert!(analysis.plan().actions().iter().all(|action| {
        action.kind() == PlanActionKind::CopyToDestination
    }));
    assert_eq!(analysis.plan().summary().considered_count(), 2);
    assert_eq!(analysis.plan().summary().included_count(), 2);
    assert!(analysis
        .plan()
        .approved_scope()
        .included_paths()
        .any(|path| path == Path::new("from-a.txt")));
    assert!(analysis
        .plan()
        .approved_scope()
        .included_paths()
        .any(|path| path == Path::new("from-b.txt")));
    assert!(analysis.plan().actions().iter().any(|action| {
        action.relative_path() == Path::new("from-a.txt") && action.source_side() == PeerSide::PeerA
    }));
    assert!(analysis.plan().actions().iter().any(|action| {
        action.relative_path() == Path::new("from-b.txt") && action.source_side() == PeerSide::PeerB
    }));
    assert!(analysis
        .plan()
        .actions()
        .iter()
        .all(|action| action.consequence().contains("Peer")));
    assert!(analysis.plan().actions().iter().all(|action| !analysis.plan().is_deletion_candidate(action.relative_path())));
}

#[test]
fn hidden_items_are_included_and_inventory_records_identity_type_metadata_and_outcome() {
    let source = TestDirectory::new("hidden-source");
    let destination = TestDirectory::new("hidden-destination");
    write_file(&source.join(".hidden"), b"hidden");
    write_file(&source.join(".hidden-directory/item"), b"nested");

    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("local peers should be analyzable");
    let hidden = analysis
        .source_inventory()
        .items()
        .iter()
        .find(|item| item.relative_path() == Path::new(".hidden"))
        .expect("hidden files should be inventoried");
    let hidden_directory = analysis
        .source_inventory()
        .items()
        .iter()
        .find(|item| item.relative_path() == Path::new(".hidden-directory"))
        .expect("hidden directories should be inventoried");

    assert_eq!(hidden.item_type(), ItemType::RegularFile);
    assert_eq!(hidden.outcome(), AnalysisOutcome::Included);
    assert_eq!(hidden.metadata().size(), 6);
    assert_eq!(hidden_directory.item_type(), ItemType::Directory);
    assert_eq!(hidden_directory.outcome(), AnalysisOutcome::Included);
    assert!(analysis
        .source_inventory()
        .approved_scope()
        .included_paths()
        .any(|path| path == Path::new(".hidden")));
}

#[test]
fn only_owned_syncplus_transfer_artifacts_are_hidden_from_user_inventory() {
    let source = TestDirectory::new("partial-artifact-source");
    let destination = TestDirectory::new("partial-artifact-destination");
    write_file(&source.join(".syncplus-partial-123-copy.txt"), b"partial");
    write_file(&source.join(".syncplus-user-file.txt"), b"user file");
    write_file(&source.join("visible.txt"), b"visible");

    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("reserved partial artifacts should not affect analysis");
    assert!(analysis
        .source_inventory()
        .item(".syncplus-partial-123-copy.txt")
        .is_none());
    assert!(analysis
        .source_inventory()
        .item(".syncplus-user-file.txt")
        .is_some());
    assert!(analysis.source_inventory().item("visible.txt").is_some());
}

#[test]
fn exclusions_are_recorded_outside_scope_and_never_become_candidates() {
    let source = TestDirectory::new("excluded-source");
    let destination = TestDirectory::new("excluded-destination");
    write_file(&source.join("keep.txt"), b"keep");
    write_file(&source.join("skip.tmp"), b"skip");
    write_file(&source.join("node_modules/package.js"), b"package");
    write_file(&destination.join("skip.tmp"), b"destination copy");
    write_file(&destination.join("node_modules/old.js"), b"old");

    let profile = profile(&source, &destination)
        .with_exclusion("*.tmp")
        .with_exclusion("node_modules/")
        .with_options(SyncOptions {
            safe_delete: false,
            destination_cleanup: true,
            deletion_method: None,
            metadata: Default::default(),
            partial_transfer_policy: Default::default(),
            retry_policy: Default::default(),
        });
    let analysis = FreshAnalysis::analyze(&profile).expect("exclusions should be analyzable");

    for relative_path in ["skip.tmp", "node_modules", "node_modules/package.js"] {
        let item = analysis
            .source_inventory()
            .items()
            .iter()
            .find(|item| item.relative_path() == Path::new(relative_path))
            .unwrap_or_else(|| panic!("{relative_path} should be inventoried"));
        assert_eq!(item.outcome(), AnalysisOutcome::Excluded);
    }

    assert!(analysis
        .source_inventory()
        .approved_scope()
        .included_paths()
        .all(|path| path != Path::new("skip.tmp")));
    assert_eq!(
        analysis.plan().summary().excluded_count(),
        analysis.source_inventory().excluded_items().count()
    );
    assert!(analysis.plan().actions().iter().all(|action| {
        action.relative_path() != Path::new("skip.tmp")
            && action.relative_path() != Path::new("node_modules")
            && action.relative_path() != Path::new("node_modules/old.js")
    }));
    assert_eq!(analysis.plan().summary().destination_removal_count(), 0);
}

#[test]
fn one_way_source_authority_plans_same_path_difference_as_an_overwrite() {
    let source = TestDirectory::new("authority-source");
    let destination = TestDirectory::new("authority-destination");
    write_file(&source.join("same.txt"), b"source-authority");
    write_file(&destination.join("same.txt"), b"destination-version");

    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("same-path differences should be analyzable");
    let action = analysis
        .plan()
        .actions()
        .iter()
        .find(|action| action.relative_path() == Path::new("same.txt"))
        .expect("a same-path difference should produce an action");

    assert_eq!(action.kind(), PlanActionKind::OverwriteDestination);
    assert!(action.consequence().contains("source"));
    assert_eq!(action.size(), Some(16));
}

#[test]
fn one_way_source_authority_can_select_peer_b() {
    let peer_a = TestDirectory::new("peer-a-authority");
    let peer_b = TestDirectory::new("peer-b-authority");
    write_file(&peer_a.join("same.txt"), b"peer-a version");
    write_file(&peer_b.join("same.txt"), b"peer-b version");

    let analysis = FreshAnalysis::analyze(
        &profile(&peer_a, &peer_b).with_source(OneWaySource::PeerB),
    )
    .expect("peer B should be selectable as the authoritative source");
    let action = analysis
        .plan()
        .action_for("same.txt")
        .expect("the selected source difference should produce an action");

    assert_eq!(action.kind(), PlanActionKind::OverwriteDestination);
    assert_eq!(action.source_side(), crate::PeerSide::PeerB);
}

#[test]
fn plan_summary_reports_action_counts_and_applicable_sizes() {
    let source = TestDirectory::new("summary-source");
    let destination = TestDirectory::new("summary-destination");
    write_file(&source.join("copy.txt"), b"copy");
    write_file(&source.join("overwrite.txt"), b"overwrite");
    write_file(&destination.join("overwrite.txt"), b"old");
    write_file(&destination.join("orphan.txt"), b"orphan");

    let analysis = FreshAnalysis::analyze(
        &profile(&source, &destination).with_options(SyncOptions {
            safe_delete: false,
            destination_cleanup: true,
            deletion_method: None,
            metadata: Default::default(),
            partial_transfer_policy: Default::default(),
            retry_policy: Default::default(),
        }),
    )
    .expect("the summary should be based on a valid process specification");
    let summary = analysis.plan().summary();

    assert!(analysis
        .plan()
        .actions()
        .iter()
        .all(|action| !action.consequence().trim().is_empty()));
    assert_eq!(summary.copy_count(), 1);
    assert_eq!(summary.copy_bytes(), 4);
    assert_eq!(summary.overwrite_count(), 1);
    assert_eq!(summary.overwrite_bytes(), 9);
    assert_eq!(summary.destination_removal_count(), 1);
    assert_eq!(summary.destination_removal_bytes(), 6);
    assert_eq!(summary.total_action_count(), 3);
    assert!(analysis.plan().validate().is_ok());
}

#[test]
fn material_changes_invalidate_the_old_analysis_before_confirmation() {
    let source = TestDirectory::new("stale-source");
    let destination = TestDirectory::new("stale-destination");
    write_file(&source.join("changing.txt"), b"before");
    let profile = profile(&source, &destination);
    let analysis = FreshAnalysis::analyze(&profile).expect("initial analysis should succeed");

    write_file(&source.join("changing.txt"), b"change");

    let error = analysis
        .confirm(&profile)
        .expect_err("confirmation must require a fresh analysis after a material change");
    assert!(matches!(error, AnalysisError::StaleAnalysis { .. }));

    let fresh = FreshAnalysis::analyze(&profile).expect("fresh analysis should succeed");
    assert!(fresh.confirm(&profile).is_ok());
}

#[test]
fn newly_appeared_items_invalidate_the_old_analysis_before_confirmation() {
    let source = TestDirectory::new("new-item-source");
    let destination = TestDirectory::new("new-item-destination");
    let profile = profile(&source, &destination);
    let analysis = FreshAnalysis::analyze(&profile).expect("initial analysis should succeed");

    write_file(&source.join("appeared.txt"), b"appeared");

    assert!(matches!(
        analysis.confirm(&profile),
        Err(AnalysisError::StaleAnalysis { .. })
    ));
}

#[cfg(unix)]
#[test]
fn symlinks_are_inventoried_as_links_without_following_their_targets() {
    let source = TestDirectory::new("symlink-source");
    let destination = TestDirectory::new("symlink-destination");
    write_file(&source.join("target.txt"), b"target");
    symlink("target.txt", source.join("link.txt")).expect("test symlink should be creatable");

    let analysis = FreshAnalysis::analyze(&profile(&source, &destination))
        .expect("symlink peers should be analyzable");
    let link = analysis
        .source_inventory()
        .item("link.txt")
        .expect("the symlink should be inventoried");

    assert_eq!(link.item_type(), ItemType::Symlink);
    assert_eq!(link.metadata().symlink_target(), Some(Path::new("target.txt")));
    assert!(analysis.source_inventory().item("link.txt/target.txt").is_none());
}

#[test]
fn safe_delete_and_destination_cleanup_actions_follow_validated_process_options() {
    let source = TestDirectory::new("options-source");
    let destination = TestDirectory::new("options-destination");
    write_file(&source.join("drain.txt"), b"drain");
    write_file(&destination.join("orphan.txt"), b"orphan");
    let profile = profile(&source, &destination).with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: true,
        deletion_method: Some(DeletionMethod::Trash),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    });

    let analysis = FreshAnalysis::analyze(&profile).expect("explicit destructive options are valid");
    let kinds: Vec<_> = analysis
        .plan()
        .actions()
        .iter()
        .map(|action| action.kind())
        .collect();

    assert!(kinds.contains(&PlanActionKind::CopyToDestination));
    assert!(kinds.contains(&PlanActionKind::RemoveSourceAfterVerification));
    assert!(kinds.contains(&PlanActionKind::RemoveDestination));
    assert!(analysis.plan().validate().is_ok());
    assert_eq!(
        analysis.plan().specification().options(),
        analysis.specification().options()
    );
}
