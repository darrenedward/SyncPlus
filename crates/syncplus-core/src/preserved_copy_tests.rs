use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ConflictResolution, ConflictResolutionAction, DestinationNamingPolicy, PeerSide,
    PreservedCopyExecutionOutcome, PreservedCopyExecutor, PreservedCopyPlan,
    PreservedCopyReviewState, PreservedCopyPlanner, PreservedPathInventory,
};

fn inventory(policy: DestinationNamingPolicy, peer_a: &[&str], peer_b: &[&str]) -> PreservedPathInventory {
    PreservedPathInventory::new(
        policy,
        peer_a.iter().map(PathBuf::from),
        peer_b.iter().map(PathBuf::from),
    )
}

fn action(path: &str, resolution: ConflictResolution) -> ConflictResolutionAction {
    ConflictResolutionAction::new(path, resolution)
}

#[test]
fn preserve_both_plans_distinct_copies_on_each_peer_without_overwriting_originals() {
    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::default(),
        &["report.pdf"],
        &["report.pdf"],
    ));

    let plan = planner
        .plan(&action("report.pdf", ConflictResolution::PreserveBoth))
        .expect("Preserve Both should produce a plan")
        .expect("Preserve Both is a copy-producing resolution");

    assert_eq!(plan.copies().len(), 2);
    assert!(plan.copies().iter().all(|copy| copy.preserves_original()));
    assert!(plan.copies().iter().all(|copy| copy.requires_explicit_removal()));
    assert_ne!(plan.copies()[0].generated_path(), plan.copies()[1].generated_path());
    assert!(plan.copies().iter().any(|copy| {
        copy.source_peer() == PeerSide::PeerA
            && copy.target_peer() == PeerSide::PeerB
            && copy.generated_path() == PathBuf::from("report (Peer A).pdf")
    }));
    assert!(plan.copies().iter().any(|copy| {
        copy.source_peer() == PeerSide::PeerB
            && copy.target_peer() == PeerSide::PeerA
            && copy.generated_path() == PathBuf::from("report (Peer B).pdf")
    }));
}

#[test]
fn rename_resolution_uses_deterministic_collision_safe_suffixes() {
    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::case_insensitive(),
        &["report.pdf", "report (Peer B).pdf"],
        &[
            "report.pdf",
            "report (Peer A).pdf",
            "REPORT (PEER A) (2).PDF",
        ],
    ));

    let plan = planner
        .plan(&action(
            "report.pdf",
            ConflictResolution::RenamePreserveForReview,
        ))
        .expect("Rename Resolution should produce a plan")
        .expect("Rename Resolution is a copy-producing resolution");

    assert_eq!(
        plan.copy_for(PeerSide::PeerB).expect("Peer B copy").generated_path(),
        PathBuf::from("report (Peer B) (2).pdf")
    );
    assert_eq!(
        plan.copy_for(PeerSide::PeerA).expect("Peer A copy").generated_path(),
        PathBuf::from("report (Peer A) (3).pdf")
    );
}

#[test]
fn preserved_copy_plan_is_a_report_with_review_later_provenance() {
    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::default(),
        &["nested/report.pdf"],
        &["nested/report.pdf"],
    ));
    let plan: PreservedCopyPlan = planner
        .plan(&action("nested/report.pdf", ConflictResolution::PreserveBoth))
        .unwrap()
        .unwrap();

    for copy in plan.copies() {
        assert_eq!(copy.original_path(), PathBuf::from("nested/report.pdf"));
        assert_eq!(copy.review_state(), PreservedCopyReviewState::ReviewLater);
        assert!(copy.generated_path().starts_with("nested"));
        assert!(!copy.generated_path().ends_with("report.pdf"));
    }
    assert!(plan.requires_review());
    assert!(plan.is_available_for_later_removal());
}

#[test]
fn planner_reserves_generated_paths_and_rejects_unsafe_relative_paths() {
    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::default(),
        &["report.pdf"],
        &["report.pdf"],
    ));
    let first = planner
        .plan(&action("report.pdf", ConflictResolution::PreserveBoth))
        .unwrap()
        .unwrap();
    let second = planner
        .plan(&action("report.pdf", ConflictResolution::PreserveBoth))
        .unwrap()
        .unwrap();

    let first_paths: BTreeSet<_> = first
        .copies()
        .iter()
        .map(|copy| copy.generated_path().to_path_buf())
        .collect();
    assert!(second
        .copies()
        .iter()
        .all(|copy| !first_paths.contains(copy.generated_path())));

    let error = planner
        .plan(&action("../report.pdf", ConflictResolution::PreserveBoth))
        .expect_err("parent traversal must be refused");
    assert!(matches!(error, crate::PreservedCopyError::UnsafeRelativePath { .. }));
}

#[test]
fn non_preservation_decisions_do_not_create_preserved_copy_operations() {
    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::default(),
        &["report.pdf"],
        &["report.pdf"],
    ));

    assert!(planner
        .plan(&action("report.pdf", ConflictResolution::KeepPeerA))
        .unwrap()
        .is_none());
}

struct TestRoots {
    root: PathBuf,
}

impl TestRoots {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("syncplus-preserved-copy-test-{unique}"));
        fs::create_dir_all(&root).expect("create test roots");
        Self { root }
    }

    fn peer_a(&self) -> PathBuf {
        self.root.join("peer-a")
    }

    fn peer_b(&self) -> PathBuf {
        self.root.join("peer-b")
    }
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn executor_copies_each_peer_version_and_keeps_originals() {
    let roots = TestRoots::new();
    fs::create_dir_all(roots.peer_a()).unwrap();
    fs::create_dir_all(roots.peer_b()).unwrap();
    fs::write(roots.peer_a().join("report.pdf"), b"peer a").unwrap();
    fs::write(roots.peer_b().join("report.pdf"), b"peer b").unwrap();

    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::default(),
        &["report.pdf"],
        &["report.pdf"],
    ));
    let plan = planner
        .plan(&action("report.pdf", ConflictResolution::PreserveBoth))
        .unwrap()
        .unwrap();
    let report = PreservedCopyExecutor::new(roots.peer_a(), roots.peer_b())
        .execute(&plan);

    assert!(!report.has_unresolved());
    assert_eq!(report.items().len(), 2);
    assert!(report.items().iter().all(|item| {
        matches!(item.outcome(), PreservedCopyExecutionOutcome::Copied)
    }));
    assert_eq!(fs::read(roots.peer_a().join("report.pdf")).unwrap(), b"peer a");
    assert_eq!(fs::read(roots.peer_b().join("report.pdf")).unwrap(), b"peer b");
    assert_eq!(
        fs::read(roots.peer_a().join("report (Peer B).pdf")).unwrap(),
        b"peer b"
    );
    assert_eq!(
        fs::read(roots.peer_b().join("report (Peer A).pdf")).unwrap(),
        b"peer a"
    );
}

#[test]
fn executor_refuses_a_target_that_appears_after_planning() {
    let roots = TestRoots::new();
    fs::create_dir_all(roots.peer_a()).unwrap();
    fs::create_dir_all(roots.peer_b()).unwrap();
    fs::write(roots.peer_a().join("report.pdf"), b"peer a").unwrap();
    fs::write(roots.peer_b().join("report.pdf"), b"peer b").unwrap();

    let mut planner = PreservedCopyPlanner::new(inventory(
        DestinationNamingPolicy::default(),
        &["report.pdf"],
        &["report.pdf"],
    ));
    let plan = planner
        .plan(&action("report.pdf", ConflictResolution::PreserveBoth))
        .unwrap()
        .unwrap();
    fs::write(roots.peer_b().join("report (Peer A).pdf"), b"newer user data").unwrap();

    let report = PreservedCopyExecutor::new(roots.peer_a(), roots.peer_b())
        .execute(&plan);
    let peer_a_result = report
        .items()
        .iter()
        .find(|item| item.copy().source_peer() == PeerSide::PeerA)
        .expect("Peer A result");
    assert!(matches!(
        peer_a_result.outcome(),
        PreservedCopyExecutionOutcome::Unresolved(_)
    ));
    assert_eq!(
        fs::read(roots.peer_b().join("report (Peer A).pdf")).unwrap(),
        b"newer user data"
    );
}
