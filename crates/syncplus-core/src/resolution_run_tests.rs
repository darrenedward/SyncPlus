use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ActionReason, ConflictDecision, ConflictResolution, ControlledTransfer, FreshAnalysis,
    FilesystemResolutionExecutor, MetadataRequirements, Peer, ResolutionActionExecutor,
    ResolutionRun, ResolutionRunError, ResolutionRunOutcome, SourceInventorySnapshot, SyncBaseline,
    SyncMode, SyncProfile,
};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("syncplus-resolution-run-test-{unique}"));
        fs::create_dir_all(root.join("peer-a")).unwrap();
        fs::create_dir_all(root.join("peer-b")).unwrap();
        fs::write(root.join("peer-a/same.txt"), b"peer a").unwrap();
        fs::write(root.join("peer-b/same.txt"), b"peer b").unwrap();
        Self { root }
    }

    fn profile(&self) -> SyncProfile {
        SyncProfile::new(
            "resolution-test",
            Peer::new("Peer A", self.root.join("peer-a")),
            Peer::new("Peer B", self.root.join("peer-b")),
        )
        .with_mode(SyncMode::Mirror)
    }

    fn baseline(&self, analysis: &FreshAnalysis) -> SyncBaseline {
        SyncBaseline::from_inventories(
            "resolution-test",
            &SourceInventorySnapshot::from_inventory(analysis.source_inventory()),
            &SourceInventorySnapshot::from_inventory(analysis.destination_inventory()),
            MetadataRequirements::default(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn decision(resolution: ConflictResolution) -> ConflictDecision {
    ConflictDecision::new("same.txt", resolution)
}

#[test]
fn deferred_decision_starts_from_fresh_analysis() {
    let fixture = Fixture::new();
    let profile = fixture.profile();

    let run = ResolutionRun::start(&profile, [decision(ConflictResolution::Defer)], None)
        .expect("deferred decision should start a Resolution Run");

    assert_eq!(run.reviewed_analysis().conflict_review().entries().len(), 1);
    let fresh = run
        .fresh_analysis(&profile, None)
        .expect("unchanged peers should re-analyze");
    assert_eq!(fresh.conflict_review().entries().len(), 1);
}

#[test]
fn changing_either_peer_after_review_refuses_the_stale_decision() {
    for changed_peer in ["peer-a", "peer-b"] {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let analysis = FreshAnalysis::analyze(&profile).unwrap();
        let baseline = fixture.baseline(&analysis);
        let run = ResolutionRun::from_analysis(
            &analysis,
            analysis
                .resolve_conflicts([decision(ConflictResolution::KeepPeerA)])
                .unwrap(),
            Some(baseline.clone()),
        )
        .unwrap();

        fs::write(fixture.root.join(changed_peer).join("same.txt"), b"changed").unwrap();
        let error = run
            .prepare(&profile, Some(&baseline), true)
            .expect_err("a changed peer must invalidate the old decision");

        assert!(matches!(error, ResolutionRunError::StaleDecision { .. }));
    }
}

#[test]
fn changed_baseline_state_is_refused_even_when_peers_are_unchanged() {
    let fixture = Fixture::new();
    let profile = fixture.profile();
    let analysis = FreshAnalysis::analyze(&profile).unwrap();
    let reviewed_baseline = fixture.baseline(&analysis);
    let run = ResolutionRun::from_analysis(
        &analysis,
        analysis
            .resolve_conflicts([decision(ConflictResolution::Defer)])
            .unwrap(),
        Some(reviewed_baseline.clone()),
    )
    .unwrap();
    let changed_baseline = SyncBaseline::from_inventories(
        profile.name(),
        &SourceInventorySnapshot::from_inventory(analysis.source_inventory()),
        &SourceInventorySnapshot::from_inventory(analysis.destination_inventory()),
        MetadataRequirements::new(true, false, false, false),
    );

    let error = run
        .prepare(&profile, Some(&changed_baseline), true)
        .expect_err("a changed baseline must invalidate the old decision");
    assert!(matches!(error, ResolutionRunError::BaselineChanged { .. }));
}

#[test]
fn data_changing_resolution_requires_fresh_confirmation() {
    let fixture = Fixture::new();
    let profile = fixture.profile();
    let run = ResolutionRun::start(&profile, [decision(ConflictResolution::KeepPeerA)], None)
        .unwrap();

    let error = run
        .prepare(&profile, None, false)
        .expect_err("data-changing resolutions need final confirmation");
    assert_eq!(error, ResolutionRunError::FinalConfirmationRequired);
    let confirmed = run
        .prepare(&profile, None, true)
        .expect("fresh confirmation should prepare the run");
    assert_eq!(confirmed.actions().len(), 1);
}

#[test]
fn failed_resolution_preserves_the_item_as_unresolved() {
    let fixture = Fixture::new();
    let profile = fixture.profile();
    let run = ResolutionRun::start(&profile, [decision(ConflictResolution::KeepPeerA)], None)
        .unwrap();
    let confirmed = run.prepare(&profile, None, true).unwrap();

    struct FailingExecutor;
    impl ResolutionActionExecutor for FailingExecutor {
        fn execute(
            &mut self,
            _action: &crate::ConflictResolutionAction,
            _analysis: &FreshAnalysis,
        ) -> Result<(), ActionReason> {
            Err(ActionReason::VerificationMismatch)
        }
    }

    let report = confirmed.execute(&mut FailingExecutor);
    let result = report.result_for("same.txt").unwrap();
    assert_eq!(result.relative_path(), PathBuf::from("same.txt"));
    assert_eq!(
        result.outcome(),
        ResolutionRunOutcome::Unresolved(ActionReason::VerificationMismatch)
    );
    assert!(result.preserves_item());
    assert!(result.requires_review());
}

#[test]
fn confirmed_keep_resolution_uses_verified_filesystem_transfer() {
    let fixture = Fixture::new();
    let profile = fixture.profile();
    let run = ResolutionRun::start(&profile, [decision(ConflictResolution::KeepPeerA)], None)
        .unwrap();
    let confirmed = run.prepare(&profile, None, true).unwrap();
    let mut executor = FilesystemResolutionExecutor::new(
        &confirmed,
        ControlledTransfer::default(),
        || false,
    )
    .unwrap();

    let report = confirmed.execute(&mut executor);

    assert!(report.is_complete(), "report: {report:?}");
    assert_eq!(
        fs::read(fixture.root.join("peer-b/same.txt")).unwrap(),
        b"peer a"
    );
    assert_eq!(
        fs::read(fixture.root.join("peer-a/same.txt")).unwrap(),
        b"peer a"
    );
}
