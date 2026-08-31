use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

use crate::{
    CompletionReconciliation, DeletionMethod, FreshAnalysis, LocalPrecheckProbe, OneWaySource,
    Peer, RecoveryMethod, RunEvidenceStore, RunId, RunReportStatus, RunWorkflow, SourceDrainStatus,
    SyncOptions, SyncProfile,
};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture { root: PathBuf, source: PathBuf, destination: PathBuf, recovery: PathBuf }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("syncplus-release-gate-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        let source = root.join("source"); let destination = root.join("destination"); let recovery = root.join("recovery");
        fs::create_dir_all(&source).unwrap(); fs::create_dir_all(&destination).unwrap(); fs::create_dir_all(&recovery).unwrap();
        Self { root, source, destination, recovery }
    }
    fn profile(&self) -> SyncProfile {
        SyncProfile::new("release gate", Peer::new("source", self.source.clone()), Peer::new("destination", self.destination.clone()))
            .with_source(OneWaySource::PeerA)
            .with_options(SyncOptions { safe_delete: true, deletion_method: Some(DeletionMethod::Trash), ..SyncOptions::default() })
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

#[test]
fn local_safe_delete_runs_through_real_rsync_and_recovery() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("report.txt"), b"release-gate").unwrap();
    let profile = fixture.profile();
    let probe = LocalPrecheckProbe::default();
    assert!(fixture.source.is_dir());
    assert!(fixture.destination.is_dir());
    assert!(crate::PrecheckProbe::peer_available(&probe, &fixture.source, false).unwrap());
    let mut store = RunEvidenceStore::open_in_memory().unwrap();
    let report = RunWorkflow::new(RecoveryMethod::trash(fixture.recovery.clone()))
        .execute(RunId::new(1), &profile, &probe, |_| true, &mut store, || false)
        .expect("real local Safe Delete should complete");
    assert_eq!(report.status(), RunReportStatus::Completed, "report: {report:?}");
    assert!(!fixture.source.join("report.txt").exists());
    assert_eq!(fs::read(fixture.destination.join("report.txt")).unwrap(), b"release-gate");
    assert!(fixture.recovery.join("report.txt").exists());
}

#[test]
fn excluded_source_items_keep_source_not_empty_in_real_reconciliation() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("keep.tmp"), b"excluded").unwrap();
    let profile = fixture.profile().with_exclusions(["*.tmp".to_owned()]);
    let analysis = FreshAnalysis::analyze(&profile).unwrap();
    let inventory = crate::SourceInventorySnapshot::from_inventory(analysis.source_inventory());
    let reconciliation = CompletionReconciliation::reconcile(&profile, &inventory, &analysis, &[]);
    assert_eq!(reconciliation.source_drain_status(), SourceDrainStatus::NotEmpty);
    let finding = reconciliation.findings().iter().find(|finding| finding.relative_path() == PathBuf::from("keep.tmp")).expect("excluded item should be reported");
    assert!(matches!(finding.reason(), crate::ReconciliationReason::Excluded));
}
