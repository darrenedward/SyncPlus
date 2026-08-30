use std::path::PathBuf;

use crate::{
    ActiveRunState, CoreError, Peer, RunEvent, RunId, RunState, SyncMode, SyncOptions,
    SyncProfile, SyncRun, TerminalOutcome,
};

fn profile() -> SyncProfile {
    SyncProfile::new(
        "Documents",
        Peer::new("Laptop", PathBuf::from("/home/user/documents")),
        Peer::new("Backup", PathBuf::from("/media/backup/documents")),
    )
}

#[test]
fn new_profiles_default_to_non_destructive_one_way_sync() {
    let profile = profile();

    assert_eq!(profile.mode(), SyncMode::OneWay);
    assert_eq!(
        profile.options(),
        SyncOptions {
            safe_delete: false,
            destination_cleanup: false,
            deletion_method: None,
        }
    );
}

#[test]
fn invalid_profiles_cannot_create_active_runs() {
    let invalid = profile().with_options(SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: None,
    });

    assert!(SyncRun::new(RunId::new(8), &invalid).is_err());
}

#[test]
fn a_sync_run_exposes_the_reviewed_lifecycle() {
    let run = SyncRun::new(RunId::new(7), &profile()).expect("valid profile");

    assert_eq!(run.state(), RunState::Active(ActiveRunState::IdleEdit));
    assert_eq!(run.snapshot_id().value(), 7);
    assert_eq!(run.snapshot().profile(), &profile());

    let events = [
        RunEvent::BeginPrecheck,
        RunEvent::PrecheckPassed,
        RunEvent::AnalysisCompleted,
        RunEvent::PlanReviewed,
        RunEvent::ExecutionConfirmed,
        RunEvent::ExecutionCompleted,
        RunEvent::ReconciliationCompleted {
            requires_review: false,
        },
    ];

    let run = events
        .into_iter()
        .try_fold(run, |run, event| run.transition(event))
        .expect("the happy path should be representable");

    assert_eq!(run.state(), RunState::Terminal(TerminalOutcome::Completed));
}

#[test]
fn every_required_terminal_outcome_is_typed() {
    let outcomes = [
        TerminalOutcome::Completed,
        TerminalOutcome::CompletedWithReviewRequired,
        TerminalOutcome::Failed,
        TerminalOutcome::Cancelled,
        TerminalOutcome::Blocked,
        TerminalOutcome::RecoveryReview,
        TerminalOutcome::ReviewCleared,
    ];

    assert_eq!(outcomes.len(), 7);
}

#[test]
fn fail_closed_transitions_leave_the_run_unchanged() {
    let run = SyncRun::new(RunId::new(7), &profile()).expect("valid profile");

    let error = run
        .clone()
        .transition(RunEvent::ExecutionConfirmed)
        .expect_err("confirmation cannot skip precheck, analysis, and review");

    assert!(matches!(error, CoreError::InvalidTransition { .. }));
    assert_eq!(run.state(), RunState::Active(ActiveRunState::IdleEdit));
}

#[test]
fn safety_failures_can_block_any_active_run_without_claiming_completion() {
    let run = SyncRun::new(RunId::new(7), &profile())
        .expect("valid profile")
        .transition(RunEvent::BeginPrecheck)
        .expect("precheck starts from edit");

    let blocked = run
        .transition(RunEvent::Blocked)
        .expect("a safety blocker must be fail-closed");

    assert_eq!(blocked.state(), RunState::Terminal(TerminalOutcome::Blocked));
    assert_ne!(blocked.state(), RunState::Terminal(TerminalOutcome::Completed));
}

#[test]
fn review_required_runs_remain_open_and_can_start_a_resolution_run() {
    let run = SyncRun::new(RunId::new(7), &profile()).expect("valid profile");
    let run = [
        RunEvent::BeginPrecheck,
        RunEvent::PrecheckPassed,
        RunEvent::AnalysisCompleted,
        RunEvent::PlanReviewed,
        RunEvent::ExecutionConfirmed,
        RunEvent::ExecutionCompleted,
        RunEvent::ReconciliationCompleted {
            requires_review: true,
        },
    ]
    .into_iter()
    .try_fold(run, |run, event| run.transition(event))
    .expect("review-required reconciliation should be representable");

    assert_eq!(run.state(), RunState::PendingReview);
    assert_eq!(
        run.outcome(),
        Some(TerminalOutcome::CompletedWithReviewRequired)
    );

    let run = run
        .transition(RunEvent::OpenReview)
        .expect("pending review should open the resolution state");
    assert_eq!(
        run.state(),
        RunState::Active(ActiveRunState::ReviewResolution)
    );

    let resolution = run
        .clone()
        .transition(RunEvent::BeginResolutionRun)
        .expect("resolution should force a fresh analysis");
    assert_eq!(
        resolution.state(),
        RunState::Active(ActiveRunState::Analyzing)
    );

    let cleared = run
        .transition(RunEvent::ReviewCleared)
        .expect("review may be explicitly cleared");
    assert_eq!(
        cleared.state(),
        RunState::Terminal(TerminalOutcome::ReviewCleared)
    );
}

#[test]
fn terminal_runs_reject_all_further_events() {
    let completed = SyncRun::new(RunId::new(7), &profile())
        .expect("valid profile")
        .transition(RunEvent::BeginPrecheck)
        .and_then(|run| run.transition(RunEvent::PrecheckPassed))
        .and_then(|run| run.transition(RunEvent::AnalysisCompleted))
        .and_then(|run| run.transition(RunEvent::PlanReviewed))
        .and_then(|run| run.transition(RunEvent::ExecutionConfirmed))
        .and_then(|run| run.transition(RunEvent::ExecutionCompleted))
        .and_then(|run| {
            run.transition(RunEvent::ReconciliationCompleted {
                requires_review: false,
            })
        })
        .expect("the run should complete");

    let error = completed
        .transition(RunEvent::BeginPrecheck)
        .expect_err("a terminal run cannot restart");

    assert!(matches!(error, CoreError::InvalidTransition { .. }));
}
