use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    ActionReason, AnalysisError, ConflictDecision, ConflictResolution, ConflictResolutionError,
    ConflictResolutionAction, ConflictResolutionPlan, ControlledTransfer, FreshAnalysis,
    DestinationNamingPolicy, OneWayPlan, PreservedCopyError, PreservedCopyExecutionReport,
    PreservedCopyExecutor, PreservedCopyPlanner, PreservedPathInventory, SourceInventorySnapshot,
    SyncBaseline, SyncBaselineItem, SyncBaselineItemStatus, SyncMode, SyncProfile, TransferError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionRunError {
    Analysis(AnalysisError),
    InvalidMode,
    InvalidDecision(ConflictResolutionError),
    BaselineMismatch,
    BaselineChanged { changed_paths: Vec<PathBuf> },
    StaleDecision { changed_paths: Vec<PathBuf> },
    FinalConfirmationRequired,
    UnknownAction { relative_path: PathBuf },
    PreservedCopy(PreservedCopyError),
}

impl fmt::Display for ResolutionRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Analysis(error) => write!(formatter, "Resolution Run analysis failed: {error}"),
            Self::InvalidMode => formatter.write_str("Resolution Runs require Mirror Sync"),
            Self::InvalidDecision(error) => write!(formatter, "Resolution Run decision is invalid: {error}"),
            Self::BaselineMismatch => formatter.write_str("Resolution Run baseline does not match the profile"),
            Self::BaselineChanged { changed_paths } => {
                write!(formatter, "Resolution Run baseline changed for {changed_paths:?}")
            }
            Self::StaleDecision { changed_paths } => {
                write!(formatter, "Resolution Run decision is stale for {changed_paths:?}")
            }
            Self::FinalConfirmationRequired => {
                formatter.write_str("fresh Execution Confirmation is required before a Resolution Run can change data")
            }
            Self::UnknownAction { relative_path } => {
                write!(formatter, "Resolution Run has no action for {relative_path:?}")
            }
            Self::PreservedCopy(error) => {
                write!(formatter, "preserved-copy planning failed: {error}")
            }
        }
    }
}

impl std::error::Error for ResolutionRunError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewedBaseline {
    items: BTreeMap<PathBuf, Option<SyncBaselineItem>>,
    comparisons: BTreeMap<PathBuf, (SyncBaselineItemStatus, SyncBaselineItemStatus)>,
}

impl ReviewedBaseline {
    fn capture(
        baseline: &SyncBaseline,
        paths: &BTreeSet<PathBuf>,
        analysis: &FreshAnalysis,
    ) -> Self {
        let peer_a = SourceInventorySnapshot::from_inventory(analysis.source_inventory());
        let peer_b = SourceInventorySnapshot::from_inventory(analysis.destination_inventory());
        let comparisons = baseline
            .compare(&peer_a, &peer_b)
            .into_iter()
            .filter(|comparison| paths.contains(comparison.relative_path()))
            .map(|comparison| {
                (
                    comparison.relative_path().to_path_buf(),
                    (comparison.peer_a(), comparison.peer_b()),
                )
            })
            .collect();
        let items = paths
            .iter()
            .map(|path| (path.clone(), baseline.item(path).cloned()))
            .collect();
        Self {
            items,
            comparisons,
        }
    }

    fn changed_paths(
        &self,
        baseline: &SyncBaseline,
        analysis: &FreshAnalysis,
    ) -> Vec<PathBuf> {
        let peer_a = SourceInventorySnapshot::from_inventory(analysis.source_inventory());
        let peer_b = SourceInventorySnapshot::from_inventory(analysis.destination_inventory());
        let current_comparisons: BTreeMap<_, _> = baseline
            .compare(&peer_a, &peer_b)
            .into_iter()
            .filter(|comparison| self.items.contains_key(comparison.relative_path()))
            .map(|comparison| {
                (
                    comparison.relative_path().to_path_buf(),
                    (comparison.peer_a(), comparison.peer_b()),
                )
            })
            .collect();
        let mut changed = BTreeSet::new();
        for (path, reviewed_item) in &self.items {
            if baseline.item(path).cloned() != *reviewed_item {
                changed.insert(path.clone());
            }
            if self.comparisons.get(path) != current_comparisons.get(path) {
                changed.insert(path.clone());
            }
        }
        changed.into_iter().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRun {
    profile: SyncProfile,
    reviewed_analysis: FreshAnalysis,
    plan: ConflictResolutionPlan,
    reviewed_baseline: Option<ReviewedBaseline>,
}

impl ResolutionRun {
    /// Start a Resolution Run by performing a fresh analysis before accepting
    /// the deferred or reviewed decisions.
    pub fn start<I>(
        profile: &SyncProfile,
        decisions: I,
        baseline: Option<SyncBaseline>,
    ) -> Result<Self, ResolutionRunError>
    where
        I: IntoIterator<Item = ConflictDecision>,
    {
        let analysis = FreshAnalysis::analyze(profile).map_err(ResolutionRunError::Analysis)?;
        let plan = analysis
            .resolve_conflicts(decisions)
            .map_err(ResolutionRunError::InvalidDecision)?;
        Self::from_analysis(&analysis, plan, baseline)
    }

    pub fn from_analysis(
        analysis: &FreshAnalysis,
        plan: ConflictResolutionPlan,
        baseline: Option<SyncBaseline>,
    ) -> Result<Self, ResolutionRunError> {
        if analysis.profile().mode() != SyncMode::Mirror {
            return Err(ResolutionRunError::InvalidMode);
        }
        let decisions = plan
            .actions()
            .iter()
            .map(|action| ConflictDecision::for_key(action.key().clone(), action.resolution()));
        let validated_plan = analysis
            .conflict_review()
            .resolve(decisions)
            .map_err(ResolutionRunError::InvalidDecision)?;
        let paths: BTreeSet<_> = validated_plan
            .actions()
            .iter()
            .map(|action| action.relative_path().to_path_buf())
            .collect();
        let reviewed_baseline = baseline.map(|baseline| {
            if !baseline_matches_profile(&baseline, analysis.profile())
                || baseline.metadata_requirements() != analysis.specification().options().metadata()
            {
                return Err(ResolutionRunError::BaselineMismatch);
            }
            Ok(ReviewedBaseline::capture(&baseline, &paths, analysis))
        });
        let reviewed_baseline = reviewed_baseline.transpose()?;
        Ok(Self {
            profile: analysis.profile().clone(),
            reviewed_analysis: analysis.clone(),
            plan: validated_plan,
            reviewed_baseline,
        })
    }

    pub fn reviewed_analysis(&self) -> &FreshAnalysis {
        &self.reviewed_analysis
    }

    pub fn plan(&self) -> &ConflictResolutionPlan {
        &self.plan
    }

    pub fn has_data_changing_actions(&self) -> bool {
        self.plan.actions().iter().any(|action| {
            !matches!(action.resolution(), ConflictResolution::Defer)
        })
    }

    pub fn fresh_analysis(
        &self,
        current_profile: &SyncProfile,
        current_baseline: Option<&SyncBaseline>,
    ) -> Result<FreshAnalysis, ResolutionRunError> {
        self.revalidate(current_profile, current_baseline)
            .map(|(analysis, _)| analysis)
    }

    pub fn prepare(
        &self,
        current_profile: &SyncProfile,
        current_baseline: Option<&SyncBaseline>,
        final_confirmation: bool,
    ) -> Result<ConfirmedResolutionRun, ResolutionRunError> {
        let (fresh_analysis, plan) = self.revalidate(current_profile, current_baseline)?;
        if plan.actions().iter().any(|action| {
            !matches!(action.resolution(), ConflictResolution::Defer)
        }) && !final_confirmation
        {
            return Err(ResolutionRunError::FinalConfirmationRequired);
        }
        Ok(ConfirmedResolutionRun {
            fresh_analysis,
            plan,
        })
    }

    fn revalidate(
        &self,
        current_profile: &SyncProfile,
        current_baseline: Option<&SyncBaseline>,
    ) -> Result<(FreshAnalysis, ConflictResolutionPlan), ResolutionRunError> {
        if self.profile != *current_profile {
            return Err(ResolutionRunError::Analysis(AnalysisError::ProfileChanged));
        }
        let fresh_analysis = FreshAnalysis::analyze(current_profile)
            .map_err(ResolutionRunError::Analysis)?;
        let reviewed_paths: BTreeSet<_> = self
            .plan
            .actions()
            .iter()
            .map(|action| action.relative_path().to_path_buf())
            .collect();
        let changed_paths: Vec<_> = self
            .reviewed_analysis
            .revision()
            .changed_paths(&fresh_analysis.revision())
            .into_iter()
            .filter(|path| reviewed_paths.contains(path))
            .collect();
        if !changed_paths.is_empty() {
            return Err(ResolutionRunError::StaleDecision { changed_paths });
        }

        if let Some(reviewed_baseline) = &self.reviewed_baseline {
            let Some(current_baseline) = current_baseline else {
                return Err(ResolutionRunError::BaselineChanged {
                    changed_paths: reviewed_paths.into_iter().collect(),
                });
            };
            if !baseline_matches_profile(current_baseline, current_profile)
                || current_baseline.metadata_requirements()
                    != fresh_analysis.specification().options().metadata()
            {
                return Err(ResolutionRunError::BaselineChanged {
                    changed_paths: reviewed_paths.into_iter().collect(),
                });
            }
            let baseline_changed = reviewed_baseline.changed_paths(current_baseline, &fresh_analysis);
            if !baseline_changed.is_empty() {
                return Err(ResolutionRunError::BaselineChanged {
                    changed_paths: baseline_changed,
                });
            }
        } else if current_baseline.is_some() {
            return Err(ResolutionRunError::BaselineChanged {
                changed_paths: reviewed_paths.into_iter().collect(),
            });
        }

        let decisions = self
            .plan
            .actions()
            .iter()
            .map(|action| ConflictDecision::new(action.relative_path(), action.resolution()));
        let plan = fresh_analysis
            .conflict_review()
            .resolve(decisions)
            .map_err(|_| ResolutionRunError::StaleDecision {
                changed_paths: reviewed_paths.into_iter().collect(),
            })?;
        Ok((fresh_analysis, plan))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedResolutionRun {
    fresh_analysis: FreshAnalysis,
    plan: ConflictResolutionPlan,
}

impl ConfirmedResolutionRun {
    pub fn fresh_analysis(&self) -> &FreshAnalysis {
        &self.fresh_analysis
    }

    pub fn actions(&self) -> &[ConflictResolutionAction] {
        self.plan.actions()
    }

    pub fn execute<E: ResolutionActionExecutor>(
        &self,
        executor: &mut E,
    ) -> ResolutionExecutionReport {
        let actions = self.plan.actions();
        let mut results = Vec::with_capacity(actions.len());
        for (index, action) in actions.iter().enumerate() {
            let relative_path = action.relative_path().to_path_buf();
            let outcome = if action.resolution() == ConflictResolution::Defer {
                executor
                    .defer(action, &self.fresh_analysis)
                    .map_or_else(ResolutionRunOutcome::Unresolved, |_| {
                        ResolutionRunOutcome::Deferred
                    })
            } else {
                executor
                    .execute(action, &self.fresh_analysis)
                    .map_or_else(ResolutionRunOutcome::Unresolved, |_| {
                        ResolutionRunOutcome::Completed
                    })
            };
            let stop_after_action = matches!(
                outcome,
                ResolutionRunOutcome::Unresolved(
                    ActionReason::CancellationRequested | ActionReason::InterruptedBoundary
                )
            );
            results.push(ResolutionRunResult {
                relative_path,
                outcome,
                preserves_item: !matches!(outcome, ResolutionRunOutcome::Completed)
                    || matches!(
                        action.resolution(),
                        ConflictResolution::PreserveBoth
                            | ConflictResolution::RenamePreserveForReview
                    ),
            });
            if stop_after_action {
                for remaining in &actions[index + 1..] {
                    let relative_path = remaining.relative_path().to_path_buf();
                    let outcome = executor
                        .cancel(remaining, &self.fresh_analysis)
                        .map_or_else(ResolutionRunOutcome::Unresolved, |_| {
                            ResolutionRunOutcome::Unresolved(
                                ActionReason::CancellationRequested,
                            )
                        });
                    results.push(ResolutionRunResult {
                        relative_path,
                        outcome,
                        preserves_item: true,
                    });
                }
                break;
            }
        }
        ResolutionExecutionReport { results }
    }
}

/// The mutation boundary for a confirmed Resolution Run. Implementations must
/// perform the selected whole-file action through a verified core boundary and
/// return a typed reason on any uncertainty. The caller receives an unresolved
/// result and the source remains preserved when this returns an error.
pub trait ResolutionActionExecutor {
    fn execute(
        &mut self,
        action: &ConflictResolutionAction,
        analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason>;

    fn defer(
        &mut self,
        _action: &ConflictResolutionAction,
        _analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason> {
        Ok(())
    }

    fn cancel(
        &mut self,
        _action: &ConflictResolutionAction,
        _analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason> {
        Ok(())
    }
}

/// Executes Keep Peer A/B actions through the same controlled rsync and
/// Verified Replacement boundary used by ordinary Sync Runs. Preserve Both and
/// Rename/Preserve use the collision-safe preserved-copy boundary and retain
/// their generated-path reports for durable Run Report integration.
#[derive(Debug)]
pub struct FilesystemResolutionExecutor<F> {
    transfer: ControlledTransfer,
    plan: OneWayPlan,
    should_cancel: F,
    preserved_plans: BTreeMap<PathBuf, crate::PreservedCopyPlan>,
    preserved_reports: BTreeMap<PathBuf, PreservedCopyExecutionReport>,
}

impl<F> FilesystemResolutionExecutor<F>
where
    F: Fn() -> bool,
{
    pub fn new(
        confirmed: &ConfirmedResolutionRun,
        transfer: ControlledTransfer,
        should_cancel: F,
    ) -> Result<Self, ResolutionRunError> {
        Self::new_with_naming_policies(
            confirmed,
            transfer,
            should_cancel,
            DestinationNamingPolicy::default(),
            DestinationNamingPolicy::default(),
        )
    }

    pub fn new_with_naming_policies(
        confirmed: &ConfirmedResolutionRun,
        transfer: ControlledTransfer,
        should_cancel: F,
        peer_a_policy: DestinationNamingPolicy,
        peer_b_policy: DestinationNamingPolicy,
    ) -> Result<Self, ResolutionRunError> {
        let plan = confirmed
            .fresh_analysis
            .resolution_transfer_plan(confirmed.actions())
            .map_err(ResolutionRunError::Analysis)?;
        let occupied_a = confirmed
            .fresh_analysis
            .source_inventory()
            .items()
            .iter()
            .map(|item| item.relative_path().to_path_buf())
            .collect::<Vec<_>>();
        let occupied_b = confirmed
            .fresh_analysis
            .destination_inventory()
            .items()
            .iter()
            .map(|item| item.relative_path().to_path_buf())
            .collect::<Vec<_>>();
        let mut planner = PreservedCopyPlanner::new(PreservedPathInventory::new_with_policies(
            peer_a_policy,
            peer_b_policy,
            occupied_a,
            occupied_b,
        ));
        let mut preserved_plans = BTreeMap::new();
        for action in confirmed.actions().iter().filter(|action| {
            matches!(
                action.resolution(),
                ConflictResolution::PreserveBoth | ConflictResolution::RenamePreserveForReview
            )
        }) {
            if let Some(plan) = planner
                .plan(action)
                .map_err(ResolutionRunError::PreservedCopy)?
            {
                preserved_plans.insert(action.relative_path().to_path_buf(), plan);
            }
        }
        Ok(Self {
            transfer,
            plan,
            should_cancel,
            preserved_plans,
            preserved_reports: BTreeMap::new(),
        })
    }

    pub fn preserved_copy_report(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Option<&PreservedCopyExecutionReport> {
        self.preserved_reports.get(relative_path.as_ref())
    }

    pub(crate) fn preserved_copy_plan(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Option<&crate::PreservedCopyPlan> {
        self.preserved_plans.get(relative_path.as_ref())
    }
}

impl<F> ResolutionActionExecutor for FilesystemResolutionExecutor<F>
where
    F: Fn() -> bool,
{
    fn execute(
        &mut self,
        action: &ConflictResolutionAction,
        analysis: &FreshAnalysis,
    ) -> Result<(), ActionReason> {
        if matches!(
            action.resolution(),
            ConflictResolution::PreserveBoth | ConflictResolution::RenamePreserveForReview
        ) {
            let Some(plan) = self.preserved_plans.get(action.relative_path()) else {
                return Err(ActionReason::TransferFailed);
            };
            let report = PreservedCopyExecutor::new(
                analysis.profile().peer_a().root().to_path_buf(),
                analysis.profile().peer_b().root().to_path_buf(),
            )
            .execute(plan);
            let unresolved = report.has_unresolved();
            self.preserved_reports
                .insert(action.relative_path().to_path_buf(), report);
            if unresolved {
                return Err(ActionReason::VerificationMismatch);
            }
            return Ok(());
        }
        if action.operation() != crate::ResolutionOperation::CopyWholeFile {
            return Err(ActionReason::DeferredForReview);
        }
        let plan_action = self
            .plan
            .action_for(action.relative_path())
            .ok_or(ActionReason::TransferFailed)?;
        self.transfer
            .execute(&self.plan, plan_action, &self.should_cancel)
            .map(|_| ())
            .map_err(transfer_reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionExecutionReport {
    results: Vec<ResolutionRunResult>,
}

impl ResolutionExecutionReport {
    pub fn results(&self) -> &[ResolutionRunResult] {
        &self.results
    }

    pub fn result_for(&self, relative_path: impl AsRef<Path>) -> Option<&ResolutionRunResult> {
        self.results
            .iter()
            .find(|result| result.relative_path() == relative_path.as_ref())
    }

    pub fn requires_review(&self) -> bool {
        self.results.iter().any(ResolutionRunResult::requires_review)
    }

    pub fn is_complete(&self) -> bool {
        !self.results.is_empty()
            && self
                .results
                .iter()
                .all(|result| !result.requires_review())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionRunOutcome {
    Completed,
    Deferred,
    Unresolved(ActionReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRunResult {
    relative_path: PathBuf,
    outcome: ResolutionRunOutcome,
    preserves_item: bool,
}

impl ResolutionRunResult {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn outcome(&self) -> ResolutionRunOutcome {
        self.outcome
    }

    pub const fn preserves_item(&self) -> bool {
        self.preserves_item
    }

    pub const fn requires_review(&self) -> bool {
        self.preserves_item || !matches!(self.outcome, ResolutionRunOutcome::Completed)
    }
}

fn transfer_reason(error: TransferError) -> ActionReason {
    match error {
        TransferError::Replacement(crate::ReplacementError::Cancelled) => {
            ActionReason::CancellationRequested
        }
        TransferError::Replacement(crate::ReplacementError::Verification(
            crate::VerificationError::SourceChanged,
        )) => ActionReason::SourceChanged,
        TransferError::Replacement(crate::ReplacementError::Verification(_))
        | TransferError::Replacement(crate::ReplacementError::MetadataMismatch) => {
            ActionReason::VerificationMismatch
        }
        TransferError::Process(crate::ProcessError::OrphanedProcessGroup)
        | TransferError::Process(crate::ProcessError::ProcessGroup(_))
        | TransferError::Replacement(crate::ReplacementError::Process(
            crate::ProcessError::OrphanedProcessGroup | crate::ProcessError::ProcessGroup(_),
        ))
        | TransferError::Replacement(crate::ReplacementError::RecoveryUncertain(_)) => {
            ActionReason::InterruptedBoundary
        }
        TransferError::InvalidProcessSpecification(_)
        | TransferError::InvalidPlan(_)
        | TransferError::Process(_)
        | TransferError::Replacement(_)
        | TransferError::MalformedOutput => ActionReason::TransferFailed,
    }
}

fn baseline_matches_profile(baseline: &SyncBaseline, profile: &SyncProfile) -> bool {
    baseline.profile_name() == profile.name()
        && baseline.peer_a_name() == profile.peer_a().name()
        && baseline.peer_a_root() == profile.peer_a().root()
        && baseline.peer_b_name() == profile.peer_b().name()
        && baseline.peer_b_root() == profile.peer_b().root()
}
