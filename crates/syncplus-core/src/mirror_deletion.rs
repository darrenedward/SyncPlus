use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    AnalysisOutcome, InventorySnapshotItem, MirrorEquality, PeerSide, SourceInventorySnapshot,
    SyncBaseline, SyncBaselineItemState,
};

/// The explicit decision made for a baseline-backed Mirror deletion
/// candidate. Only `DeleteCounterpart` may produce a deletion action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorDeletionChoice {
    DeleteCounterpart,
    PreserveRemaining,
    Defer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionDecision {
    relative_path: PathBuf,
    choice: MirrorDeletionChoice,
}

impl MirrorDeletionDecision {
    pub fn new(relative_path: impl Into<PathBuf>, choice: MirrorDeletionChoice) -> Self {
        Self {
            relative_path: relative_path.into(),
            choice,
        }
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn choice(&self) -> MirrorDeletionChoice {
        self.choice
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionEvidence {
    baseline_missing_state: SyncBaselineItemState,
    baseline_remaining_state: SyncBaselineItemState,
    current_remaining_state: SyncBaselineItemState,
}

impl MirrorDeletionEvidence {
    pub fn baseline_missing_state(&self) -> &SyncBaselineItemState {
        &self.baseline_missing_state
    }

    pub fn baseline_remaining_state(&self) -> &SyncBaselineItemState {
        &self.baseline_remaining_state
    }

    pub fn current_remaining_state(&self) -> &SyncBaselineItemState {
        &self.current_remaining_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionCandidate {
    relative_path: PathBuf,
    missing_peer: PeerSide,
    affected_peer: PeerSide,
    evidence: MirrorDeletionEvidence,
}

impl MirrorDeletionCandidate {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn missing_peer(&self) -> PeerSide {
        self.missing_peer
    }

    /// The peer that still contains the item and would be affected by a
    /// reviewed counterpart deletion.
    pub const fn affected_peer(&self) -> PeerSide {
        self.affected_peer
    }

    pub fn evidence(&self) -> &MirrorDeletionEvidence {
        &self.evidence
    }

    pub fn baseline_missing_state(&self) -> &SyncBaselineItemState {
        self.evidence.baseline_missing_state()
    }

    pub fn remaining_state(&self) -> &SyncBaselineItemState {
        self.evidence.current_remaining_state()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorDeletionError {
    MissingDecision { relative_path: PathBuf },
    UnknownCandidate { relative_path: PathBuf },
    DuplicateDecision { relative_path: PathBuf },
    FinalConfirmationRequired,
}

impl fmt::Display for MirrorDeletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDecision { relative_path } => {
                write!(formatter, "Mirror deletion candidate has no decision: {relative_path:?}")
            }
            Self::UnknownCandidate { relative_path } => {
                write!(formatter, "resolution targets an unknown Mirror deletion candidate: {relative_path:?}")
            }
            Self::DuplicateDecision { relative_path } => {
                write!(formatter, "Mirror deletion candidate has more than one decision: {relative_path:?}")
            }
            Self::FinalConfirmationRequired => {
                formatter.write_str("final Execution Confirmation is required before Mirror deletion")
            }
        }
    }
}

impl std::error::Error for MirrorDeletionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionReview {
    candidates: Vec<MirrorDeletionCandidate>,
}

impl MirrorDeletionReview {
    pub fn candidates(&self) -> &[MirrorDeletionCandidate] {
        &self.candidates
    }

    pub fn candidate_for(&self, relative_path: impl AsRef<Path>) -> Option<&MirrorDeletionCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.relative_path() == relative_path.as_ref())
    }

    pub fn resolve<I>(
        &self,
        decisions: I,
    ) -> Result<MirrorDeletionPlan, MirrorDeletionError>
    where
        I: IntoIterator<Item = MirrorDeletionDecision>,
    {
        let expected: BTreeSet<PathBuf> = self
            .candidates
            .iter()
            .map(|candidate| candidate.relative_path.clone())
            .collect();
        let mut seen = BTreeSet::new();
        let mut actions = Vec::new();

        for decision in decisions {
            if !expected.contains(&decision.relative_path) {
                return Err(MirrorDeletionError::UnknownCandidate {
                    relative_path: decision.relative_path,
                });
            }
            if !seen.insert(decision.relative_path.clone()) {
                return Err(MirrorDeletionError::DuplicateDecision {
                    relative_path: decision.relative_path,
                });
            }
            let candidate = self
                .candidate_for(&decision.relative_path)
                .expect("decision path was checked against candidates");
            actions.push(MirrorDeletionAction {
                candidate: candidate.clone(),
                choice: decision.choice,
            });
        }

        if let Some(relative_path) = expected.difference(&seen).next() {
            return Err(MirrorDeletionError::MissingDecision {
                relative_path: relative_path.clone(),
            });
        }

        actions.sort_by(|left, right| {
            left.candidate
                .relative_path
                .cmp(&right.candidate.relative_path)
        });
        Ok(MirrorDeletionPlan { actions })
    }
}

impl SyncBaseline {
    /// Derive deletion candidates only from a two-sided baseline where one
    /// peer is now absent and the remaining peer is still baseline-equivalent.
    /// A missing baseline, a changed counterpart, and a one-sided baseline do
    /// not authorize deletion.
    pub fn deletion_candidates(
        &self,
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
    ) -> Vec<MirrorDeletionCandidate> {
        let current_a = current_items(peer_a);
        let current_b = current_items(peer_b);
        let equality = MirrorEquality::new(self.metadata_requirements());
        let mut candidates = Vec::new();

        for baseline_item in self.items() {
            let Some(baseline_a) = baseline_item.peer_a() else {
                continue;
            };
            let Some(baseline_b) = baseline_item.peer_b() else {
                continue;
            };
            if !baseline_a.equal_state(baseline_b, equality) {
                continue;
            }
            let path = baseline_item.relative_path();
            let item_a = current_a.get(path).copied();
            let item_b = current_b.get(path).copied();

            let candidate = match (item_a, item_b) {
                (None, Some(current_b))
                    if current_b.outcome() == AnalysisOutcome::Included
                        && baseline_b.equal_inventory(current_b, equality) =>
                {
                    Some((
                        PeerSide::PeerA,
                        PeerSide::PeerB,
                        baseline_a.clone(),
                        baseline_b.clone(),
                        state_from_snapshot(current_b),
                    ))
                }
                (Some(current_a), None)
                    if current_a.outcome() == AnalysisOutcome::Included
                        && baseline_a.equal_inventory(current_a, equality) =>
                {
                    Some((
                        PeerSide::PeerB,
                        PeerSide::PeerA,
                        baseline_b.clone(),
                        baseline_a.clone(),
                        state_from_snapshot(current_a),
                    ))
                }
                _ => None,
            };

            if let Some((missing_peer, affected_peer, baseline_missing, baseline_remaining, current_remaining)) = candidate {
                candidates.push(MirrorDeletionCandidate {
                    relative_path: path.to_path_buf(),
                    missing_peer,
                    affected_peer,
                    evidence: MirrorDeletionEvidence {
                        baseline_missing_state: baseline_missing,
                        baseline_remaining_state: baseline_remaining,
                        current_remaining_state: current_remaining,
                    },
                });
            }
        }

        candidates
    }

    pub fn deletion_review(
        &self,
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
    ) -> MirrorDeletionReview {
        MirrorDeletionReview {
            candidates: self.deletion_candidates(peer_a, peer_b),
        }
    }
}

fn current_items(snapshot: &SourceInventorySnapshot) -> BTreeMap<&Path, &InventorySnapshotItem> {
    snapshot
        .items()
        .iter()
        .map(|item| (item.relative_path(), item))
        .collect()
}

fn state_from_snapshot(item: &InventorySnapshotItem) -> SyncBaselineItemState {
    SyncBaselineItemState::from_parts(
        item.item_type(),
        item.size(),
        item.modified_at_unix_nanos(),
        item.is_readonly(),
        item.executable_permissions(),
        item.symlink_target().map(Path::to_path_buf),
        item.content_fingerprint().copied(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorDeletionOutcome {
    Completed,
    FailedPreserved,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionResult {
    relative_path: PathBuf,
    affected_peer: PeerSide,
    outcome: MirrorDeletionOutcome,
    preserves_remaining_copy: bool,
    mirror_invariant_restored: bool,
}

impl MirrorDeletionResult {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn affected_peer(&self) -> PeerSide {
        self.affected_peer
    }

    pub const fn outcome(&self) -> MirrorDeletionOutcome {
        self.outcome
    }

    pub const fn preserves_remaining_copy(&self) -> bool {
        self.preserves_remaining_copy
    }

    pub const fn mirror_invariant_restored(&self) -> bool {
        self.mirror_invariant_restored
    }

    pub const fn requires_review(&self) -> bool {
        !self.mirror_invariant_restored
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionAction {
    candidate: MirrorDeletionCandidate,
    choice: MirrorDeletionChoice,
}

impl MirrorDeletionAction {
    pub fn relative_path(&self) -> &Path {
        self.candidate.relative_path()
    }

    pub const fn choice(&self) -> MirrorDeletionChoice {
        self.choice
    }

    pub const fn affected_peer(&self) -> PeerSide {
        self.candidate.affected_peer()
    }

    pub fn evidence(&self) -> &MirrorDeletionEvidence {
        self.candidate.evidence()
    }

    pub const fn mutates_files(&self) -> bool {
        matches!(self.choice, MirrorDeletionChoice::DeleteCounterpart)
    }

    /// The filesystem removal executor must call this only after a failed
    /// removal attempt. The result is fail-closed and explicitly keeps the
    /// remaining peer copy and Mirror Invariant unresolved.
    pub fn failed_preserving_remaining(&self) -> MirrorDeletionResult {
        MirrorDeletionResult {
            relative_path: self.candidate.relative_path.clone(),
            affected_peer: self.candidate.affected_peer,
            outcome: MirrorDeletionOutcome::FailedPreserved,
            preserves_remaining_copy: true,
            mirror_invariant_restored: false,
        }
    }

    pub fn completed(&self) -> MirrorDeletionResult {
        if !self.mutates_files() {
            return MirrorDeletionResult {
                relative_path: self.candidate.relative_path.clone(),
                affected_peer: self.candidate.affected_peer,
                outcome: MirrorDeletionOutcome::Deferred,
                preserves_remaining_copy: true,
                mirror_invariant_restored: false,
            };
        }
        MirrorDeletionResult {
            relative_path: self.candidate.relative_path.clone(),
            affected_peer: self.candidate.affected_peer,
            outcome: MirrorDeletionOutcome::Completed,
            preserves_remaining_copy: false,
            mirror_invariant_restored: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDeletionPlan {
    actions: Vec<MirrorDeletionAction>,
}

impl MirrorDeletionPlan {
    pub const fn is_finally_confirmed(&self) -> bool {
        false
    }

    pub fn confirm(
        &self,
        final_confirmation: bool,
    ) -> Result<ConfirmedMirrorDeletionPlan, MirrorDeletionError> {
        if !final_confirmation {
            return Err(MirrorDeletionError::FinalConfirmationRequired);
        }
        Ok(ConfirmedMirrorDeletionPlan {
            actions: self.actions.clone(),
        })
    }

    pub const fn action_count(&self) -> usize {
        self.actions.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedMirrorDeletionPlan {
    actions: Vec<MirrorDeletionAction>,
}

impl ConfirmedMirrorDeletionPlan {
    pub const fn is_finally_confirmed(&self) -> bool {
        true
    }

    pub fn actions(&self) -> &[MirrorDeletionAction] {
        &self.actions
    }

    pub fn deletion_actions(&self) -> Vec<&MirrorDeletionAction> {
        self.actions
            .iter()
            .filter(|action| action.mutates_files())
            .collect()
    }

    pub fn requires_review(&self) -> bool {
        self.actions
            .iter()
            .any(|action| !action.mutates_files())
    }
}
