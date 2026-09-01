use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use crate::{ConflictEntry, ConflictEntryKey, ConflictReview, PeerSide};

/// The only decisions a Mirror conflict may receive.
///
/// These choices are deliberately whole-file decisions. There is no content
/// merge variant, and the two preservation choices do not remove either
/// already-existing peer version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictResolution {
    KeepPeerA,
    KeepPeerB,
    PreserveBoth,
    RenamePreserveForReview,
    Defer,
}

impl ConflictResolution {
    pub const fn all() -> &'static [Self; 5] {
        &[
            Self::KeepPeerA,
            Self::KeepPeerB,
            Self::PreserveBoth,
            Self::RenamePreserveForReview,
            Self::Defer,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictDecision {
    entry_key: ConflictEntryKey,
    resolution: ConflictResolution,
}

impl ConflictDecision {
    pub fn new(relative_path: impl Into<PathBuf>, resolution: ConflictResolution) -> Self {
        Self {
            entry_key: ConflictEntryKey::same_path(relative_path),
            resolution,
        }
    }

    pub fn for_entry(entry: &ConflictEntry, resolution: ConflictResolution) -> Self {
        Self::for_key(entry.key(), resolution)
    }

    pub fn for_key(entry_key: ConflictEntryKey, resolution: ConflictResolution) -> Self {
        Self {
            entry_key,
            resolution,
        }
    }

    pub fn key(&self) -> &ConflictEntryKey {
        &self.entry_key
    }

    pub fn relative_path(&self) -> &Path {
        self.entry_key.relative_path()
    }

    pub const fn resolution(&self) -> ConflictResolution {
        self.resolution
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolutionError {
    MissingDecision { relative_path: PathBuf },
    UnknownConflict { relative_path: PathBuf },
    UnavailableResolution {
        relative_path: PathBuf,
        resolution: ConflictResolution,
    },
    DuplicateDecision { relative_path: PathBuf },
    FinalConfirmationRequired,
}

impl fmt::Display for ConflictResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDecision { relative_path } => {
                write!(formatter, "Mirror conflict has no resolution: {relative_path:?}")
            }
            Self::UnknownConflict { relative_path } => {
                write!(formatter, "resolution targets an unknown Mirror conflict: {relative_path:?}")
            }
            Self::UnavailableResolution {
                relative_path,
                resolution,
            } => write!(
                formatter,
                "resolution {resolution:?} is not available for Mirror conflict {relative_path:?}"
            ),
            Self::DuplicateDecision { relative_path } => {
                write!(formatter, "Mirror conflict has more than one resolution: {relative_path:?}")
            }
            Self::FinalConfirmationRequired => {
                formatter.write_str("final Execution Confirmation is required before applying resolutions")
            }
        }
    }
}

impl std::error::Error for ConflictResolutionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionOperation {
    /// Copy one complete, verified peer item over the other peer's same path.
    CopyWholeFile,
    /// Keep both existing peer versions without mutating either one.
    PreserveBoth,
    /// Defer path generation and preserve both versions for later review.
    RenamePreserveForReview,
    /// Make no filesystem change and keep this conflict open.
    Defer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictResolutionAction {
    entry_key: ConflictEntryKey,
    relative_path: PathBuf,
    resolution: ConflictResolution,
    operation: ResolutionOperation,
    source_side: Option<PeerSide>,
    target_side: Option<PeerSide>,
}

impl ConflictResolutionAction {
    pub fn new(relative_path: impl Into<PathBuf>, resolution: ConflictResolution) -> Self {
        Self::from_decision(ConflictDecision::new(relative_path, resolution))
    }

    fn from_decision(decision: ConflictDecision) -> Self {
        let relative_path = decision.relative_path().to_path_buf();
        let (operation, source_side, target_side) = match decision.resolution {
            ConflictResolution::KeepPeerA => (
                ResolutionOperation::CopyWholeFile,
                Some(PeerSide::PeerA),
                Some(PeerSide::PeerB),
            ),
            ConflictResolution::KeepPeerB => (
                ResolutionOperation::CopyWholeFile,
                Some(PeerSide::PeerB),
                Some(PeerSide::PeerA),
            ),
            ConflictResolution::PreserveBoth => {
                (ResolutionOperation::PreserveBoth, None, None)
            }
            ConflictResolution::RenamePreserveForReview => {
                (ResolutionOperation::RenamePreserveForReview, None, None)
            }
            ConflictResolution::Defer => (ResolutionOperation::Defer, None, None),
        };
        Self {
            entry_key: decision.entry_key,
            relative_path,
            resolution: decision.resolution,
            operation,
            source_side,
            target_side,
        }
    }

    pub fn key(&self) -> &ConflictEntryKey {
        &self.entry_key
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn resolution(&self) -> ConflictResolution {
        self.resolution
    }

    pub const fn operation(&self) -> ResolutionOperation {
        self.operation
    }

    pub const fn source_side(&self) -> Option<PeerSide> {
        self.source_side
    }

    pub const fn target_side(&self) -> Option<PeerSide> {
        self.target_side
    }

    pub const fn mutates_files(&self) -> bool {
        matches!(self.operation, ResolutionOperation::CopyWholeFile)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictResolutionPlan {
    actions: Vec<ConflictResolutionAction>,
}

impl ConflictResolutionPlan {
    /// A plan is not executable. Calling `confirm(true)` is the explicit
    /// final confirmation boundary that produces the executable view.
    pub const fn is_finally_confirmed(&self) -> bool {
        false
    }

    pub fn confirm(
        &self,
        final_confirmation: bool,
    ) -> Result<ConfirmedConflictResolutionPlan, ConflictResolutionError> {
        if !final_confirmation {
            return Err(ConflictResolutionError::FinalConfirmationRequired);
        }
        Ok(ConfirmedConflictResolutionPlan {
            actions: self.actions.clone(),
        })
    }

    pub const fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn actions(&self) -> &[ConflictResolutionAction] {
        &self.actions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedConflictResolutionPlan {
    actions: Vec<ConflictResolutionAction>,
}

impl ConfirmedConflictResolutionPlan {
    pub const fn is_finally_confirmed(&self) -> bool {
        true
    }

    pub fn actions(&self) -> &[ConflictResolutionAction] {
        &self.actions
    }

    /// Preserve-for-review and deferred decisions intentionally keep the run
    /// open. A successful Keep decision is the only resolution that can clear
    /// the conflict without a later review step.
    pub fn requires_review(&self) -> bool {
        self.actions.iter().any(|action| {
            matches!(
                action.resolution(),
                ConflictResolution::PreserveBoth
                    | ConflictResolution::RenamePreserveForReview
                    | ConflictResolution::Defer
            )
        })
    }
}

impl ConflictReview {
    /// Validate a complete, unique per-path decision set and produce a plan
    /// that cannot expose executable actions until final confirmation.
    pub fn resolve<I>(
        &self,
        decisions: I,
    ) -> Result<ConflictResolutionPlan, ConflictResolutionError>
    where
        I: IntoIterator<Item = ConflictDecision>,
    {
        let expected: BTreeSet<ConflictEntryKey> = self
            .entries()
            .iter()
            .filter(|entry| !entry.available_resolutions().is_empty())
            .map(ConflictEntry::key)
            .collect();
        let mut seen: BTreeSet<ConflictEntryKey> = BTreeSet::new();
        let mut actions = Vec::new();

        for decision in decisions {
            let Some(entry) = self
                .entries()
                .iter()
                .find(|entry| entry.key() == *decision.key())
            else {
                return Err(ConflictResolutionError::UnknownConflict {
                    relative_path: decision.relative_path().to_path_buf(),
                });
            };
            if !entry.available_resolutions().contains(&decision.resolution) {
                return Err(ConflictResolutionError::UnavailableResolution {
                    relative_path: decision.relative_path().to_path_buf(),
                    resolution: decision.resolution,
                });
            }
            if !seen.insert(decision.key().clone()) {
                return Err(ConflictResolutionError::DuplicateDecision {
                    relative_path: decision.relative_path().to_path_buf(),
                });
            }
            actions.push(ConflictResolutionAction::from_decision(decision));
        }

        if let Some(relative_path) = expected.difference(&seen).next() {
            return Err(ConflictResolutionError::MissingDecision {
                relative_path: relative_path.relative_path().to_path_buf(),
            });
        }

        actions.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(ConflictResolutionPlan { actions })
    }
}
