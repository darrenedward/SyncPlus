use crate::{
    OneWayPlan, PlanError, ProcessError, ProcessSpecError, ProcessSupervisor, ReplacementError,
    VerifiedReplacement,
};
use crate::replacement::perform_verified_replacement_with_cancel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    InvalidProcessSpecification(ProcessSpecError),
    InvalidPlan(PlanError),
    Process(ProcessError),
    Replacement(ReplacementError),
    MalformedOutput,
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProcessSpecification(error) => {
                write!(formatter, "invalid transfer specification: {error}")
            }
            Self::InvalidPlan(error) => write!(formatter, "invalid transfer plan: {error}"),
            Self::Process(error) => error.fmt(formatter),
            Self::Replacement(error) => error.fmt(formatter),
            Self::MalformedOutput => formatter.write_str(
                "transfer output was malformed; no replacement or source removal was authorized",
            ),
        }
    }
}

impl std::error::Error for TransferError {}

impl From<ProcessSpecError> for TransferError {
    fn from(error: ProcessSpecError) -> Self {
        Self::InvalidProcessSpecification(error)
    }
}

impl From<PlanError> for TransferError {
    fn from(error: PlanError) -> Self {
        Self::InvalidPlan(error)
    }
}

impl From<ProcessError> for TransferError {
    fn from(error: ProcessError) -> Self {
        Self::Process(error)
    }
}

impl From<ReplacementError> for TransferError {
    fn from(error: ReplacementError) -> Self {
        Self::Replacement(error)
    }
}

/// Composes the controlled process runner with Verified Replacement. It
/// never removes the source; Safe Delete's per-item proof boundary owns that
/// separate destructive decision.
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlledTransfer {
    supervisor: ProcessSupervisor,
}

impl ControlledTransfer {
    pub fn new(supervisor: ProcessSupervisor) -> Self {
        Self { supervisor }
    }

    pub fn execute<F>(
        &self,
        plan: &OneWayPlan,
        action: &crate::PlanAction,
        should_cancel: F,
    ) -> Result<VerifiedReplacement, TransferError>
    where
        F: Fn() -> bool,
    {
        plan.validate()?;
        let action = plan
            .actions()
            .iter()
            .find(|candidate| *candidate == action)
            .ok_or_else(|| TransferError::InvalidPlan(PlanError::ActionNotInPlan {
                path: action.relative_path().to_path_buf(),
            }))?;
        let specification = plan.specification();
        let (source, destination) = specification.transfer_paths(action)?;
        let supervisor = self.supervisor;
        let replacement = perform_verified_replacement_with_cancel(
            &source,
            &destination,
            &should_cancel,
            |temporary| {
                let invocation = specification
                    .item_invocation(&source, temporary)
                    .map_err(|error| ReplacementError::Transfer(error.to_string()))?;
                let outcome = supervisor
                    .run(&invocation, &should_cancel)
                    .map_err(|error| ReplacementError::Transfer(error.to_string()))?;
                if outcome.cancelled() {
                    return Err(ReplacementError::Cancelled);
                }
                if !outcome.succeeded() {
                    return Err(ReplacementError::Transfer(format!(
                        "controlled process exited with code {:?} and signal {:?}",
                        outcome.exit_code(),
                        outcome.signal()
                    )));
                }
                if outcome.stderr_had_output() {
                    return Err(ReplacementError::Transfer(
                        "controlled process emitted stderr; transfer evidence is unresolved"
                            .to_owned(),
                    ));
                }
                if !outcome.output().is_well_formed() {
                    return Err(ReplacementError::Transfer(
                        TransferError::MalformedOutput.to_string(),
                    ));
                }
                Ok(())
            },
        )?;
        Ok(replacement)
    }
}
