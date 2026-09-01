use crate::{
    OneWayPlan, PlanAction, PlanActionKind, PlanError, ProcessError, ProcessSpecError,
    ProcessSupervisor, ReplacementError, VerifiedReplacement,
};
use crate::replacement::perform_verified_replacement_with_cancel_and_metadata_and_partial;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    InvalidProcessSpecification(ProcessSpecError),
    InvalidPlan(PlanError),
    Process(ProcessError),
    Replacement(ReplacementError),
    MalformedOutput,
}

impl TransferError {
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Process(ProcessError::Io(_)) => true,
            Self::Replacement(ReplacementError::Process(ProcessError::Io(_))) => true,
            Self::Replacement(ReplacementError::ProcessExit { signal, exit_code }) => {
                signal.is_none() && matches!(exit_code, Some(10 | 11 | 30 | 35))
            }
            Self::Process(_) => false,
            Self::InvalidProcessSpecification(_)
            | Self::InvalidPlan(_)
            | Self::Replacement(_)
            | Self::MalformedOutput => false,
        }
    }

    pub fn requires_recovery_review(&self) -> bool {
        matches!(
            self,
            Self::Process(ProcessError::OrphanedProcessGroup)
                | Self::Process(ProcessError::ProcessGroup(_))
                | Self::Replacement(ReplacementError::Process(
                    ProcessError::OrphanedProcessGroup | ProcessError::ProcessGroup(_),
                ))
                | Self::Replacement(ReplacementError::ProcessExit {
                    signal: Some(_),
                    ..
                })
                | Self::Replacement(ReplacementError::RecoveryUncertain(_))
        )
    }
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

    pub(crate) const fn supervisor(&self) -> &ProcessSupervisor {
        &self.supervisor
    }

    pub fn execute<F>(
        &self,
        plan: &OneWayPlan,
        action: &PlanAction,
        should_cancel: F,
    ) -> Result<VerifiedReplacement, TransferError>
    where
        F: Fn() -> bool,
    {
        self.execute_with_progress_and_policy(
            plan,
            action,
            should_cancel,
            |_| {},
        )
    }

    pub(crate) fn execute_with_progress_and_policy<F, P>(
        &self,
        plan: &OneWayPlan,
        action: &PlanAction,
        should_cancel: F,
        mut progress: P,
    ) -> Result<VerifiedReplacement, TransferError>
    where
        F: Fn() -> bool,
        P: FnMut(u64),
    {
        plan.validate()?;
        let action = plan
            .actions()
            .iter()
            .find(|candidate| *candidate == action)
            .ok_or_else(|| TransferError::InvalidPlan(PlanError::ActionNotInPlan {
                path: action.relative_path().to_path_buf(),
            }))?;
        if !matches!(
            action.kind(),
            PlanActionKind::CopyToDestination | PlanActionKind::OverwriteDestination
        ) {
            return Err(TransferError::InvalidPlan(PlanError::ActionNotAllowed {
                kind: action.kind(),
            }));
        }
        self.execute_paths(
            plan,
            action,
            plan.specification().transfer_paths(action)?,
            should_cancel,
            &mut progress,
        )
    }

    pub(crate) fn execute_source_verification<F, P>(
        &self,
        plan: &OneWayPlan,
        action: &PlanAction,
        should_cancel: F,
        progress: P,
    ) -> Result<VerifiedReplacement, TransferError>
    where
        F: Fn() -> bool,
        P: FnMut(u64),
    {
        plan.validate()?;
        let action = plan
            .actions()
            .iter()
            .find(|candidate| *candidate == action)
            .ok_or_else(|| TransferError::InvalidPlan(PlanError::ActionNotInPlan {
                path: action.relative_path().to_path_buf(),
            }))?;
        if action.kind() != PlanActionKind::RemoveSourceAfterVerification {
            return Err(TransferError::InvalidPlan(PlanError::ActionNotAllowed {
                kind: action.kind(),
            }));
        }
        self.execute_paths(
            plan,
            action,
            (
                plan.specification().source_path(action)?,
                plan.specification().destination_path(action)?,
            ),
            should_cancel,
            progress,
        )
    }

    fn execute_paths<F, P>(
        &self,
        plan: &OneWayPlan,
        _action: &PlanAction,
        (source, destination): (std::path::PathBuf, std::path::PathBuf),
        should_cancel: F,
        mut progress: P,
    ) -> Result<VerifiedReplacement, TransferError>
    where
        F: Fn() -> bool,
        P: FnMut(u64),
    {
        let specification = plan.specification();
        let supervisor = self.supervisor;
        let options = specification.options();
        let replacement = perform_verified_replacement_with_cancel_and_metadata_and_partial(
            &source,
            &destination,
            options.metadata(),
            options.partial_transfer_policy(),
            &should_cancel,
            |temporary| {
                let source_metadata = fs::symlink_metadata(&source)
                    .map_err(|error| ReplacementError::Io(error.to_string()))?;
                if source_metadata.file_type().is_dir() {
                    fs::create_dir(temporary)
                        .map_err(|error| ReplacementError::Io(error.to_string()))?;
                    if let Ok(destination_metadata) = fs::symlink_metadata(&destination) {
                        if destination_metadata.file_type().is_dir() {
                            preserve_existing_directory(
                                &destination,
                                temporary,
                            )?;
                        }
                    }
                    #[cfg(unix)]
                    if options.metadata().executable_permissions() {
                        use std::os::unix::fs::PermissionsExt;

                        fs::set_permissions(
                            temporary,
                            fs::Permissions::from_mode(source_metadata.permissions().mode()),
                        )
                        .map_err(|error| ReplacementError::Io(error.to_string()))?;
                    }
                    return Ok(());
                }
                let invocation = specification
                    .item_invocation(&source, temporary)
                    .map_err(|error| ReplacementError::Transfer(error.to_string()))?;
                let outcome = supervisor
                    .run(&invocation, &should_cancel)
                    .map_err(ReplacementError::Process)?;
                if outcome.cancelled() {
                    return Err(ReplacementError::Cancelled);
                }
                if !outcome.succeeded() {
                    return Err(ReplacementError::ProcessExit {
                        exit_code: outcome.exit_code(),
                        signal: outcome.signal(),
                    });
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
                if let Some(last) = outcome.output().progress().last() {
                    progress(last.completed_bytes());
                }
                Ok(())
            },
        )?;
        Ok(replacement)
    }
}

/// Keep destination entries that are outside the source's approved scope when
/// a directory entry itself needs replacement. The old directory is moved to
/// its recovery sibling only after this staging succeeds, so an unsupported or
/// unverifiable destination entry leaves the visible destination untouched.
fn preserve_existing_directory(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), ReplacementError> {
    for entry in fs::read_dir(source).map_err(|error| ReplacementError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| ReplacementError::Io(error.to_string()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| ReplacementError::Io(error.to_string()))?;
        if metadata.file_type().is_dir() {
            fs::create_dir(&destination_path)
                .map_err(|error| ReplacementError::Io(error.to_string()))?;
            preserve_existing_directory(&source_path, &destination_path)?;
            fs::set_permissions(&destination_path, metadata.permissions())
                .map_err(|error| ReplacementError::Io(error.to_string()))?;
        } else if metadata.file_type().is_file() {
            fs::hard_link(&source_path, &destination_path)
                .map_err(|error| ReplacementError::Io(error.to_string()))?;
        } else if metadata.file_type().is_symlink() {
            #[cfg(unix)]
            {
                let target = fs::read_link(&source_path)
                    .map_err(|error| ReplacementError::Io(error.to_string()))?;
                std::os::unix::fs::symlink(target, &destination_path)
                    .map_err(|error| ReplacementError::Io(error.to_string()))?;
            }
            #[cfg(not(unix))]
            {
                return Err(ReplacementError::Transfer(
                    "preserving destination symlinks is unsupported on this platform".to_owned(),
                ));
            }
        } else {
            return Err(ReplacementError::Transfer(
                "an existing destination special file cannot be preserved safely".to_owned(),
            ));
        }
    }
    Ok(())
}
