use std::{
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ActionId, ActionOutcome, ActionReason, DeletionMethod, FileMetadataProof, JournalEvent, OneWayPlan,
    PlanAction, PlanActionKind, RecoveryEvidence, RemovalResult, RunEvidenceStore, RunId,
    VerificationError, VerifiedReplacement,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryMethod {
    /// A caller-provided recovery directory for the verified Trash boundary.
    /// Native OS Trash discovery, provenance, and Restore remain part of the
    /// parent recovery-method issue.
    VerifiedRecoveryFolder { root: PathBuf },
    /// The platform's user Trash data root. The caller must pass the
    /// validated per-user XDG data directory; this never invokes a shell or
    /// silently changes to permanent removal.
    NativeTrash { data_root: PathBuf },
    PermanentRemoval,
}

impl RecoveryMethod {
    pub fn trash(root: impl Into<PathBuf>) -> Self {
        Self::VerifiedRecoveryFolder { root: root.into() }
    }

    pub fn verified_recovery_folder(root: impl Into<PathBuf>) -> Self {
        Self::VerifiedRecoveryFolder { root: root.into() }
    }

    pub fn native_trash(data_root: impl Into<PathBuf>) -> Self {
        Self::NativeTrash { data_root: data_root.into() }
    }

    pub const fn permanent_removal() -> Self {
        Self::PermanentRemoval
    }

    pub const fn deletion_method(&self) -> DeletionMethod {
        match self {
            Self::VerifiedRecoveryFolder { .. } | Self::NativeTrash { .. } => DeletionMethod::Trash,
            Self::PermanentRemoval => DeletionMethod::PermanentRemoval,
        }
    }

    fn recovery_root(&self) -> Option<PathBuf> {
        match self {
            Self::VerifiedRecoveryFolder { root } => Some(root.clone()),
            Self::NativeTrash { data_root } => Some(data_root.join("Trash/files")),
            Self::PermanentRemoval => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalReceipt {
    action_id: ActionId,
    deletion_method: DeletionMethod,
    recovery_target: Option<PathBuf>,
}

impl RemovalReceipt {
    pub const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub const fn deletion_method(&self) -> DeletionMethod {
        self.deletion_method
    }

    pub fn recovery_target(&self) -> Option<&Path> {
        self.recovery_target.as_deref()
    }
}

#[derive(Debug)]
pub enum SafeDeleteError {
    InvalidPlan(String),
    InvalidAction(String),
    Verification(VerificationError),
    RecoveryUnavailable(String),
    RecoveryUncertain(String),
    Io(String),
    Storage(crate::StorageError),
}

impl std::fmt::Display for SafeDeleteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPlan(reason) => write!(formatter, "invalid Safe Delete plan: {reason}"),
            Self::InvalidAction(reason) => write!(formatter, "invalid Safe Delete action: {reason}"),
            Self::Verification(error) => error.fmt(formatter),
            Self::RecoveryUnavailable(reason) => {
                write!(formatter, "Safe Delete recovery is unavailable: {reason}")
            }
            Self::RecoveryUncertain(reason) => {
                write!(formatter, "Safe Delete recovery is uncertain: {reason}")
            }
            Self::Io(reason) => write!(formatter, "Safe Delete filesystem error: {reason}"),
            Self::Storage(error) => write!(formatter, "Safe Delete journal error: {error}"),
        }
    }
}

impl std::error::Error for SafeDeleteError {}

impl From<VerificationError> for SafeDeleteError {
    fn from(error: VerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<crate::StorageError> for SafeDeleteError {
    fn from(error: crate::StorageError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Debug, Clone)]
pub struct SafeDeleteExecutor {
    recovery_method: RecoveryMethod,
}

struct RemovalAttempt {
    result: RemovalResult,
    #[cfg(target_os = "linux")]
    source_guard: SourcePreservationGuard,
}

#[cfg(target_os = "linux")]
struct SourcePreservationGuard {
    parent: std::os::fd::OwnedFd,
    name: std::ffi::CString,
    retain_on_drop: bool,
}

#[cfg(target_os = "linux")]
impl SourcePreservationGuard {
    fn retain(&mut self) {
        self.retain_on_drop = true;
    }

    fn cleanup(&mut self) -> Result<(), SafeDeleteError> {
        use std::os::fd::AsRawFd;

        let result = unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
        if result == 0 || io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            self.retain_on_drop = true;
            Ok(())
        } else {
            self.retain_on_drop = true;
            Err(SafeDeleteError::RecoveryUncertain(format!(
                "source preservation guard could not be cleaned up: {}",
                io::Error::last_os_error()
            )))
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for SourcePreservationGuard {
    fn drop(&mut self) {
        if !self.retain_on_drop {
            use std::os::fd::AsRawFd;

            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

impl SafeDeleteExecutor {
    pub fn new(recovery_method: RecoveryMethod) -> Self {
        Self { recovery_method }
    }

    pub const fn recovery_method(&self) -> &RecoveryMethod {
        &self.recovery_method
    }

    pub fn settle_one(
        &self,
        run_id: RunId,
        plan: &OneWayPlan,
        action: &PlanAction,
        replacement: &VerifiedReplacement,
        store: &mut RunEvidenceStore,
    ) -> Result<RemovalReceipt, SafeDeleteError> {
        plan.validate()
            .map_err(|error| SafeDeleteError::InvalidPlan(error.to_string()))?;
        let planned_action = plan
            .actions()
            .iter()
            .find(|candidate| candidate.action_id() == action.action_id())
            .ok_or_else(|| {
                SafeDeleteError::InvalidAction(format!(
                    "action {} is not in the plan",
                    action.action_id()
                ))
            })?;
        if planned_action != action {
            return Err(SafeDeleteError::InvalidAction(
                "the supplied action does not match the planned action".to_owned(),
            ));
        }
        if action.kind() != PlanActionKind::RemoveSourceAfterVerification {
            return Err(SafeDeleteError::InvalidAction(
                "only source-removal actions can enter the Safe Delete proof boundary".to_owned(),
            ));
        }
        let options = plan.specification().options();
        let selected_method = options
            .deletion_method()
            .ok_or_else(|| {
                SafeDeleteError::InvalidPlan(
                    "Safe Delete requires an explicitly selected deletion method".to_owned(),
                )
            })?;
        if selected_method != self.recovery_method.deletion_method() {
            return Err(SafeDeleteError::InvalidAction(
                "the executor method does not match the frozen profile selection".to_owned(),
            ));
        }
        ensure_prior_source_removals_settled(run_id, plan, action.action_id(), store)?;

        let source = plan
            .specification()
            .source_path(action)
            .map_err(|error| SafeDeleteError::InvalidAction(error.to_string()))?;
        let destination = plan
            .specification()
            .destination_path(action)
            .map_err(|error| SafeDeleteError::InvalidAction(error.to_string()))?;
        if replacement.source() != source || replacement.destination() != destination {
            return Err(SafeDeleteError::InvalidAction(
                "transfer proof is bound to a different source or destination".to_owned(),
            ));
        }
        if let Err(error) =
        validate_source_item_path(plan.specification().source_root(), action.relative_path())
        {
            return self.fail_unresolved(run_id, action.action_id(), store, error);
        }
        let source_root = match fs::canonicalize(plan.specification().source_root()) {
            Ok(path) => path,
            Err(error) => {
                return self.fail_unresolved(run_id, action.action_id(), store, io_error(error))
            }
        };
        let source = source_root.join(action.relative_path());
        let proof = replacement.proof();
        let metadata_requirements = options.metadata();
        if replacement.metadata_requirements() != metadata_requirements {
            return self.fail_unresolved(
                run_id,
                action.action_id(),
                store,
                SafeDeleteError::InvalidAction(
                    "transfer proof metadata requirements do not match the frozen profile"
                        .to_owned(),
                ),
            );
        }
        if let Err(error) = ensure_journaled_source_proof(run_id, action.action_id(), proof, store) {
            return self.fail_unresolved(run_id, action.action_id(), store, error);
        }
        if proof.source_before() != proof.source_after() {
            return self.fail_unresolved(
                run_id,
                action.action_id(),
                store,
                SafeDeleteError::Verification(VerificationError::SourceChanged),
            );
        }
        if !matches!(
            proof.source_after().metadata().item_type(),
            crate::ItemType::RegularFile | crate::ItemType::Symlink
        ) {
            return self.fail_unresolved(
                run_id,
                action.action_id(),
                store,
                SafeDeleteError::Verification(VerificationError::UnsupportedItem),
            );
        }
        if let Err(error) = proof.source_after().recheck(&source) {
            return self.fail_unresolved(
                run_id,
                action.action_id(),
                store,
                SafeDeleteError::Verification(error),
            );
        }
        let destination_content = match proof.installed_destination_proof() {
            Some(expected) => Some(
                crate::verify_content(&destination, &expected)
                    .map_err(SafeDeleteError::Verification)
                    .or_else(|error| {
                        self.fail_unresolved(run_id, action.action_id(), store, error)
                    })?,
            ),
            None => None,
        };
        let destination_metadata = match FileMetadataProof::capture(&destination) {
            Ok(metadata) => metadata,
            Err(error) => {
                return self.fail_unresolved(
                    run_id,
                    action.action_id(),
                    store,
                    SafeDeleteError::Verification(error),
                )
            }
        };
        if !proof
            .source_after()
            .metadata()
            .matches_transfer_metadata(&destination_metadata, metadata_requirements)
        {
            return self.fail_unresolved(
                run_id,
                action.action_id(),
                store,
                SafeDeleteError::Verification(VerificationError::HashMismatch),
            );
        }
        let (recovery_target, provenance) = if let Some(recovery_root) = self.recovery_method.recovery_root() {
            let (_recovery_root, recovery_target, same_filesystem) =
                match validate_recovery_root(&source_root, &source, &recovery_root)
                {
                    Ok(layout) => layout,
                    Err(error) => {
                        return self.fail_unresolved(
                            run_id,
                            action.action_id(),
                            store,
                            error,
                        )
                    }
                };
            match fs::symlink_metadata(&recovery_target) {
                Ok(_) => {
                    return self.fail_unresolved(
                        run_id,
                        action.action_id(),
                        store,
                        SafeDeleteError::RecoveryUnavailable(
                            "the recovery target already exists".to_owned(),
                        ),
                    )
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return self.fail_unresolved(
                        run_id,
                        action.action_id(),
                        store,
                        io_error(error),
                    )
                }
            }
            if !same_filesystem {
                if let Err(error) =
                    ensure_recovery_space(
                        &recovery_root,
                        proof
                            .source_after()
                            .content_proof()
                            .map_or_else(
                                || proof.source_after().metadata().size(),
                                |content| content.size(),
                            ),
                    )
                {
                    return self.fail_unresolved(run_id, action.action_id(), store, error);
                }
            }
            let snapshot = store.load_snapshot(run_id)?;
            let peer = match action.source_side() {
                crate::PeerSide::PeerA => snapshot.profile().peer_a().name(),
                crate::PeerSide::PeerB => snapshot.profile().peer_b().name(),
            };
            let source_metadata = proof.source_after().metadata();
            let provenance = crate::RecoveryProvenance::new_for_action_with_target(
                action.action_id(),
                peer,
                source_root.clone(),
                action.relative_path().to_path_buf(),
                run_id,
                selected_method,
                source_metadata.item_type(),
                proof.source_after().content_proof(),
                source_metadata.identity(),
                source_metadata.symlink_target().map(Path::to_path_buf),
            )
            .map_err(|error| SafeDeleteError::RecoveryUnavailable(error.to_string()))?;
            (Some(recovery_target), Some(provenance))
        } else {
            self.fail_unresolved(
                run_id,
                action.action_id(),
                store,
                SafeDeleteError::RecoveryUnavailable(
                    "Permanent Removal requires the parent recovery and authorization slice"
                        .to_owned(),
                ),
            )?;
            (None, None)
        };

        let transfer_evidence = RecoveryEvidence::new(
            now_unix_nanos(),
            None,
            true,
            true,
            false,
            proof
                .source_after()
                .content_proof()
                .map(|content| content.size())
                .or_else(|| Some(proof.source_after().metadata().size())),
            destination_content.map(|content| content.size()).or_else(|| {
                Some(proof.source_after().metadata().size())
            }),
            proof
                .source_after()
                .content_proof()
                .map(|content| *content.sha256()),
            destination_content.map(|content| *content.sha256()),
        );
        store.append_event(
            run_id,
            JournalEvent::TransferVerified {
                action_id: action.action_id(),
                evidence: transfer_evidence.clone(),
                metadata_verified: true,
            },
        )?;
        store.append_event(
            run_id,
            JournalEvent::ProofBoundary {
                action_id: action.action_id(),
                deletion_method: selected_method,
                evidence: transfer_evidence,
                metadata_verified: true,
            },
        )?;
        store.append_event(
            run_id,
            JournalEvent::RemovalStarted {
                action_id: action.action_id(),
                deletion_method: selected_method,
            },
        )?;

        let mut attempt = match self.perform_removal(
            &source_root,
            &source,
            action.relative_path(),
            proof,
            metadata_requirements,
            provenance
                .as_ref()
                .ok_or_else(|| SafeDeleteError::RecoveryUnavailable("recovery provenance is unavailable".to_owned()))?,
        ) {
            Ok(attempt) => attempt,
            Err(error) => {
                return self.record_failure(
                    run_id,
                    action.action_id(),
                    store,
                    &source,
                    &destination,
                    recovery_target.as_deref(),
                    error,
                )
            }
        };
        if let Err(storage_error) = store.append_event(
            run_id,
            JournalEvent::RemovalCompleted {
                action_id: action.action_id(),
                result: attempt.result.clone(),
            },
        ) {
            let journal_failure = SafeDeleteError::RecoveryUncertain(format!(
                "RemovalCompleted journal write failed after filesystem mutation: {storage_error}"
            ));
            let review = self.append_failure_event(
                run_id,
                action.action_id(),
                store,
                Some(&source),
                Some(&destination),
                recovery_target.as_deref(),
                &journal_failure,
                true,
            );
            return match review {
                Ok(()) => Err(journal_failure),
                Err(review_error) => Err(review_error),
            };
        }
        #[cfg(target_os = "linux")]
        let _ = attempt.source_guard.cleanup();
        Ok(RemovalReceipt {
            action_id: action.action_id(),
            deletion_method: selected_method,
            recovery_target: attempt
                .result
                .evidence()
                .recovery_target()
                .map(Path::to_path_buf),
        })
    }

    fn perform_removal(
        &self,
        source_root: &Path,
        source: &Path,
        relative_path: &Path,
        proof: &crate::VerifiedTransferProof,
        metadata_requirements: crate::MetadataRequirements,
        provenance: &crate::RecoveryProvenance,
    ) -> Result<RemovalAttempt, SafeDeleteError> {
        match self.recovery_method.recovery_root() {
            Some(recovery_root) => {
                let (recovery_root, recovery_target, same_filesystem) =
                    validate_recovery_root(source_root, source, &recovery_root)?;
                if matches!(self.recovery_method, RecoveryMethod::VerifiedRecoveryFolder { .. }) {
                    if let Some(parent) = recovery_target.parent() {
                        fs::create_dir_all(parent).map_err(io_error)?;
                    }
                }
                let provenance_path =
                    self.prepare_recovery_provenance(provenance, &source, &recovery_target)?;
                let result = if same_filesystem {
                    self.move_to_same_filesystem_recovery(
                        source_root,
                        &recovery_root,
                        relative_path,
                        source,
                        &recovery_target,
                        proof,
                        metadata_requirements,
                        provenance,
                    )
                } else {
                    self.copy_to_cross_filesystem_recovery(
                        source_root,
                        &recovery_root,
                        relative_path,
                        source,
                        &recovery_target,
                        proof,
                        metadata_requirements,
                        provenance,
                    )
                };
                if result.is_err() {
                    if let Some(path) = provenance_path {
                        let _ = fs::remove_file(path);
                    }
                }
                result
            }
            None => Err(SafeDeleteError::RecoveryUnavailable(
                "Permanent Removal is not available in this core slice".to_owned(),
            )),
        }
    }

    fn prepare_native_provenance(
        &self,
        source: &Path,
        recovery_target: &Path,
    ) -> Result<Option<PathBuf>, SafeDeleteError> {
        let RecoveryMethod::NativeTrash { .. } = self.recovery_method else {
            return Ok(None);
        };
        let info_root = recovery_target.parent().and_then(Path::parent).ok_or_else(|| {
            SafeDeleteError::RecoveryUnavailable("native Trash target has no info directory".to_owned())
        })?.join("info");
        fs::create_dir_all(&info_root).map_err(io_error)?;
        let name = recovery_target.file_name().ok_or_else(|| {
            SafeDeleteError::RecoveryUnavailable("native Trash target has no file name".to_owned())
        })?;
        let info = info_root.join(name).with_extension("trashinfo");
        if info.exists() {
            return Err(SafeDeleteError::RecoveryUnavailable("native Trash provenance already exists".to_owned()));
        }
        let escaped = source.to_string_lossy().replace('%', "%25").replace('\n', "%0A");
        let contents = format!("[Trash Info]\nPath={escaped}\nDeletionDate={}\n", now_unix_nanos());
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&info).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(io_error)?;
        }
        file.write_all(contents.as_bytes()).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        Ok(Some(info))
    }

    fn prepare_recovery_provenance(
        &self,
        provenance: &crate::RecoveryProvenance,
        source: &Path,
        recovery_target: &Path,
    ) -> Result<Option<PathBuf>, SafeDeleteError> {
        match self.recovery_method {
            RecoveryMethod::NativeTrash { .. } => {
                self.prepare_native_provenance(source, recovery_target)
            }
            RecoveryMethod::VerifiedRecoveryFolder { .. } => provenance
                .write_sidecar_for(recovery_target)
                .map(Some)
                .map_err(|error| SafeDeleteError::RecoveryUnavailable(error.to_string())),
            RecoveryMethod::PermanentRemoval => Ok(None),
        }
    }

    fn move_to_same_filesystem_recovery(
        &self,
        source_root: &Path,
        recovery_root: &Path,
        relative_path: &Path,
        _source: &Path,
        recovery_target: &Path,
        proof: &crate::VerifiedTransferProof,
        metadata_requirements: crate::MetadataRequirements,
        provenance: &crate::RecoveryProvenance,
    ) -> Result<RemovalAttempt, SafeDeleteError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;

            let (source_parent, source_name) = open_relative_parent(source_root, relative_path)?;
            let (recovery_parent, recovery_name) =
                open_or_create_relative_parent(recovery_root, relative_path)?;
            let source_lock = ensure_source_entry_matches(&source_parent, &source_name, proof)?;
            let mut source_guard = match create_source_guard(&source_parent, &source_name) {
                Ok(guard) => guard,
                Err(error) => return Err(error),
            };
            if let Err(error) = rename_at_noreplace(
                source_parent.as_raw_fd(),
                &source_name,
                recovery_parent.as_raw_fd(),
                &recovery_name,
            ) {
                source_guard.retain();
                return Err(error);
            }
            let verification = ensure_entry_absent(&source_parent, &source_name)
                .and_then(|()| {
                    verify_recovery_entry(
                        &recovery_parent,
                        &recovery_name,
                        proof,
                        metadata_requirements,
                    )
                });
            if let Err(error) = verification {
                drop(source_lock);
                if restore_source_from_guard(&source_guard, &source_parent, &source_name, proof)
                    .is_ok()
                {
                    let _ = source_guard.cleanup();
                    return Err(SafeDeleteError::RecoveryUnavailable(format!(
                        "recovery verification failed and the source was restored: {error}"
                    )));
                }
                source_guard.retain();
                return Err(SafeDeleteError::RecoveryUncertain(format!(
                    "recovery verification failed and the source restoration is uncertain: {error}"
                )));
            }
            drop(source_lock);
            source_guard.retain();
            Ok(RemovalAttempt {
                result: RemovalResult::new(
                    DeletionMethod::Trash,
                    removal_evidence(Some(recovery_target), true, proof, provenance.clone()),
                ),
                source_guard,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                source_root,
                recovery_root,
                relative_path,
                _source,
                recovery_target,
                proof,
            );
            Err(SafeDeleteError::RecoveryUnavailable(
                "atomic descriptor-relative recovery is supported only on Linux".to_owned(),
            ))
        }
    }

    fn copy_to_cross_filesystem_recovery(
        &self,
        source_root: &Path,
        recovery_root: &Path,
        relative_path: &Path,
        _source: &Path,
        recovery_target: &Path,
        proof: &crate::VerifiedTransferProof,
        metadata_requirements: crate::MetadataRequirements,
        provenance: &crate::RecoveryProvenance,
    ) -> Result<RemovalAttempt, SafeDeleteError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                source_root,
                recovery_root,
                relative_path,
                _source,
                recovery_target,
                proof,
                metadata_requirements,
                provenance,
            );
            return Err(SafeDeleteError::RecoveryUnavailable(
                "descriptor-relative cross-filesystem recovery is supported only on Linux"
                    .to_owned(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;

            if proof.source_after().metadata().item_type() != crate::ItemType::RegularFile {
                return Err(SafeDeleteError::RecoveryUnavailable(
                    "cross-filesystem recovery currently supports regular files only"
                        .to_owned(),
                ));
            }

            let source_size = proof.source_after().content().size();
            ensure_recovery_space(recovery_target, source_size)?;
            let (recovery_parent, recovery_name) =
                open_or_create_relative_parent(recovery_root, relative_path)?;
            let mut source_guard =
                create_source_guard_for_path(source_root, relative_path, proof)?;
            let (mut temporary, temporary_name) =
                create_recovery_temporary(&recovery_parent, &recovery_name)?;
            let copy_result = (|| {
                copy_source_without_following(
                    source_root,
                    relative_path,
                    &mut temporary,
                    proof,
                    metadata_requirements,
                )?;
                verify_recovery_file(&mut temporary, proof, metadata_requirements)?;
                temporary.sync_all().map_err(io_error)?;
                rename_at_noreplace(
                    recovery_parent.as_raw_fd(),
                    &temporary_name,
                    recovery_parent.as_raw_fd(),
                    &recovery_name,
                )
                .map_err(|error| SafeDeleteError::RecoveryUncertain(error.to_string()))?;
                verify_recovery_entry(
                    &recovery_parent,
                    &recovery_name,
                    proof,
                    metadata_requirements,
                )?;
                remove_source_exact(source_root, relative_path, proof, &source_guard)?;
                Ok(())
            })();
            match copy_result {
                Ok(()) => {
                    source_guard.retain();
                    Ok(RemovalAttempt {
                        result: RemovalResult::new(
                            DeletionMethod::Trash,
                            removal_evidence(Some(recovery_target), true, proof, provenance.clone()),
                        ),
                        source_guard,
                    })
                }
                Err(error) => {
                    if matches!(error, SafeDeleteError::RecoveryUncertain(_)) {
                        source_guard.retain();
                    }
                    cleanup_recovery_temporary(&recovery_parent, &temporary_name);
                    Err(error)
                }
            }
        }
    }

    fn fail_unresolved<T>(
        &self,
        run_id: RunId,
        action_id: ActionId,
        store: &mut RunEvidenceStore,
        error: SafeDeleteError,
    ) -> Result<T, SafeDeleteError> {
        self.append_failure_event(
            run_id,
            action_id,
            store,
            None,
            None,
            None,
            &error,
            false,
        )?;
        Err(error)
    }

    fn record_failure<T>(
        &self,
        run_id: RunId,
        action_id: ActionId,
        store: &mut RunEvidenceStore,
        source: &Path,
        destination: &Path,
        recovery_target: Option<&Path>,
        error: SafeDeleteError,
    ) -> Result<T, SafeDeleteError> {
        let review = matches!(error, SafeDeleteError::RecoveryUncertain(_));
        self.append_failure_event(
            run_id,
            action_id,
            store,
            Some(source),
            Some(destination),
            recovery_target,
            &error,
            review,
        )?;
        Err(error)
    }

    fn append_failure_event(
        &self,
        run_id: RunId,
        action_id: ActionId,
        store: &mut RunEvidenceStore,
        source: Option<&Path>,
        destination: Option<&Path>,
        recovery_target: Option<&Path>,
        error: &SafeDeleteError,
        review: bool,
    ) -> Result<(), SafeDeleteError> {
        let reason = action_reason(error);
        let event = if review {
            JournalEvent::RecoveryReview {
                action_id,
                reason,
                evidence: match (source, destination) {
                    (Some(source), Some(destination)) => {
                        observe_recovery_boundary(source, destination, recovery_target)
                    }
                    _ => RecoveryEvidence::new(
                        now_unix_nanos(),
                        recovery_target.map(Path::to_path_buf),
                        false,
                        false,
                        false,
                        None,
                        None,
                        None,
                        None,
                    ),
                },
            }
        } else {
            JournalEvent::Unresolved { action_id, reason }
        };
        match store.append_event(run_id, event) {
            Ok(()) => Ok(()),
            Err(storage_error @ crate::StorageError::InvalidEvent(_)) => {
                Err(SafeDeleteError::Storage(storage_error))
            }
            Err(storage_error) => Err(SafeDeleteError::Storage(storage_error)),
        }
    }
}

fn ensure_prior_source_removals_settled(
    run_id: RunId,
    plan: &OneWayPlan,
    action_id: ActionId,
    store: &RunEvidenceStore,
) -> Result<(), SafeDeleteError> {
    let journal = store.load_journal(run_id)?;
    for prior_action in plan.actions().iter().filter(|candidate| {
        candidate.action_id() < action_id
            && candidate.kind() == PlanActionKind::RemoveSourceAfterVerification
    }) {
        let Some(entry) = journal
            .iter()
            .find(|entry| entry.plan().action_id() == prior_action.action_id())
        else {
            return Err(SafeDeleteError::InvalidAction(format!(
                "source-removal action {} must be journaled before action {}",
                prior_action.action_id(),
                action_id
            )));
        };
        if !matches!(entry.outcome(), ActionOutcome::Completed) {
            return Err(SafeDeleteError::InvalidAction(format!(
                "source-removal action {} is not settled before action {}",
                prior_action.action_id(),
                action_id
            )));
        }
    }
    Ok(())
}

fn ensure_journaled_source_proof(
    run_id: RunId,
    action_id: ActionId,
    proof: &crate::VerifiedTransferProof,
    store: &RunEvidenceStore,
) -> Result<(), SafeDeleteError> {
    let journal = store.load_journal(run_id)?;
    let entry = journal
        .iter()
        .find(|entry| entry.plan().action_id() == action_id)
        .ok_or_else(|| {
            SafeDeleteError::InvalidAction(format!(
                "Safe Delete action {action_id} must have a durable plan boundary"
            ))
        })?;
    if !entry.started() || !matches!(entry.outcome(), ActionOutcome::InProgress) {
        return Err(SafeDeleteError::InvalidAction(format!(
            "Safe Delete action {action_id} is not in a transferable journal state"
        )));
    }
    let source = proof.source_after();
    let planned = entry.plan().pre_action();
    let content_matches = match source.content_proof() {
        Some(content) => planned.sha256() == Some(content.sha256()),
        None => planned.sha256().is_none(),
    };
    if planned.item_type() != source.metadata().item_type()
        || planned.size() != source.metadata().size()
        || planned.modified_at_unix_nanos()
            != source.metadata().modified_at_unix_nanos()
        || planned.identity() != source.metadata().identity()
        || !content_matches
    {
        return Err(SafeDeleteError::Verification(
            VerificationError::SourceChanged,
        ));
    }
    Ok(())
}

fn validate_source_item_path(source_root: &Path, relative_path: &Path) -> Result<(), SafeDeleteError> {
    validate_relative_path(relative_path)?;
    let source_root_metadata = fs::symlink_metadata(source_root).map_err(io_error)?;
    if !source_root_metadata.is_dir() || source_root_metadata.file_type().is_symlink() {
        return Err(SafeDeleteError::InvalidAction(
            "the selected source root is not a real directory".to_owned(),
        ));
    }
    let source = source_root.join(relative_path);
    if source == source_root {
        return Err(SafeDeleteError::InvalidAction(
            "the selected source root is never an item eligible for removal".to_owned(),
        ));
    }
    let canonical_root = fs::canonicalize(source_root).map_err(io_error)?;
    if source.parent().is_none_or(|parent| {
        fs::canonicalize(parent)
            .map(|canonical_parent| !canonical_parent.starts_with(&canonical_root))
            .unwrap_or(true)
    }) {
        return Err(SafeDeleteError::InvalidAction(
            "the source item resolves outside the selected source root".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), SafeDeleteError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SafeDeleteError::InvalidAction(
            "source removal requires a non-empty normalized relative path".to_owned(),
        ));
    }
    Ok(())
}

fn validate_recovery_root(
    source_root: &Path,
    source: &Path,
    recovery_root: &Path,
) -> Result<(PathBuf, PathBuf, bool), SafeDeleteError> {
    let source_root = canonical_directory(source_root, "source root")?;
    let recovery_root = canonical_directory(recovery_root, "recovery root")?;
    if recovery_root == source_root || recovery_root.starts_with(&source_root) {
        return Err(SafeDeleteError::RecoveryUnavailable(
            "the recovery root overlaps the selected source root".to_owned(),
        ));
    }
    let source_metadata = fs::symlink_metadata(source).map_err(io_error)?;
    let source_for_overlap = if source_metadata.file_type().is_symlink() {
        source.to_path_buf()
    } else {
        fs::canonicalize(source).map_err(io_error)?
    };
    if source_for_overlap == recovery_root || source_for_overlap.starts_with(&recovery_root) {
        return Err(SafeDeleteError::RecoveryUnavailable(
            "the recovery root overlaps the source item".to_owned(),
        ));
    }
    let source_device = device_of(source)?;
    let recovery_device = device_of(&recovery_root)?;
    let relative = source.strip_prefix(&source_root).map_err(|_| {
        SafeDeleteError::RecoveryUnavailable(
            "the source item is outside the selected source root".to_owned(),
        )
    })?;
    Ok((
        recovery_root.clone(),
        recovery_root.join(relative),
        source_device == recovery_device,
    ))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, SafeDeleteError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SafeDeleteError::RecoveryUnavailable(format!("{label} is unavailable: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SafeDeleteError::RecoveryUnavailable(format!(
            "{label} must be a non-symlink directory"
        )));
    }
    fs::canonicalize(path).map_err(io_error)
}

fn ensure_recovery_space(path: &Path, required: u64) -> Result<(), SafeDeleteError> {
    let parent = path.parent().ok_or_else(|| {
        SafeDeleteError::RecoveryUnavailable("recovery target has no parent".to_owned())
    })?;
    let available = available_space(parent)?;
    if available < required {
        return Err(SafeDeleteError::RecoveryUnavailable(format!(
            "recovery volume has {available} bytes available but requires {required}"
        )));
    }
    Ok(())
}

fn available_space(path: &Path) -> Result<u64, SafeDeleteError> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| SafeDeleteError::RecoveryUnavailable("path contains NUL".to_owned()))?;
        let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let result = unsafe { libc::statvfs(path.as_ptr(), status.as_mut_ptr()) };
        if result != 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        let status = unsafe { status.assume_init() };
        return (status.f_bavail as u128)
            .checked_mul(status.f_frsize as u128)
            .and_then(|space| u64::try_from(space).ok())
            .ok_or_else(|| {
                SafeDeleteError::RecoveryUnavailable(
                    "recovery volume free-space value overflowed".to_owned(),
                )
            });
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SafeDeleteError::RecoveryUnavailable(
            "recovery volume free-space probing is unsupported".to_owned(),
        ))
    }
}

static NEXT_RECOVERY_TEMPORARY: AtomicU64 = AtomicU64::new(1);
#[cfg(target_os = "linux")]
static NEXT_SOURCE_GUARD: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "linux")]
fn create_source_guard_for_path(
    source_root: &Path,
    relative_path: &Path,
    proof: &crate::VerifiedTransferProof,
) -> Result<SourcePreservationGuard, SafeDeleteError> {
    let (parent, name) = open_relative_parent(source_root, relative_path)?;
    let source_lock = ensure_source_entry_matches(&parent, &name, proof)?;
    let guard = create_source_guard(&parent, &name);
    drop(source_lock);
    guard
}

#[cfg(target_os = "linux")]
fn create_source_guard(
    parent: &std::os::fd::OwnedFd,
    source_name: &std::ffi::CString,
) -> Result<SourcePreservationGuard, SafeDeleteError> {
    use std::{
        ffi::{CString, OsStr},
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };

    for _ in 0..1024 {
        let sequence = NEXT_SOURCE_GUARD.fetch_add(1, Ordering::Relaxed);
        let mut name = std::ffi::OsString::from(".syncplus-source-guard-");
        name.push(sequence.to_string());
        name.push("-");
        name.push(OsStr::from_bytes(source_name.to_bytes()));
        let guard_name = CString::new(name.as_os_str().as_bytes())
            .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?;
        let result = unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                source_name.as_ptr(),
                parent.as_raw_fd(),
                guard_name.as_ptr(),
                0,
            )
        };
        if result == 0 {
            return Ok(SourcePreservationGuard {
                parent: parent.try_clone().map_err(io_error)?,
                name: guard_name,
                retain_on_drop: false,
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(SafeDeleteError::RecoveryUnavailable(format!(
                "the source could not be protected before removal: {error}"
            )));
        }
    }
    Err(SafeDeleteError::RecoveryUnavailable(
        "could not allocate a source preservation guard".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn restore_source_from_guard(
    guard: &SourcePreservationGuard,
    source_parent: &std::os::fd::OwnedFd,
    source_name: &std::ffi::CString,
    proof: &crate::VerifiedTransferProof,
) -> Result<(), SafeDeleteError> {
    use std::os::fd::AsRawFd;

    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(SafeDeleteError::RecoveryUncertain(
            "the source path was recreated before restoration".to_owned(),
        ));
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::NotFound {
        return Err(SafeDeleteError::RecoveryUncertain(format!(
            "the source path could not be inspected during restoration: {error}"
        )));
    }
    let result = unsafe {
        libc::linkat(
            guard.parent.as_raw_fd(),
            guard.name.as_ptr(),
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            0,
        )
    };
    if result != 0 {
        return Err(SafeDeleteError::RecoveryUncertain(format!(
            "the original source could not be restored: {}",
            io::Error::last_os_error()
        )));
    }
    let restored = ensure_source_entry_matches(source_parent, source_name, proof);
    match restored {
        Ok(file) => {
            drop(file);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn create_recovery_temporary(
    parent: &std::os::fd::OwnedFd,
    target_name: &std::ffi::CString,
) -> Result<(std::fs::File, std::ffi::CString), SafeDeleteError> {
    use std::{
        ffi::{CString, OsStr},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };

    for _ in 0..1024 {
        let sequence = NEXT_RECOVERY_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let mut name = std::ffi::OsString::from(".");
        name.push("syncplus-recovery-");
        name.push(sequence.to_string());
        name.push("-");
        name.push(OsStr::from_bytes(target_name.to_bytes()));
        name.push(".tmp");
        let temporary_name = CString::new(name.as_os_str().as_bytes())
            .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary_name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            return Ok((unsafe { std::fs::File::from_raw_fd(fd) }, temporary_name));
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::AlreadyExists => continue,
            _ => return Err(io_error(io::Error::last_os_error())),
        }
    }
    Err(SafeDeleteError::RecoveryUnavailable(
        "could not allocate a unique recovery temporary".to_owned(),
    ))
}

fn copy_source_without_following(
    source_root: &Path,
    relative_path: &Path,
    destination_file: &mut std::fs::File,
    proof: &crate::VerifiedTransferProof,
    metadata_requirements: crate::MetadataRequirements,
) -> Result<(), SafeDeleteError> {
    let mut source_file = open_source_file(source_root, relative_path)?;
    let source_metadata = source_file.metadata().map_err(io_error)?;
    if !proof
        .source_after()
        .metadata()
        .matches_open_file_metadata(&source_metadata)
    {
        return Err(SafeDeleteError::Verification(
            VerificationError::SourceChanged,
        ));
    }

    destination_file.set_len(0).map_err(io_error)?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source_file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        destination_file
            .write_all(&buffer[..read])
            .map_err(io_error)?;
    }
    #[cfg(unix)]
    if let Some(permissions) = proof.source_after().metadata().permissions() {
        use std::os::unix::fs::PermissionsExt;
        destination_file
            .set_permissions(fs::Permissions::from_mode(permissions))
            .map_err(io_error)?;
    }
    if metadata_requirements.timestamps() {
        let modified_at = proof
            .source_after()
            .metadata()
            .modified_at()
            .ok_or_else(|| {
                SafeDeleteError::Verification(VerificationError::HashMismatch)
            })?;
        destination_file
            .set_modified(modified_at)
            .map_err(io_error)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_recovery_temporary(
    parent: &std::os::fd::OwnedFd,
    name: &std::ffi::CString,
) {
    use std::os::fd::AsRawFd;

    unsafe {
        libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
    }
}

#[cfg(target_os = "linux")]
fn open_source_file(source_root: &Path, relative_path: &Path) -> Result<std::fs::File, SafeDeleteError> {
    use std::{
        os::fd::{AsRawFd, FromRawFd},
    };

    let (parent, name) = open_relative_parent(source_root, relative_path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_source_file(
    source_root: &Path,
    relative_path: &Path,
) -> Result<std::fs::File, SafeDeleteError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.open(source_root.join(relative_path)).map_err(io_error)
}

#[cfg(target_os = "linux")]
fn remove_source_exact(
    source_root: &Path,
    relative_path: &Path,
    proof: &crate::VerifiedTransferProof,
    source_guard: &SourcePreservationGuard,
) -> Result<(), SafeDeleteError> {
    let (source_parent, source_name) = open_relative_parent(source_root, relative_path)?;
    let source_lock = ensure_source_entry_matches(&source_parent, &source_name, proof)?;
    let result = unsafe {
        libc::unlinkat(
            std::os::fd::AsRawFd::as_raw_fd(&source_parent),
            source_name.as_ptr(),
            0,
        )
    };
    if result != 0 {
        let removal_error = io::Error::last_os_error();
        drop(source_lock);
        let _ = restore_source_from_guard(source_guard, &source_parent, &source_name, proof);
        return Err(SafeDeleteError::RecoveryUncertain(format!(
            "source removal returned an uncertain result: {removal_error}"
        )));
    }
    drop(source_lock);
    if let Err(error) = ensure_entry_absent(&source_parent, &source_name) {
        let _ = restore_source_from_guard(source_guard, &source_parent, &source_name, proof);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_source_exact(
    _source_root: &Path,
    _relative_path: &Path,
    _proof: &crate::VerifiedTransferProof,
    _source_guard: &(),
) -> Result<(), SafeDeleteError> {
    Err(SafeDeleteError::RecoveryUnavailable(
        "safe descriptor-relative source removal is supported only on Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn open_relative_parent(
    root: &Path,
    relative_path: &Path,
) -> Result<(std::os::fd::OwnedFd, std::ffi::CString), SafeDeleteError> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };

    let mut fd = open_directory(root)?;
    let components: Vec<_> = relative_path.components().collect();
    let final_name = match components.last() {
        Some(Component::Normal(name)) => CString::new(name.as_bytes())
            .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?,
        _ => {
            return Err(SafeDeleteError::InvalidAction(
                "source removal requires a named item".to_owned(),
            ))
        }
    };
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(name) = component else {
            return Err(SafeDeleteError::InvalidAction(
                "source removal path contains a non-normal component".to_owned(),
            ));
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?;
        let child = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
            )
        };
        if child < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(child) };
    }
    Ok((fd, final_name))
}

#[cfg(target_os = "linux")]
fn open_or_create_relative_parent(
    root: &Path,
    relative_path: &Path,
) -> Result<(std::os::fd::OwnedFd, std::ffi::CString), SafeDeleteError> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };

    let mut fd = open_directory(root)?;
    let components: Vec<_> = relative_path.components().collect();
    let final_name = match components.last() {
        Some(Component::Normal(name)) => CString::new(name.as_bytes())
            .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?,
        _ => {
            return Err(SafeDeleteError::InvalidAction(
                "source removal requires a named item".to_owned(),
            ))
        }
    };
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(name) = component else {
            return Err(SafeDeleteError::InvalidAction(
                "source removal path contains a non-normal component".to_owned(),
            ));
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?;
        let child = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
            )
        };
        if child >= 0 {
            fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(child) };
            continue;
        }
        let open_error = io::Error::last_os_error();
        if open_error.kind() != io::ErrorKind::NotFound {
            return Err(io_error(open_error));
        }
        let created = unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 {
            let create_error = io::Error::last_os_error();
            if create_error.kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error(create_error));
            }
        }
        let child = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
            )
        };
        if child < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(child) };
    }
    Ok((fd, final_name))
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> Result<std::os::fd::OwnedFd, SafeDeleteError> {
    use std::ffi::CString;
    use std::os::{
        fd::FromRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    };

    let expected = fs::symlink_metadata(path).map_err(io_error)?;
    if !expected.is_dir() || expected.file_type().is_symlink() {
        return Err(SafeDeleteError::RecoveryUnavailable(
            "a recovery root was replaced with a non-directory".to_owned(),
        ));
    }

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SafeDeleteError::InvalidAction("path contains NUL".to_owned()))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status_result = unsafe { libc::fstat(fd, status.as_mut_ptr()) };
    if status_result != 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(io_error(error));
    }
    let status = unsafe { status.assume_init() };
    if status.st_dev as u64 != expected.dev() || status.st_ino as u64 != expected.ino() {
        unsafe { libc::close(fd) };
        return Err(SafeDeleteError::RecoveryUnavailable(
            "a recovery root changed during safety validation".to_owned(),
        ));
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn verify_recovery_entry(
    parent: &std::os::fd::OwnedFd,
    name: &std::ffi::CString,
    proof: &crate::VerifiedTransferProof,
    metadata_requirements: crate::MetadataRequirements,
) -> Result<(), SafeDeleteError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    if proof.source_after().metadata().item_type() == crate::ItemType::Symlink {
        use std::os::unix::ffi::OsStringExt;

        let entry = PathBuf::from("/proc/self/fd")
            .join(parent.as_raw_fd().to_string())
            .join(std::ffi::OsString::from_vec(name.as_bytes().to_vec()));
        let metadata = FileMetadataProof::capture(&entry).map_err(SafeDeleteError::Verification)?;
        if !proof
            .source_after()
            .metadata()
            .matches_transfer_metadata(&metadata, metadata_requirements)
        {
            return Err(SafeDeleteError::RecoveryUncertain(
                "the recovered symlink failed metadata verification".to_owned(),
            ));
        }
        return Ok(());
    }

    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(SafeDeleteError::RecoveryUncertain(format!(
            "the installed recovery item could not be opened: {}",
            io::Error::last_os_error()
        )));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    verify_recovery_file(&mut file, proof, metadata_requirements)
}

fn verify_recovery_file(
    file: &mut std::fs::File,
    proof: &crate::VerifiedTransferProof,
    metadata_requirements: crate::MetadataRequirements,
) -> Result<(), SafeDeleteError> {
    let opened_metadata = file.metadata().map_err(io_error)?;
    if !proof
        .source_after()
        .metadata()
        .matches_open_transfer_metadata(&opened_metadata, metadata_requirements)
    {
        return Err(SafeDeleteError::RecoveryUncertain(
            "the recovery item failed metadata verification".to_owned(),
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let content = crate::ContentProof::from_reader(file)?;
    let finished_metadata = file.metadata().map_err(io_error)?;
    if !proof.source_after().content().matches(&content)
        || !proof
            .source_after()
            .metadata()
            .matches_open_transfer_metadata(&finished_metadata, metadata_requirements)
    {
        return Err(SafeDeleteError::RecoveryUncertain(
            "the recovery item failed content or metadata verification".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_entry_absent(
    parent: &std::os::fd::OwnedFd,
    name: &std::ffi::CString,
) -> Result<(), SafeDeleteError> {
    use std::os::fd::AsRawFd;

    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(SafeDeleteError::RecoveryUncertain(
            "an item remained at the source boundary".to_owned(),
        ));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(SafeDeleteError::RecoveryUncertain(format!(
            "item absence could not be verified: {error}"
        )))
    }
}

#[cfg(target_os = "linux")]
fn ensure_source_entry_matches(
    parent: &std::os::fd::OwnedFd,
    name: &std::ffi::CString,
    proof: &crate::VerifiedTransferProof,
) -> Result<Option<std::fs::File>, SafeDeleteError> {
    use std::{
        os::fd::{AsRawFd, FromRawFd},
    };

    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let status = unsafe { status.assume_init() };
    let expected_identity = proof
        .source_after()
        .metadata()
        .identity()
        .ok_or_else(|| SafeDeleteError::Verification(VerificationError::SourceChanged))?;
    let expected_type = proof.source_after().metadata().item_type();
    let expected_file_type = match expected_type {
        crate::ItemType::RegularFile => libc::S_IFREG,
        crate::ItemType::Symlink => libc::S_IFLNK,
        _ => {
            return Err(SafeDeleteError::Verification(
                VerificationError::UnsupportedItem,
            ))
        }
    };
    if status.st_dev as u64 != expected_identity.device()
        || status.st_ino as u64 != expected_identity.inode()
        || status.st_size < 0
        || status.st_size as u64 != proof.source_after().metadata().size()
        || status.st_mode & libc::S_IFMT != expected_file_type
        || status.st_mode & 0o7777
            != proof.source_after().metadata().permissions().unwrap_or_default()
    {
        return Err(SafeDeleteError::Verification(
            VerificationError::SourceChanged,
        ));
    }
    if expected_type == crate::ItemType::Symlink {
        return Ok(None);
    }
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let lock_result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if lock_result != 0 {
        return Err(SafeDeleteError::RecoveryUnavailable(
            "the source is locked by another cooperating process".to_owned(),
        ));
    }
    let opened_metadata = file.metadata().map_err(io_error)?;
    if !proof
        .source_after()
        .metadata()
        .matches_open_file_metadata(&opened_metadata)
    {
        return Err(SafeDeleteError::Verification(
            VerificationError::SourceChanged,
        ));
    }
    let content = crate::ContentProof::from_reader(&mut file)?;
    let finished_metadata = file.metadata().map_err(io_error)?;
    if !proof.source_after().content().matches(&content)
        || !proof
            .source_after()
            .metadata()
            .matches_open_file_metadata(&finished_metadata)
    {
        return Err(SafeDeleteError::Verification(
            VerificationError::SourceChanged,
        ));
    }
    Ok(Some(file))
}

#[cfg(target_os = "linux")]
fn rename_at_noreplace(
    source_parent: std::os::fd::RawFd,
    source_name: &std::ffi::CString,
    destination_parent: std::os::fd::RawFd,
    destination_name: &std::ffi::CString,
) -> Result<(), SafeDeleteError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source_parent,
            source_name.as_ptr(),
            destination_parent,
            destination_name.as_ptr(),
            1u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(SafeDeleteError::RecoveryUncertain(format!(
            "atomic recovery move failed: {}",
            io::Error::last_os_error()
        )))
    }
}

fn removal_evidence(
    recovery_target: Option<&Path>,
    recovery_present: bool,
    proof: &crate::VerifiedTransferProof,
    provenance: crate::RecoveryProvenance,
) -> RecoveryEvidence {
    let content = proof.installed_destination_proof();
    let evidence = RecoveryEvidence::new(
        now_unix_nanos(),
        recovery_target.map(Path::to_path_buf),
        false,
        true,
        recovery_present,
        None,
        content
            .map(|content| content.size())
            .or_else(|| Some(proof.source_after().metadata().size())),
        None,
        content.map(|content| *content.sha256()),
    )
    .with_provenance(provenance);
    match proof.source_after().content_proof() {
        Some(content) => evidence.with_recovery_proof(content.size(), Some(*content.sha256())),
        None => evidence,
    }
}

fn observe_recovery_boundary(
    source: &Path,
    destination: &Path,
    recovery_target: Option<&Path>,
) -> RecoveryEvidence {
    let (source_present, source_size, source_sha256) = observe_content(source);
    let (destination_present, destination_size, destination_sha256) = observe_content(destination);
    let (recovery_present, _, _) = recovery_target
        .map(observe_content)
        .unwrap_or((false, None, None));
    RecoveryEvidence::new(
        now_unix_nanos(),
        recovery_target.map(Path::to_path_buf),
        source_present,
        destination_present,
        recovery_present,
        source_size,
        destination_size,
        source_sha256,
        destination_sha256,
    )
}

fn observe_content(path: &Path) -> (bool, Option<u64>, Option<[u8; 32]>) {
    match crate::ContentProof::from_path(path) {
        Ok(proof) => (true, Some(proof.size()), Some(*proof.sha256())),
        Err(_) => (fs::symlink_metadata(path).is_ok(), None, None),
    }
}

fn now_unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
        .unwrap_or(0)
}

fn device_of(path: &Path) -> Result<u64, SafeDeleteError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(metadata.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(0)
    }
}

fn io_error(error: io::Error) -> SafeDeleteError {
    SafeDeleteError::Io(error.to_string())
}

fn action_reason(error: &SafeDeleteError) -> ActionReason {
    match error {
        SafeDeleteError::Verification(VerificationError::SourceChanged) => {
            ActionReason::SourceChanged
        }
        SafeDeleteError::Verification(_) => ActionReason::VerificationMismatch,
        SafeDeleteError::RecoveryUnavailable(_) => ActionReason::DestinationUnavailable,
        SafeDeleteError::RecoveryUncertain(_) => ActionReason::InterruptedBoundary,
        SafeDeleteError::InvalidPlan(_)
        | SafeDeleteError::InvalidAction(_)
        | SafeDeleteError::Io(_)
        | SafeDeleteError::Storage(_) => ActionReason::PermissionDenied,
    }
}
