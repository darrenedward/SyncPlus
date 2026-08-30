use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    verify_content, verify_content_with_cancel, FileMetadataProof, MetadataRequirements,
    PartialTransferPolicy, SourceObservation, VerificationError, VerifiedTransferProof,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReplacement {
    source: PathBuf,
    destination: PathBuf,
    previous_destination: Option<PathBuf>,
    proof: VerifiedTransferProof,
    metadata: MetadataRequirements,
}

impl VerifiedReplacement {
    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the old destination's recovery artifact. It remains on disk
    /// until the run evidence layer records and settles the selected recovery
    /// policy; this transfer slice never silently trashes or removes it.
    pub fn previous_destination(&self) -> Option<&Path> {
        self.previous_destination.as_deref()
    }

    pub fn proof(&self) -> &VerifiedTransferProof {
        &self.proof
    }

    pub const fn metadata_requirements(&self) -> MetadataRequirements {
        self.metadata
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplacementError {
    Io(String),
    Transfer(String),
    ProcessExit { exit_code: Option<i32>, signal: Option<i32> },
    Verification(VerificationError),
    MetadataMismatch,
    Cancelled,
    RecoveryUncertain(String),
}

impl std::fmt::Display for ReplacementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(reason) => write!(formatter, "replacement filesystem error: {reason}"),
            Self::Transfer(reason) => write!(formatter, "transfer failed: {reason}"),
            Self::ProcessExit { exit_code, signal } => {
                write!(formatter, "controlled transfer exited with code {exit_code:?} and signal {signal:?}")
            }
            Self::Verification(error) => error.fmt(formatter),
            Self::MetadataMismatch => {
                formatter.write_str("transferred file type or executable permissions did not match")
            }
            Self::Cancelled => formatter.write_str("replacement was cancelled"),
            Self::RecoveryUncertain(reason) => {
                write!(formatter, "replacement recovery is uncertain: {reason}")
            }
        }
    }
}

impl std::error::Error for ReplacementError {}

impl From<VerificationError> for ReplacementError {
    fn from(error: VerificationError) -> Self {
        Self::Verification(error)
    }
}

fn map_verification_error(error: VerificationError) -> ReplacementError {
    if matches!(error, VerificationError::Cancelled) {
        ReplacementError::Cancelled
    } else {
        ReplacementError::Verification(error)
    }
}

fn check_cancelled<C>(should_cancel: &C) -> Result<(), ReplacementError>
where
    C: Fn() -> bool,
{
    if should_cancel() {
        Err(ReplacementError::Cancelled)
    } else {
        Ok(())
    }
}

/// Transfers one regular file through a same-directory temporary path and
/// returns only after the source and installed destination have independent
/// size and SHA-256 proof. The source is never removed by this function.
#[cfg(test)]
pub(crate) fn perform_verified_replacement<F>(
    source: &Path,
    destination: &Path,
    transfer: F,
) -> Result<VerifiedReplacement, ReplacementError>
where
    F: FnOnce(&Path) -> Result<(), ReplacementError>,
{
    perform_verified_replacement_with_cancel(source, destination, || false, transfer)
}

/// The cancellation-aware replacement boundary. Cancellation is checked at
/// every point where a transfer could otherwise cross into an installation or
/// rollback decision, and hashing uses the same callback while reading data.
#[cfg(test)]
pub(crate) fn perform_verified_replacement_with_cancel<C, F>(
    source: &Path,
    destination: &Path,
    should_cancel: C,
    transfer: F,
) -> Result<VerifiedReplacement, ReplacementError>
where
    C: Fn() -> bool,
    F: FnOnce(&Path) -> Result<(), ReplacementError>,
{
    perform_verified_replacement_with_cancel_and_metadata(
        source,
        destination,
        MetadataRequirements::default(),
        should_cancel,
        transfer,
    )
}

#[cfg(test)]
pub(crate) fn perform_verified_replacement_with_cancel_and_metadata<C, F>(
    source: &Path,
    destination: &Path,
    metadata: MetadataRequirements,
    should_cancel: C,
    transfer: F,
) -> Result<VerifiedReplacement, ReplacementError>
where
    C: Fn() -> bool,
    F: FnOnce(&Path) -> Result<(), ReplacementError>,
{
    perform_verified_replacement_with_cancel_and_metadata_and_partial(
        source,
        destination,
        metadata,
        PartialTransferPolicy::Cleanup,
        should_cancel,
        transfer,
    )
}

pub(crate) fn perform_verified_replacement_with_cancel_and_metadata_and_partial<C, F>(
    source: &Path,
    destination: &Path,
    metadata: MetadataRequirements,
    partial_policy: PartialTransferPolicy,
    should_cancel: C,
    transfer: F,
) -> Result<VerifiedReplacement, ReplacementError>
where
    C: Fn() -> bool,
    F: FnOnce(&Path) -> Result<(), ReplacementError>,
{
    check_cancelled(&should_cancel)?;
    let source_before = SourceObservation::capture_with_cancel(source, || should_cancel())
        .map_err(map_verification_error)?;
    let temporary_kind = match partial_policy {
        PartialTransferPolicy::Cleanup => "temporary",
        PartialTransferPolicy::KeepPartialForResume => "partial",
    };
    let temporary = temporary_sibling(destination, temporary_kind)?;
    create_empty_file(&temporary)?;

    if let Err(error) = transfer(&temporary) {
        return Err(cleanup_temporary_according_to_policy(
            &temporary,
            error,
            partial_policy,
        ));
    }
    if let Err(error) = check_cancelled(&should_cancel) {
        return Err(cleanup_temporary_according_to_policy(
            &temporary,
            error,
            partial_policy,
        ));
    }

    let result = (|| {
        check_cancelled(&should_cancel)?;
        sync_file(&temporary)?;
        let temporary_destination = verify_content_with_cancel(
            &temporary,
            &source_before.content(),
            || should_cancel(),
        )
        .map_err(map_verification_error)?;
        check_cancelled(&should_cancel)?;
        apply_metadata_requirements(&temporary, source_before.metadata(), metadata)?;
        let temporary_metadata = FileMetadataProof::capture(&temporary)?;
        if !source_before
            .metadata()
            .matches_transfer_metadata(&temporary_metadata, metadata)
        {
            return Err(ReplacementError::MetadataMismatch);
        }
        let source_after = SourceObservation::capture_with_cancel(source, || should_cancel())
            .map_err(map_verification_error)?;
        if source_after != source_before {
            return Err(VerificationError::SourceChanged.into());
        }
        check_cancelled(&should_cancel)?;

        let destination_exists = match fs::symlink_metadata(destination) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(io_error(error)),
        };
        let previous_destination = if destination_exists {
            let previous_metadata = FileMetadataProof::capture(destination).map_err(|error| {
                ReplacementError::RecoveryUncertain(format!(
                    "could not capture the previous destination before preservation: {error}"
                ))
            })?;
            let previous = temporary_sibling(destination, "previous")?;
            rename_without_replacement(destination, &previous).map_err(io_error)?;
            let moved_metadata = match FileMetadataProof::capture(&previous) {
                Ok(metadata) => metadata,
                Err(error) => {
                    return Err(restore_previous(
                        destination,
                        Some(&previous),
                        ReplacementError::RecoveryUncertain(format!(
                            "could not verify the preserved previous destination: {error}"
                        )),
                    ));
                }
            };
            if moved_metadata != previous_metadata {
                return Err(restore_previous(
                    destination,
                    Some(&previous),
                    ReplacementError::RecoveryUncertain(
                        "the previous destination changed while it was being preserved"
                            .to_owned(),
                    ),
                ));
            }
            Some(previous)
        } else {
            None
        };

        if let Err(error) = check_cancelled(&should_cancel) {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                None,
                None,
                error,
            ));
        }
        if let Err(error) = rename_without_replacement(&temporary, destination).map_err(io_error) {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                None,
                None,
                error,
            ));
        }

        let installed_metadata = match FileMetadataProof::capture(destination) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(restore_after_failed_install(
                    destination,
                    previous_destination.as_deref(),
                    None,
                    None,
                    ReplacementError::Verification(error),
                ));
            }
        };
        if !source_before
            .metadata()
            .matches_transfer_metadata(&installed_metadata, metadata)
        {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                Some(&installed_metadata),
                Some(source_before.content()),
                ReplacementError::MetadataMismatch,
            ));
        }

        if let Err(error) = check_cancelled(&should_cancel) {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                Some(&installed_metadata),
                Some(source_before.content()),
                error,
            ));
        }
        if let Err(error) = sync_file(destination) {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                Some(&installed_metadata),
                Some(source_before.content()),
                error,
            ));
        }

        let installed_destination = match verify_content_with_cancel(
            destination,
            &source_before.content(),
            || should_cancel(),
        )
        .map_err(map_verification_error)
        {
            Ok(proof) => proof,
            Err(error) => {
                return Err(restore_after_failed_install(
                    destination,
                    previous_destination.as_deref(),
                    Some(&installed_metadata),
                    Some(source_before.content()),
                    error,
                ));
            }
        };
        let final_installed_metadata = match FileMetadataProof::capture(destination) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(restore_after_failed_install(
                    destination,
                    previous_destination.as_deref(),
                    Some(&installed_metadata),
                    Some(source_before.content()),
                    ReplacementError::Verification(error),
                ));
            }
        };
        if final_installed_metadata != installed_metadata {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                Some(&installed_metadata),
                Some(source_before.content()),
                ReplacementError::RecoveryUncertain(
                    "the installed destination changed after final verification".to_owned(),
                ),
            ));
        }
        let final_source = match SourceObservation::capture_with_cancel(source, || should_cancel())
            .map_err(map_verification_error)
        {
            Ok(observation) => observation,
            Err(error) => {
                return Err(restore_after_failed_install(
                    destination,
                    previous_destination.as_deref(),
                    Some(&installed_metadata),
                    Some(source_before.content()),
                    error,
                ));
            }
        };
        if final_source != source_after {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                Some(&installed_metadata),
                Some(source_before.content()),
                ReplacementError::Verification(VerificationError::SourceChanged),
            ));
        }
        if should_cancel() {
            return Err(restore_after_failed_install(
                destination,
                previous_destination.as_deref(),
                Some(&installed_metadata),
                Some(source_before.content()),
                ReplacementError::Cancelled,
            ));
        }
        Ok(VerifiedReplacement {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            previous_destination,
            proof: VerifiedTransferProof::new(
                source_before,
                temporary_destination,
                final_source,
                installed_destination,
            ),
            metadata,
        })
    })();

    match result {
        Ok(replacement) => Ok(replacement),
        Err(error) => Err(cleanup_temporary_according_to_policy(
            &temporary,
            error,
            partial_policy,
        )),
    }
}

/// Remove only SyncPlus-owned incomplete transfer artifacts. These files are
/// intentionally hidden and excluded from analysis while they await a
/// resume; callers invoke this only after Fresh Analysis and before a new
/// verified transfer.
pub(crate) fn cleanup_partial_transfer_artifacts(root: &Path) -> io::Result<()> {
    fn visit(directory: &Path) -> io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_dir() {
                visit(&path)?;
            } else if metadata.file_type().is_file()
                && entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".syncplus-partial-")
            {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    visit(root)
}

fn apply_metadata_requirements(
    path: &Path,
    source: &FileMetadataProof,
    requirements: MetadataRequirements,
) -> Result<(), ReplacementError> {
    if requirements.timestamps() {
        let modified_at = source
            .modified_at()
            .ok_or(ReplacementError::MetadataMismatch)?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(io_error)?
            .set_modified(modified_at)
            .map_err(io_error)?;
    }
    Ok(())
}

fn restore_after_failed_install(
    destination: &Path,
    previous_destination: Option<&Path>,
    expected_metadata: Option<&FileMetadataProof>,
    expected_content: Option<crate::ContentProof>,
    original_error: ReplacementError,
) -> ReplacementError {
    let Some(expected_metadata) = expected_metadata else {
        if fs::symlink_metadata(destination).is_ok() {
            return ReplacementError::RecoveryUncertain(format!(
                "the installed destination could not be identified after {original_error}"
            ));
        }
        return restore_previous(destination, previous_destination, original_error);
    };

    let current_metadata = match FileMetadataProof::capture(destination) {
        Ok(metadata) if &metadata == expected_metadata => metadata,
        Ok(_) => {
            return ReplacementError::RecoveryUncertain(format!(
                "the installed destination changed before rollback after {original_error}"
            ));
        }
        Err(error) => {
            return ReplacementError::RecoveryUncertain(format!(
                "could not identify the installed destination before rollback after {original_error}: {error}"
            ));
        }
    };
    if current_metadata.item_type() != crate::ItemType::RegularFile {
        return ReplacementError::RecoveryUncertain(format!(
            "the installed destination changed type before rollback after {original_error}"
        ));
    }
    if let Some(expected_content) = expected_content {
        if let Err(error) = verify_content(destination, &expected_content) {
            return ReplacementError::RecoveryUncertain(format!(
                "the installed destination content changed before rollback after {original_error}: {error}"
            ));
        }
    }
    let failed_destination = match temporary_sibling(destination, "failed") {
        Ok(path) => path,
        Err(error) => {
            return ReplacementError::RecoveryUncertain(format!(
                "could not allocate a recovery path after {original_error}: {error}"
            ));
        }
    };
    if let Err(error) = rename_without_replacement(destination, &failed_destination) {
        return ReplacementError::RecoveryUncertain(format!(
            "could not preserve the failed installed destination after {original_error}: {error}"
        ));
    }
    match FileMetadataProof::capture(&failed_destination) {
        Ok(metadata) if &metadata == expected_metadata => {}
        Ok(_) => {
            return ReplacementError::RecoveryUncertain(format!(
                "the failed installed destination changed while being preserved after {original_error}"
            ));
        }
        Err(error) => {
            return ReplacementError::RecoveryUncertain(format!(
                "could not verify the preserved failed destination after {original_error}: {error}"
            ));
        }
    };
    if let Some(expected_content) = expected_content {
        if let Err(error) = verify_content(&failed_destination, &expected_content) {
            return ReplacementError::RecoveryUncertain(format!(
                "the preserved failed destination changed after {original_error}: {error}"
            ));
        }
    }
    if previous_destination.is_some() {
        restore_previous(destination, previous_destination, original_error)
    } else {
        ReplacementError::RecoveryUncertain(format!(
            "the failed installed destination was preserved at {:?} after {original_error}",
            failed_destination
        ))
    }
}

fn restore_previous(
    destination: &Path,
    previous_destination: Option<&Path>,
    original_error: ReplacementError,
) -> ReplacementError {
    if let Some(previous) = previous_destination {
        if let Err(error) = rename_without_replacement(previous, destination) {
            return ReplacementError::RecoveryUncertain(format!(
                "could not restore the previous destination after {original_error}: {error}"
            ));
        }
    }
    original_error
}

fn rename_without_replacement(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let source = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        let destination = CString::new(destination.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                1u32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is required on the supported Linux platform",
        ))
    }
}

fn cleanup_temporary(path: &Path, original_error: ReplacementError) -> ReplacementError {
    match fs::remove_file(path) {
        Ok(()) => original_error,
        Err(error) if error.kind() == io::ErrorKind::NotFound => original_error,
        Err(error) => ReplacementError::RecoveryUncertain(format!(
            "could not clean up the temporary destination after {original_error}: {error}"
        )),
    }
}

fn cleanup_temporary_according_to_policy(
    path: &Path,
    original_error: ReplacementError,
    policy: PartialTransferPolicy,
) -> ReplacementError {
    match policy {
        PartialTransferPolicy::Cleanup => cleanup_temporary(path, original_error),
        PartialTransferPolicy::KeepPartialForResume => original_error,
    }
}

fn create_empty_file(path: &Path) -> Result<(), ReplacementError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(|_| ())
        .map_err(io_error)
}

fn sync_file(path: &Path) -> Result<(), ReplacementError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}

fn io_error(error: io::Error) -> ReplacementError {
    ReplacementError::Io(error.to_string())
}

static NEXT_SIBLING: AtomicU64 = AtomicU64::new(1);

fn temporary_sibling(path: &Path, kind: &str) -> Result<PathBuf, ReplacementError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| ReplacementError::Io("destination has no file name".to_owned()))?;
    let sequence = NEXT_SIBLING.fetch_add(1, Ordering::Relaxed);
    let mut sibling = OsString::from(format!(
        ".syncplus-{kind}-{}-{sequence}-",
        std::process::id()
    ));
    sibling.push(file_name);
    Ok(parent.join(sibling))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::{
        cleanup_partial_transfer_artifacts, perform_verified_replacement,
        perform_verified_replacement_with_cancel,
        perform_verified_replacement_with_cancel_and_metadata_and_partial, ReplacementError,
    };
    use crate::{MetadataRequirements, PartialTransferPolicy};

    #[test]
    fn old_destination_survives_until_verified_replacement_is_installed() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"new destination").unwrap();
        fs::write(&destination, b"old destination").unwrap();

        let replacement = perform_verified_replacement(&source, &destination, |temporary| {
            fs::copy(&source, temporary).map(|_| ()).map_err(|error| {
                ReplacementError::Transfer(error.to_string())
            })
        })
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new destination");
        assert_eq!(
            fs::read(replacement.previous_destination().unwrap()).unwrap(),
            b"old destination"
        );
        assert_eq!(
            replacement.proof().source_before().content(),
            replacement.proof().installed_destination()
        );
        assert_eq!(fs::read(&source).unwrap(), b"new destination");
    }

    #[test]
    fn transfer_or_verification_failure_preserves_source_and_old_destination() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"source bytes").unwrap();
        fs::write(&destination, b"old bytes").unwrap();

        let error = perform_verified_replacement(&source, &destination, |temporary| {
            fs::write(temporary, b"wrong bytes").map_err(|error| {
                ReplacementError::Transfer(error.to_string())
            })
        })
        .expect_err("mismatched temporary data must fail closed");
        assert!(matches!(error, ReplacementError::Verification(_)));
        assert_eq!(fs::read(&source).unwrap(), b"source bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"old bytes");

        let error = perform_verified_replacement(&source, &destination, |_| {
            Err(ReplacementError::Cancelled)
        })
        .expect_err("cancellation must preserve both versions");
        assert_eq!(error, ReplacementError::Cancelled);
        assert_eq!(fs::read(&source).unwrap(), b"source bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"old bytes");
    }

    #[test]
    fn keep_partial_for_resume_is_explicit_hidden_and_cleaned_before_resume() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"complete source bytes").unwrap();
        fs::write(&destination, b"old destination bytes").unwrap();

        let error = perform_verified_replacement_with_cancel_and_metadata_and_partial(
            &source,
            &destination,
            MetadataRequirements::default(),
            PartialTransferPolicy::KeepPartialForResume,
            || false,
            |temporary| {
                fs::write(temporary, b"incomplete bytes").map_err(|error| {
                    ReplacementError::Transfer(error.to_string())
                })?;
                Err(ReplacementError::Transfer("transient transfer failure".to_owned()))
            },
        )
        .expect_err("failed transfer should not install partial content");
        assert!(matches!(error, ReplacementError::Transfer(_)));
        assert_eq!(fs::read(&source).unwrap(), b"complete source bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"old destination bytes");

        let partials: Vec<_> = fs::read_dir(&fixture.path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".syncplus-partial-")
            })
            .collect();
        assert_eq!(partials.len(), 1);
        cleanup_partial_transfer_artifacts(&fixture.path).unwrap();
        assert!(!partials[0].exists());
    }

    #[cfg(unix)]
    #[test]
    fn executable_permission_mismatch_preserves_source_and_destination() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.sh");
        let destination = fixture.path.join("destination.sh");
        fs::write(&source, b"#!/bin/sh\necho safe\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&destination, b"old script").unwrap();

        let error = perform_verified_replacement(&source, &destination, |temporary| {
            fs::copy(&source, temporary).map_err(|error| {
                ReplacementError::Transfer(error.to_string())
            })?;
            fs::set_permissions(temporary, fs::Permissions::from_mode(0o644))
                .map_err(|error| ReplacementError::Transfer(error.to_string()))
        })
        .expect_err("loss of executable permission must fail closed");

        assert_eq!(error, ReplacementError::MetadataMismatch);
        assert_eq!(fs::read(&source).unwrap(), b"#!/bin/sh\necho safe\n");
        assert_eq!(fs::read(&destination).unwrap(), b"old script");
    }

    #[test]
    fn cancellation_after_transfer_preserves_source_and_old_destination() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"new bytes").unwrap();
        fs::write(&destination, b"old bytes").unwrap();
        let cancelled = AtomicBool::new(false);

        let error = perform_verified_replacement_with_cancel(
            &source,
            &destination,
            || cancelled.load(Ordering::Relaxed),
            |temporary| {
                fs::copy(&source, temporary).map_err(|error| {
                    ReplacementError::Transfer(error.to_string())
                })?;
                cancelled.store(true, Ordering::Relaxed);
                Ok(())
            },
        )
        .expect_err("cancellation before verification must stop installation");

        assert_eq!(error, ReplacementError::Cancelled);
        assert_eq!(fs::read(&source).unwrap(), b"new bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"old bytes");
    }

    #[test]
    fn source_mutation_after_transfer_blocks_replacement_before_old_destination_moves() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"original").unwrap();
        fs::write(&destination, b"old").unwrap();

        let error = perform_verified_replacement(&source, &destination, |temporary| {
            fs::copy(&source, temporary).map_err(|error| {
                ReplacementError::Transfer(error.to_string())
            })?;
            fs::write(&source, b"mutated").map_err(|error| {
                ReplacementError::Transfer(error.to_string())
            })
        })
        .expect_err("source mutation must block replacement");
        assert!(matches!(error, ReplacementError::Verification(_)));
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert_eq!(fs::read(&source).unwrap(), b"mutated");
    }

    struct Fixture {
        path: PathBuf,
    }

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "syncplus-replacement-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
