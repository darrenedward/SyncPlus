use std::{
    fmt,
    fs::{self, Metadata, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::{FileIdentity, ItemType, MetadataRequirements};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentProof {
    size: u64,
    sha256: [u8; 32],
}

impl ContentProof {
    pub const fn new(size: u64, sha256: [u8; 32]) -> Self {
        Self { size, sha256 }
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn from_path(path: &Path) -> Result<Self, VerificationError> {
        Self::from_path_with_cancel(path, || false)
    }

    pub fn from_path_with_cancel<F>(
        path: &Path,
        mut cancelled: F,
    ) -> Result<Self, VerificationError>
    where
        F: FnMut() -> bool,
    {
        let path_metadata = fs::symlink_metadata(path).map_err(io_error)?;
        if !path_metadata.file_type().is_file() {
            return Err(VerificationError::UnsupportedItem);
        }

        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(path).map_err(io_error)?;
        let opened_metadata = file.metadata().map_err(io_error)?;
        if !same_file_metadata(&path_metadata, &opened_metadata) {
            return Err(VerificationError::SourceChanged);
        }
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if cancelled() {
                return Err(VerificationError::Cancelled);
            }
            let read = file.read(&mut buffer).map_err(io_error)?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .ok_or(VerificationError::SizeOverflow)?;
            hasher.update(&buffer[..read]);
        }

        let finished_metadata = file.metadata().map_err(io_error)?;
        let path_after = fs::symlink_metadata(path).map_err(io_error)?;
        if !same_file_metadata(&opened_metadata, &finished_metadata)
            || !same_file_metadata(&path_metadata, &path_after)
        {
            return Err(VerificationError::SourceChanged);
        }

        Ok(Self {
            size,
            sha256: hasher.finalize().into(),
        })
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.size == other.size && self.sha256 == other.sha256
    }

    pub(crate) fn from_reader<R: Read>(reader: &mut R) -> Result<Self, VerificationError> {
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(io_error)?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .ok_or(VerificationError::SizeOverflow)?;
            hasher.update(&buffer[..read]);
        }
        Ok(Self {
            size,
            sha256: hasher.finalize().into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadataProof {
    item_type: ItemType,
    size: u64,
    modified_at_unix_nanos: Option<i64>,
    identity: Option<FileIdentity>,
    permissions: Option<u32>,
    symlink_target: Option<PathBuf>,
}

impl FileMetadataProof {
    pub fn capture(path: &Path) -> Result<Self, VerificationError> {
        let metadata = fs::symlink_metadata(path).map_err(io_error)?;
        Ok(Self::from_metadata(path, &metadata))
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn modified_at_unix_nanos(&self) -> Option<i64> {
        self.modified_at_unix_nanos
    }

    pub const fn identity(&self) -> Option<FileIdentity> {
        self.identity
    }

    pub const fn permissions(&self) -> Option<u32> {
        self.permissions
    }

    pub fn symlink_target(&self) -> Option<&Path> {
        self.symlink_target.as_deref()
    }

    fn same_as(&self, other: &Self) -> bool {
        self == other
    }

    pub(crate) fn matches_transfer_metadata(
        &self,
        other: &Self,
        requirements: MetadataRequirements,
    ) -> bool {
        (!requirements.file_type() || self.item_type == other.item_type)
            && (!requirements.symlink_targets() || self.symlink_target == other.symlink_target)
            && (!requirements.executable_permissions()
                || executable_permissions(self.permissions)
                    == executable_permissions(other.permissions))
            && (!requirements.timestamps()
                || self.modified_at_unix_nanos == other.modified_at_unix_nanos)
    }

    pub(crate) fn matches_open_file_metadata(&self, metadata: &Metadata) -> bool {
        self.item_type == ItemType::RegularFile
            && metadata.file_type().is_file()
            && self.size == metadata.len()
            && self.modified_at_unix_nanos == modified_at_unix_nanos(metadata)
            && self.identity == file_identity(metadata)
            && self.permissions == permissions(metadata)
    }

    pub(crate) fn matches_open_transfer_metadata(
        &self,
        metadata: &Metadata,
        requirements: MetadataRequirements,
    ) -> bool {
        (!requirements.file_type() || self.item_type == ItemType::RegularFile)
            && (!requirements.file_type() || metadata.file_type().is_file())
            && (!requirements.executable_permissions()
                || executable_permissions(self.permissions)
                    == executable_permissions(permissions(metadata)))
            && (!requirements.timestamps()
                || self.modified_at_unix_nanos == modified_at_unix_nanos(metadata))
    }

    pub(crate) fn modified_at(&self) -> Option<SystemTime> {
        let nanos = self.modified_at_unix_nanos?;
        if nanos >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_nanos(nanos as u64))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_nanos(nanos.unsigned_abs()))
        }
    }

    fn from_metadata(path: &Path, metadata: &Metadata) -> Self {
        let item_type = if metadata.file_type().is_file() {
            ItemType::RegularFile
        } else if metadata.file_type().is_dir() {
            ItemType::Directory
        } else if metadata.file_type().is_symlink() {
            ItemType::Symlink
        } else {
            ItemType::Unsupported
        };

        Self {
            item_type,
            size: metadata.len(),
            modified_at_unix_nanos: modified_at_unix_nanos(metadata),
            identity: file_identity(metadata),
            permissions: permissions(metadata),
            symlink_target: if item_type == ItemType::Symlink {
                fs::read_link(path).ok()
            } else {
                None
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceObservation {
    metadata: FileMetadataProof,
    content: Option<ContentProof>,
}

impl SourceObservation {
    pub fn capture(path: &Path) -> Result<Self, VerificationError> {
        Self::capture_with_cancel(path, || false)
    }

    pub fn capture_with_cancel<F>(
        path: &Path,
        mut cancelled: F,
    ) -> Result<Self, VerificationError>
    where
        F: FnMut() -> bool,
    {
        let before = FileMetadataProof::capture(path)?;
        if before.item_type == ItemType::Unsupported {
            return Err(VerificationError::UnsupportedItem);
        }
        let content = if before.item_type == ItemType::RegularFile {
            Some(ContentProof::from_path_with_cancel(path, &mut cancelled)?)
        } else {
            None
        };
        let after = FileMetadataProof::capture(path)?;
        if !before.same_as(&after)
            || content.is_some_and(|content| before.size != content.size)
        {
            return Err(VerificationError::SourceChanged);
        }
        Ok(Self {
            metadata: before,
            content,
        })
    }

    pub fn metadata(&self) -> &FileMetadataProof {
        &self.metadata
    }

    pub fn content(&self) -> ContentProof {
        self.content
            .expect("content proofs are only available for regular files")
    }

    pub const fn content_proof(&self) -> Option<ContentProof> {
        self.content
    }

    pub fn recheck(&self, path: &Path) -> Result<(), VerificationError> {
        let current = Self::capture(path)?;
        if self.metadata.same_as(&current.metadata)
            && match (self.content, current.content) {
                (Some(expected), Some(actual)) => expected.matches(&actual),
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
        {
            Ok(())
        } else {
            Err(VerificationError::SourceChanged)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransferProof {
    source_before: SourceObservation,
    temporary_destination: Option<ContentProof>,
    source_after: SourceObservation,
    installed_destination: Option<ContentProof>,
}

impl VerifiedTransferProof {
    pub(crate) fn new(
        source_before: SourceObservation,
        temporary_destination: Option<ContentProof>,
        source_after: SourceObservation,
        installed_destination: Option<ContentProof>,
    ) -> Self {
        Self {
            source_before,
            temporary_destination,
            source_after,
            installed_destination,
        }
    }

    pub fn source_before(&self) -> &SourceObservation {
        &self.source_before
    }

    pub fn temporary_destination(&self) -> ContentProof {
        self.temporary_destination
            .expect("content proofs are only available for regular files")
    }

    pub const fn temporary_destination_proof(&self) -> Option<ContentProof> {
        self.temporary_destination
    }

    pub fn source_after(&self) -> &SourceObservation {
        &self.source_after
    }

    pub fn installed_destination(&self) -> ContentProof {
        self.installed_destination
            .expect("content proofs are only available for regular files")
    }

    pub const fn installed_destination_proof(&self) -> Option<ContentProof> {
        self.installed_destination
    }

}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    Io(String),
    Cancelled,
    UnsupportedItem,
    SourceChanged,
    SizeMismatch { expected: u64, actual: u64 },
    HashMismatch,
    SizeOverflow,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(reason) => write!(formatter, "filesystem verification failed: {reason}"),
            Self::Cancelled => formatter.write_str("verification was cancelled"),
            Self::UnsupportedItem => formatter.write_str("only regular files can be transferred"),
            Self::SourceChanged => formatter.write_str("source changed during verification"),
            Self::SizeMismatch { expected, actual } => {
                write!(formatter, "size mismatch: expected {expected}, observed {actual}")
            }
            Self::HashMismatch => formatter.write_str("SHA-256 verification mismatch"),
            Self::SizeOverflow => formatter.write_str("file size exceeded supported range"),
        }
    }
}

impl std::error::Error for VerificationError {}

pub fn verify_content(
    path: &Path,
    expected: &ContentProof,
) -> Result<ContentProof, VerificationError> {
    verify_content_with_cancel(path, expected, || false)
}

pub fn verify_content_with_cancel<F>(
    path: &Path,
    expected: &ContentProof,
    cancelled: F,
) -> Result<ContentProof, VerificationError>
where
    F: FnMut() -> bool,
{
    let actual = ContentProof::from_path_with_cancel(path, cancelled)?;
    if actual.size != expected.size {
        return Err(VerificationError::SizeMismatch {
            expected: expected.size,
            actual: actual.size,
        });
    }
    if actual.sha256 != expected.sha256 {
        return Err(VerificationError::HashMismatch);
    }
    Ok(actual)
}

fn io_error(error: io::Error) -> VerificationError {
    VerificationError::Io(error.to_string())
}

fn same_file_metadata(left: &Metadata, right: &Metadata) -> bool {
    file_identity(left) == file_identity(right)
        && left.file_type() == right.file_type()
        && left.len() == right.len()
        && modified_at_unix_nanos(left) == modified_at_unix_nanos(right)
        && permissions(left) == permissions(right)
}

fn executable_permissions(permissions: Option<u32>) -> Option<u32> {
    permissions.map(|value| value & 0o111)
}

fn modified_at_unix_nanos(metadata: &Metadata) -> Option<i64> {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity::new(metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(unix)]
fn permissions(metadata: &Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.mode() & 0o7777)
}

#[cfg(not(unix))]
fn permissions(_metadata: &Metadata) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

    use super::{verify_content, ContentProof, SourceObservation, VerificationError};

    #[test]
    fn independently_verifies_size_and_sha256() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"same bytes").unwrap();
        fs::write(&destination, b"same bytes").unwrap();
        let source_proof = SourceObservation::capture(&source).unwrap();
        let destination_proof = verify_content(&destination, &source_proof.content()).unwrap();
        assert_eq!(destination_proof, source_proof.content());
    }

    #[test]
    fn same_size_different_content_is_not_proof() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        let destination = fixture.path.join("destination.txt");
        fs::write(&source, b"source!").unwrap();
        fs::write(&destination, b"changed").unwrap();
        let proof = SourceObservation::capture(&source).unwrap();
        assert!(matches!(
            verify_content(&destination, &proof.content()),
            Err(VerificationError::HashMismatch)
        ));
    }

    #[test]
    fn source_identity_and_content_mutation_fail_recheck() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        fs::write(&source, b"original").unwrap();
        let observation = SourceObservation::capture(&source).unwrap();
        fs::write(&source, b"mutated!").unwrap();
        assert!(matches!(
            observation.recheck(&source),
            Err(VerificationError::SourceChanged)
        ));
    }

    #[test]
    fn hashing_is_cancellation_aware() {
        let fixture = Fixture::new();
        let source = fixture.path.join("source.txt");
        fs::write(&source, b"original").unwrap();
        let cancelled = ContentProof::from_path_with_cancel(&source, || true);
        assert!(matches!(cancelled, Err(VerificationError::Cancelled)));
    }

    struct Fixture {
        path: PathBuf,
    }

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "syncplus-verification-{}-{}",
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
