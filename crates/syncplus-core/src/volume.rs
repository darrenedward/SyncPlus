use std::{
    fmt,
    fs,
    io,
    path::{Path, PathBuf},
};

use crate::{FileMetadataProof, VerificationError};

/// The operating-system identity of the filesystem containing a local peer.
///
/// On Linux this is the filesystem device number reported for the selected
/// directory. It is deliberately independent of the mount path, because a
/// different device can be mounted at the same path after a disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeIdentity {
    device: u64,
}

impl VolumeIdentity {
    pub const fn new(device: u64) -> Self {
        Self { device }
    }

    pub const fn device(self) -> u64 {
        self.device
    }

    /// Capture the identity of a real local directory without following a
    /// symlink at the selected peer root.
    pub fn capture(path: &Path) -> Result<Self, VolumeIdentityError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                VolumeIdentityError::Unavailable(path.to_path_buf())
            } else {
                VolumeIdentityError::Io {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                }
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(VolumeIdentityError::SymlinkRoot(path.to_path_buf()));
        }
        if !metadata.is_dir() {
            return Err(VolumeIdentityError::NotDirectory(path.to_path_buf()));
        }

        let identity = FileMetadataProof::capture(path)
            .map_err(VolumeIdentityError::Verification)?
            .identity()
            .ok_or_else(|| VolumeIdentityError::Unsupported(path.to_path_buf()))?;
        Ok(Self::new(identity.device()))
    }
}

impl fmt::Display for VolumeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "filesystem device {}", self.device)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeIdentityError {
    Unavailable(PathBuf),
    SymlinkRoot(PathBuf),
    NotDirectory(PathBuf),
    Unsupported(PathBuf),
    Verification(VerificationError),
    Io { path: PathBuf, detail: String },
}

impl fmt::Display for VolumeIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(path) => write!(formatter, "peer path is unavailable: {path:?}"),
            Self::SymlinkRoot(path) => {
                write!(formatter, "peer root must be a real directory, not a symlink: {path:?}")
            }
            Self::NotDirectory(path) => write!(formatter, "peer root is not a directory: {path:?}"),
            Self::Unsupported(path) => write!(
                formatter,
                "the operating system does not provide a stable volume identity for {path:?}"
            ),
            Self::Verification(error) => write!(formatter, "could not inspect peer identity: {error}"),
            Self::Io { path, detail } => {
                write!(formatter, "could not inspect peer identity for {path:?}: {detail}")
            }
        }
    }
}

impl std::error::Error for VolumeIdentityError {}
