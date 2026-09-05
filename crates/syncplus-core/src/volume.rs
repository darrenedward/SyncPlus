use std::{
    fmt, fs, io,
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
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| VolumeIdentityError::from_metadata_io(path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(VolumeIdentityError::SymlinkRoot(path.to_path_buf()));
        }
        if !metadata.is_dir() {
            return Err(VolumeIdentityError::NotDirectory(path.to_path_buf()));
        }

        let identity = match FileMetadataProof::capture(path) {
            Ok(proof) => proof
                .identity()
                .ok_or_else(|| VolumeIdentityError::Unsupported(path.to_path_buf()))?,
            Err(error) if verification_means_unavailable(&error) => {
                return Err(VolumeIdentityError::Unavailable(path.to_path_buf()));
            }
            Err(error) => return Err(VolumeIdentityError::Verification(error)),
        };
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
                write!(
                    formatter,
                    "peer root must be a real directory, not a symlink: {path:?}"
                )
            }
            Self::NotDirectory(path) => write!(formatter, "peer root is not a directory: {path:?}"),
            Self::Unsupported(path) => write!(
                formatter,
                "the operating system does not provide a stable volume identity for {path:?}"
            ),
            Self::Verification(error) => {
                write!(formatter, "could not inspect peer identity: {error}")
            }
            Self::Io { path, detail } => {
                write!(
                    formatter,
                    "could not inspect peer identity for {path:?}: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for VolumeIdentityError {}

impl VolumeIdentityError {
    fn from_metadata_io(path: &Path, error: io::Error) -> Self {
        if io_error_means_unavailable(&error) {
            Self::Unavailable(path.to_path_buf())
        } else {
            Self::Io {
                path: path.to_path_buf(),
                detail: error.to_string(),
            }
        }
    }

    pub(crate) fn indicates_unavailable_peer(&self) -> bool {
        match self {
            Self::Unavailable(_) => true,
            Self::Io { detail, .. } => io_message_means_unavailable(detail),
            Self::Verification(error) => io_message_means_unavailable(&error.to_string()),
            _ => false,
        }
    }
}

/// Missing, unplugged, or stale mounts are unavailability, not a probe crash.
pub(crate) fn io_error_means_unavailable(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::ENODEV | libc::ENXIO | libc::ESTALE)
        ) || {
            #[cfg(target_os = "linux")]
            {
                error.raw_os_error() == Some(libc::ENOMEDIUM)
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn io_message_means_unavailable(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("no such device")
        || lower.contains("os error 19")
        || lower.contains("no medium found")
        || lower.contains("stale file handle")
        || lower.contains("no such file or directory")
}

fn verification_means_unavailable(error: &VerificationError) -> bool {
    matches!(error, VerificationError::Io(reason) if io_message_means_unavailable(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_device_os_errors_mean_the_peer_is_unavailable() {
        assert!(io_error_means_unavailable(&io::Error::from_raw_os_error(
            libc::ENODEV
        )));
        assert!(io_error_means_unavailable(&io::Error::from_raw_os_error(
            libc::ENXIO
        )));
        assert!(io_error_means_unavailable(&io::Error::from_raw_os_error(
            libc::ESTALE
        )));
        assert!(io_error_means_unavailable(&io::Error::from_raw_os_error(
            libc::ENOENT
        )));
        assert!(!io_error_means_unavailable(&io::Error::from_raw_os_error(
            libc::EACCES
        )));
    }

    #[test]
    fn capture_of_a_missing_path_is_unavailable() {
        let path = Path::new("/syncplus-missing-volume-identity-path");
        assert!(matches!(
            VolumeIdentity::capture(path),
            Err(VolumeIdentityError::Unavailable(_))
        ));
    }
}
