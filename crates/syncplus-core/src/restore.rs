use std::{fs, io, path::{Component, Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

use crate::{ContentProof, FileIdentity, ItemType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProvenance {
    peer: String,
    original_root: PathBuf,
    relative_path: PathBuf,
    run_id: crate::RunId,
    removed_at_unix_nanos: i64,
    item_type: ItemType,
    content: Option<ContentProof>,
    source_identity: Option<FileIdentity>,
}

impl RecoveryProvenance {
    pub fn new(peer: impl Into<String>, original_root: PathBuf, relative_path: PathBuf, run_id: crate::RunId, item_type: ItemType, content: Option<ContentProof>, source_identity: Option<FileIdentity>) -> Result<Self, RestoreError> {
        validate_relative_path(&relative_path)?;
        Ok(Self { peer: peer.into(), original_root, relative_path, run_id, removed_at_unix_nanos: now(), item_type, content, source_identity })
    }
    pub fn peer(&self) -> &str { &self.peer }
    pub fn original_root(&self) -> &Path { &self.original_root }
    pub fn relative_path(&self) -> &Path { &self.relative_path }
    pub const fn run_id(&self) -> crate::RunId { self.run_id }
    pub const fn item_type(&self) -> ItemType { self.item_type }
    pub fn content(&self) -> Option<ContentProof> { self.content }
    pub const fn source_identity(&self) -> Option<FileIdentity> { self.source_identity }
    pub fn destination(&self) -> Result<PathBuf, RestoreError> {
        let root = fs::canonicalize(&self.original_root).map_err(io_error)?;
        let destination = root.join(&self.relative_path);
        if !destination.parent().is_some_and(|parent| parent.starts_with(&root)) {
            return Err(RestoreError::InvalidProvenance("recovery path escapes its original peer root".into()));
        }
        Ok(destination)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError { InvalidProvenance(String), SidecarInvalid(String), Collision(PathBuf, String), Io(String), Verification(String), Cancelled }
impl std::fmt::Display for RestoreError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Self::InvalidProvenance(s) => write!(f, "invalid recovery provenance: {s}"), Self::SidecarInvalid(s) => write!(f, "invalid recovery sidecar: {s}"), Self::Collision(p,s) => write!(f, "restore refused at {p:?}: {s}"), Self::Io(s) => write!(f, "restore filesystem error: {s}"), Self::Verification(s) => write!(f, "restore verification failed: {s}"), Self::Cancelled => f.write_str("restore cancelled") } } }
impl std::error::Error for RestoreError {}
fn io_error(e: io::Error) -> RestoreError { RestoreError::Io(e.to_string()) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome { Restored, AlreadyPresent }

pub struct CollisionSafeRestore;
impl CollisionSafeRestore {
    pub fn restore<C>(recovered: &Path, provenance: &RecoveryProvenance, should_cancel: C) -> Result<RestoreOutcome, RestoreError>
    where C: Fn() -> bool {
        validate_relative_path(provenance.relative_path())?;
        let destination = provenance.destination()?;
        let recovered_meta = fs::symlink_metadata(recovered).map_err(io_error)?;
        if provenance.item_type() != ItemType::RegularFile || !recovered_meta.file_type().is_file() {
            return Err(RestoreError::Verification("only regular-file restore is supported and the recovered item type must match provenance".into()));
        }
        if let Some(expected) = provenance.content() { let actual = ContentProof::from_path(recovered).map_err(|e| RestoreError::Verification(e.to_string()))?; if !expected.matches(&actual) { return Err(RestoreError::Verification("recovered content does not match provenance".into())); } }
        if let Ok(existing) = fs::symlink_metadata(&destination) {
            if provenance.item_type() == ItemType::RegularFile && existing.file_type().is_file() && provenance.content().is_some() {
                let actual = ContentProof::from_path(&destination).map_err(|e| RestoreError::Verification(e.to_string()))?;
                if provenance.content().is_some_and(|expected| expected.matches(&actual)) { return Ok(RestoreOutcome::AlreadyPresent); }
            }
            return Err(RestoreError::Collision(destination, "destination is newer, different, or lacks matching proof; no overwrite was performed".into()));
        }
        if should_cancel() { return Err(RestoreError::Cancelled); }
        let parent = destination.parent().ok_or_else(|| RestoreError::InvalidProvenance("destination has no parent".into()))?;
        fs::create_dir_all(parent).map_err(io_error)?;
        let name = destination.file_name().ok_or_else(|| RestoreError::InvalidProvenance("destination has no name".into()))?;
        let temporary = parent.join(format!(".syncplus-restore-{}", name.to_string_lossy()));
        if temporary.exists() { return Err(RestoreError::Collision(temporary, "restore temporary path already exists".into())); }
        fs::copy(recovered, &temporary).map_err(io_error)?;
        let result = (|| { if should_cancel() { return Err(RestoreError::Cancelled); } let actual = ContentProof::from_path(&temporary).map_err(|e| RestoreError::Verification(e.to_string()))?; if provenance.content().is_some_and(|expected| !expected.matches(&actual)) { return Err(RestoreError::Verification("temporary restore content changed before installation".into())); } fs::rename(&temporary, &destination).map_err(io_error)?; Ok(RestoreOutcome::Restored) })();
        if result.is_err() { let _ = fs::remove_file(&temporary); }
        result
    }
}

fn validate_relative_path(path: &Path) -> Result<(), RestoreError> { if path.as_os_str().is_empty() || path.is_absolute() || path.components().any(|c| !matches!(c, Component::Normal(_))) { return Err(RestoreError::InvalidProvenance("original path must be a non-empty normalized relative path".into())); } Ok(()) }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_nanos()).ok()).unwrap_or_default() }
