use std::{fs, io, path::{Component, Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

use crate::{ContentProof, FileIdentity, ItemType};
use sha2::{Digest, Sha256};

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

    /// Write a validated, content-free provenance sidecar for custom Trash.
    pub fn write_sidecar(&self, path: &Path) -> Result<(), RestoreError> {
        let payload = self.sidecar_payload();
        let checksum = digest_text(&payload);
        let contents = format!("{payload}checksum={checksum}\n");
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(io_error)?;
        use io::Write;
        file.write_all(contents.as_bytes()).map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }

    pub fn read_sidecar(path: &Path) -> Result<Self, RestoreError> {
        let contents = fs::read_to_string(path).map_err(io_error)?;
        let checksum = contents.lines().find_map(|line| line.strip_prefix("checksum=")).ok_or_else(|| RestoreError::SidecarInvalid("checksum is missing".into()))?;
        let payload = contents.strip_suffix(&format!("checksum={checksum}\n")).ok_or_else(|| RestoreError::SidecarInvalid("sidecar is malformed".into()))?;
        if digest_text(payload) != checksum { return Err(RestoreError::SidecarInvalid("sidecar integrity check failed".into())); }
        let values: std::collections::BTreeMap<_, _> = payload.lines().filter_map(|line| line.split_once('=')).collect();
        let root = PathBuf::from(values.get("root").ok_or_else(|| RestoreError::SidecarInvalid("original root is missing".into()))?);
        let relative = PathBuf::from(values.get("relative").ok_or_else(|| RestoreError::SidecarInvalid("relative path is missing".into()))?);
        let run_id = values.get("run_id").and_then(|v| v.parse().ok()).ok_or_else(|| RestoreError::SidecarInvalid("run id is invalid".into()))?;
        let item_type = match values.get("item_type").copied() { Some("regular_file") => ItemType::RegularFile, Some("directory") => ItemType::Directory, Some("symlink") => ItemType::Symlink, _ => return Err(RestoreError::SidecarInvalid("item type is invalid".into())) };
        Self::new(values.get("peer").copied().unwrap_or_default(), root, relative, crate::RunId::new(run_id), item_type, None, None).map_err(|e| RestoreError::SidecarInvalid(e.to_string()))
    }

    fn sidecar_payload(&self) -> String {
        let item_type = match self.item_type { ItemType::RegularFile => "regular_file", ItemType::Directory => "directory", ItemType::Symlink => "symlink", ItemType::Unsupported => "unsupported" };
        format!("peer={}\nroot={}\nrelative={}\nrun_id={}\nitem_type={}\n", self.peer, self.original_root.display(), self.relative_path.display(), self.run_id.value(), item_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError { InvalidProvenance(String), SidecarInvalid(String), Collision(PathBuf, String), Io(String), Verification(String), Cancelled }
impl std::fmt::Display for RestoreError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Self::InvalidProvenance(s) => write!(f, "invalid recovery provenance: {s}"), Self::SidecarInvalid(s) => write!(f, "invalid recovery sidecar: {s}"), Self::Collision(p,s) => write!(f, "restore refused at {p:?}: {s}"), Self::Io(s) => write!(f, "restore filesystem error: {s}"), Self::Verification(s) => write!(f, "restore verification failed: {s}"), Self::Cancelled => f.write_str("restore cancelled") } } }
impl std::error::Error for RestoreError {}
fn io_error(e: io::Error) -> RestoreError { RestoreError::Io(e.to_string()) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome { Restored, AlreadyPresent }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreJournalEvent { Decision { run_id: crate::RunId, path: PathBuf }, Completed { run_id: crate::RunId, path: PathBuf, outcome: RestoreOutcome }, Refused { run_id: crate::RunId, path: PathBuf, reason: String } }

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

    pub fn restore_with_journal<C, J>(recovered: &Path, provenance: &RecoveryProvenance, should_cancel: C, mut journal: J) -> Result<RestoreOutcome, RestoreError>
    where C: Fn() -> bool, J: FnMut(RestoreJournalEvent) {
        let path = provenance.destination()?;
        journal(RestoreJournalEvent::Decision { run_id: provenance.run_id(), path: path.clone() });
        match Self::restore(recovered, provenance, should_cancel) {
            Ok(outcome) => { journal(RestoreJournalEvent::Completed { run_id: provenance.run_id(), path, outcome }); Ok(outcome) }
            Err(error) => { journal(RestoreJournalEvent::Refused { run_id: provenance.run_id(), path, reason: error.to_string() }); Err(error) }
        }
    }
}

fn validate_relative_path(path: &Path) -> Result<(), RestoreError> { if path.as_os_str().is_empty() || path.is_absolute() || path.components().any(|c| !matches!(c, Component::Normal(_))) { return Err(RestoreError::InvalidProvenance("original path must be a non-empty normalized relative path".into())); } Ok(()) }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_nanos()).ok()).unwrap_or_default() }
fn digest_text(value: &str) -> String { let mut digest = Sha256::new(); digest.update(value.as_bytes()); digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect() }
