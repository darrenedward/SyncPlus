use std::{
    collections::BTreeMap,
    fs,
    io,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

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
        validate_original_root(&original_root)?;
        let peer = peer.into();
        validate_peer(&peer)?;
        Ok(Self { peer, original_root, relative_path, run_id, removed_at_unix_nanos: now(), item_type, content, source_identity })
    }
    pub fn peer(&self) -> &str { &self.peer }
    pub fn original_root(&self) -> &Path { &self.original_root }
    pub fn relative_path(&self) -> &Path { &self.relative_path }
    pub const fn run_id(&self) -> crate::RunId { self.run_id }
    pub const fn removed_at_unix_nanos(&self) -> i64 { self.removed_at_unix_nanos }
    pub const fn item_type(&self) -> ItemType { self.item_type }
    pub fn content(&self) -> Option<ContentProof> { self.content }
    pub const fn source_identity(&self) -> Option<FileIdentity> { self.source_identity }

    pub(crate) fn from_record(
        peer: String,
        original_root: PathBuf,
        relative_path: PathBuf,
        run_id: crate::RunId,
        removed_at_unix_nanos: i64,
        item_type: ItemType,
        content: Option<ContentProof>,
        source_identity: Option<FileIdentity>,
    ) -> Result<Self, RestoreError> {
        validate_relative_path(&relative_path)?;
        validate_original_root(&original_root)?;
        validate_peer(&peer)?;
        Ok(Self {
            peer,
            original_root,
            relative_path,
            run_id,
            removed_at_unix_nanos,
            item_type,
            content,
            source_identity,
        })
    }
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
        let marker = "\nchecksum=";
        let marker_position = contents
            .rfind(marker)
            .ok_or_else(|| RestoreError::SidecarInvalid("checksum is missing".into()))?;
        let payload = &contents[..marker_position + 1];
        let checksum = contents[marker_position + 1..]
            .strip_prefix("checksum=")
            .and_then(|value| value.strip_suffix('\n'))
            .ok_or_else(|| RestoreError::SidecarInvalid("sidecar is malformed".into()))?;
        if checksum.len() != 64
            || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
            || digest_text(payload) != checksum
        {
            return Err(RestoreError::SidecarInvalid(
                "sidecar integrity check failed".into(),
            ));
        }
        let mut values = BTreeMap::new();
        for line in payload.lines() {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| RestoreError::SidecarInvalid("sidecar field is malformed".into()))?;
            if !matches!(
                key,
                "peer_hex"
                    | "root_hex"
                    | "relative_hex"
                    | "run_id"
                    | "removed_at_unix_nanos"
                    | "item_type"
                    | "content"
                    | "source_identity"
            ) || values.insert(key, value).is_some()
            {
                return Err(RestoreError::SidecarInvalid(
                    "sidecar has an unknown or duplicate field".into(),
                ));
            }
        }
        let peer = decode_string(values.get("peer_hex").copied().ok_or_else(|| {
            RestoreError::SidecarInvalid("peer is missing".into())
        })?)?;
        let root = decode_path(values.get("root_hex").copied().ok_or_else(|| {
            RestoreError::SidecarInvalid("original root is missing".into())
        })?)?;
        let relative = decode_path(values.get("relative_hex").copied().ok_or_else(|| {
            RestoreError::SidecarInvalid("relative path is missing".into())
        })?)?;
        let run_id = values
            .get("run_id")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| RestoreError::SidecarInvalid("run id is invalid".into()))?;
        let removed_at_unix_nanos = values
            .get("removed_at_unix_nanos")
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| RestoreError::SidecarInvalid("removal time is invalid".into()))?;
        let item_type = match values.get("item_type").copied() {
            Some("regular_file") => ItemType::RegularFile,
            Some("directory") => ItemType::Directory,
            Some("symlink") => ItemType::Symlink,
            Some("unsupported") => ItemType::Unsupported,
            _ => return Err(RestoreError::SidecarInvalid("item type is invalid".into())),
        };
        let content = values
            .get("content")
            .filter(|value| !value.is_empty())
            .map(|value| parse_content(value))
            .transpose()?;
        let source_identity = values
            .get("source_identity")
            .filter(|value| !value.is_empty())
            .map(|value| parse_identity(value))
            .transpose()?;
        Self::from_record(
            peer,
            root,
            relative,
            crate::RunId::new(run_id),
            removed_at_unix_nanos,
            item_type,
            content,
            source_identity,
        )
        .map_err(|error| RestoreError::SidecarInvalid(error.to_string()))
    }

    fn sidecar_payload(&self) -> String {
        let item_type = match self.item_type { ItemType::RegularFile => "regular_file", ItemType::Directory => "directory", ItemType::Symlink => "symlink", ItemType::Unsupported => "unsupported" };
        let content = self.content.map(|proof| format!("{}:{}", proof.size(), hex_hash(proof.sha256()))).unwrap_or_default();
        let identity = self.source_identity.map(|identity| format!("{}:{}", identity.device(), identity.inode())).unwrap_or_default();
        format!("peer_hex={}\nroot_hex={}\nrelative_hex={}\nrun_id={}\nremoved_at_unix_nanos={}\nitem_type={}\ncontent={}\nsource_identity={}\n", encode_string(&self.peer), encode_path(&self.original_root), encode_path(&self.relative_path), self.run_id.value(), self.removed_at_unix_nanos, item_type, content, identity)
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
fn validate_original_root(path: &Path) -> Result<(), RestoreError> { if path.as_os_str().is_empty() { return Err(RestoreError::InvalidProvenance("original peer root must be non-empty".into())); } Ok(()) }
fn validate_peer(peer: &str) -> Result<(), RestoreError> { if peer.trim().is_empty() || peer.chars().any(|character| character == '\n' || character == '\r') { return Err(RestoreError::InvalidProvenance("recovery peer is missing or malformed".into())); } Ok(()) }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_nanos()).ok()).unwrap_or_default() }
fn digest_text(value: &str) -> String { let mut digest = Sha256::new(); digest.update(value.as_bytes()); digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect() }

fn encode_bytes(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn decode_bytes(value: &str) -> Result<Vec<u8>, RestoreError> { if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(RestoreError::SidecarInvalid("encoded sidecar value is invalid".into())); } value.as_bytes().chunks_exact(2).map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or_default(), 16).map_err(|_| RestoreError::SidecarInvalid("encoded sidecar value is invalid".into()))).collect() }
fn encode_string(value: &str) -> String { encode_bytes(value.as_bytes()) }
fn decode_string(value: &str) -> Result<String, RestoreError> { String::from_utf8(decode_bytes(value)?).map_err(|_| RestoreError::SidecarInvalid("peer is not valid UTF-8".into())) }
fn encode_path(path: &Path) -> String {
    #[cfg(unix)]
    { encode_bytes(path.as_os_str().as_bytes()) }
    #[cfg(not(unix))]
    { encode_string(&path.as_os_str().to_string_lossy()) }
}
fn decode_path(value: &str) -> Result<PathBuf, RestoreError> {
    let bytes = decode_bytes(value)?;
    #[cfg(unix)]
    { Ok(PathBuf::from(OsString::from_vec(bytes))) }
    #[cfg(not(unix))]
    { String::from_utf8(bytes).map(PathBuf::from).map_err(|_| RestoreError::SidecarInvalid("path is not valid for this platform".into())) }
}

fn hex_hash(hash: &[u8; 32]) -> String { hash.iter().map(|byte| format!("{byte:02x}")).collect() }

fn parse_content(value: &str) -> Result<ContentProof, RestoreError> {
    let (size, hash) = value.split_once(':').ok_or_else(|| RestoreError::SidecarInvalid("content proof is malformed".into()))?;
    let size = size.parse().map_err(|_| RestoreError::SidecarInvalid("content size is invalid".into()))?;
    let bytes = hash.as_bytes();
    if bytes.len() != 64 { return Err(RestoreError::SidecarInvalid("content digest is invalid".into())); }
    let mut digest = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|_| RestoreError::SidecarInvalid("content digest is invalid".into()))?, 16).map_err(|_| RestoreError::SidecarInvalid("content digest is invalid".into()))?;
    }
    Ok(ContentProof::new(size, digest))
}

fn parse_identity(value: &str) -> Result<FileIdentity, RestoreError> {
    let (device, inode) = value.split_once(':').ok_or_else(|| RestoreError::SidecarInvalid("source identity is malformed".into()))?;
    Ok(FileIdentity::new(
        device.parse().map_err(|_| RestoreError::SidecarInvalid("source device is invalid".into()))?,
        inode.parse().map_err(|_| RestoreError::SidecarInvalid("source inode is invalid".into()))?,
    ))
}
