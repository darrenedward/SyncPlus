use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::{ContentProof, DeletionMethod, FileIdentity, ItemType};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryVerificationState {
    Verified,
    ReviewRequired,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProvenance {
    action_id: Option<crate::ActionId>,
    peer: String,
    original_root: PathBuf,
    relative_path: PathBuf,
    run_id: crate::RunId,
    removed_at_unix_nanos: i64,
    recovery_method: DeletionMethod,
    verification_state: RecoveryVerificationState,
    item_type: ItemType,
    content: Option<ContentProof>,
    source_identity: Option<FileIdentity>,
    symlink_target: Option<PathBuf>,
}

impl RecoveryProvenance {
    pub fn new(
        peer: impl Into<String>,
        original_root: PathBuf,
        relative_path: PathBuf,
        run_id: crate::RunId,
        item_type: ItemType,
        content: Option<ContentProof>,
        source_identity: Option<FileIdentity>,
    ) -> Result<Self, RestoreError> {
        Self::new_with_details(
            None,
            peer,
            original_root,
            relative_path,
            run_id,
            DeletionMethod::Trash,
            RecoveryVerificationState::Verified,
            item_type,
            content,
            source_identity,
            None,
        )
    }

    pub fn new_for_action(
        action_id: crate::ActionId,
        peer: impl Into<String>,
        original_root: PathBuf,
        relative_path: PathBuf,
        run_id: crate::RunId,
        recovery_method: DeletionMethod,
        item_type: ItemType,
        content: Option<ContentProof>,
        source_identity: Option<FileIdentity>,
    ) -> Result<Self, RestoreError> {
        Self::new_for_action_with_target(
            action_id,
            peer,
            original_root,
            relative_path,
            run_id,
            recovery_method,
            item_type,
            content,
            source_identity,
            None,
        )
    }

    pub fn new_for_action_with_target(
        action_id: crate::ActionId,
        peer: impl Into<String>,
        original_root: PathBuf,
        relative_path: PathBuf,
        run_id: crate::RunId,
        recovery_method: DeletionMethod,
        item_type: ItemType,
        content: Option<ContentProof>,
        source_identity: Option<FileIdentity>,
        symlink_target: Option<PathBuf>,
    ) -> Result<Self, RestoreError> {
        Self::new_with_details(
            Some(action_id),
            peer,
            original_root,
            relative_path,
            run_id,
            recovery_method,
            RecoveryVerificationState::Verified,
            item_type,
            content,
            source_identity,
            symlink_target,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_details(
        action_id: Option<crate::ActionId>,
        peer: impl Into<String>,
        original_root: PathBuf,
        relative_path: PathBuf,
        run_id: crate::RunId,
        recovery_method: DeletionMethod,
        verification_state: RecoveryVerificationState,
        item_type: ItemType,
        content: Option<ContentProof>,
        source_identity: Option<FileIdentity>,
        symlink_target: Option<PathBuf>,
    ) -> Result<Self, RestoreError> {
        validate_relative_path(&relative_path)?;
        validate_original_root(&original_root)?;
        let peer = peer.into();
        validate_peer(&peer)?;
        if item_type == ItemType::Symlink && symlink_target.is_none() {
            return Err(RestoreError::InvalidProvenance(
                "symlink recovery provenance is missing its target".into(),
            ));
        }
        Ok(Self {
            action_id,
            peer,
            original_root,
            relative_path,
            run_id,
            removed_at_unix_nanos: now(),
            recovery_method,
            verification_state,
            item_type,
            content,
            source_identity,
            symlink_target,
        })
    }

    pub const fn action_id(&self) -> Option<crate::ActionId> {
        self.action_id
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    pub fn original_root(&self) -> &Path {
        &self.original_root
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn run_id(&self) -> crate::RunId {
        self.run_id
    }

    pub const fn removed_at_unix_nanos(&self) -> i64 {
        self.removed_at_unix_nanos
    }

    pub const fn recovery_method(&self) -> DeletionMethod {
        self.recovery_method
    }

    pub const fn verification_state(&self) -> RecoveryVerificationState {
        self.verification_state
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
    }

    pub fn content(&self) -> Option<ContentProof> {
        self.content
    }

    pub const fn source_identity(&self) -> Option<FileIdentity> {
        self.source_identity
    }

    pub fn symlink_target(&self) -> Option<&Path> {
        self.symlink_target.as_deref()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_record_with_details(
        action_id: Option<crate::ActionId>,
        peer: String,
        original_root: PathBuf,
        relative_path: PathBuf,
        run_id: crate::RunId,
        removed_at_unix_nanos: i64,
        recovery_method: DeletionMethod,
        verification_state: RecoveryVerificationState,
        item_type: ItemType,
        content: Option<ContentProof>,
        source_identity: Option<FileIdentity>,
        symlink_target: Option<PathBuf>,
    ) -> Result<Self, RestoreError> {
        validate_relative_path(&relative_path)?;
        validate_original_root(&original_root)?;
        validate_peer(&peer)?;
        Ok(Self {
            action_id,
            peer,
            original_root,
            relative_path,
            run_id,
            removed_at_unix_nanos,
            recovery_method,
            verification_state,
            item_type,
            content,
            source_identity,
            symlink_target,
        })
    }

    pub fn destination(&self) -> Result<PathBuf, RestoreError> {
        let root = fs::canonicalize(&self.original_root).map_err(io_error)?;
        let destination = root.join(&self.relative_path);
        if !destination.starts_with(&root) {
            return Err(RestoreError::InvalidProvenance(
                "recovery path escapes its original peer root".into(),
            ));
        }
        Ok(destination)
    }

    pub fn sidecar_path(recovered: &Path) -> Result<PathBuf, RestoreError> {
        if recovered.as_os_str().is_empty() {
            return Err(RestoreError::SidecarInvalid(
                "recovery item path is empty".into(),
            ));
        }
        Ok(recovered.with_extension("syncplus-manifest"))
    }

    /// Write a validated, content-free provenance sidecar for custom or
    /// remote recovery. The sidecar is created without replacement and is
    /// user-readable only on Unix.
    pub fn write_sidecar(&self, path: &Path) -> Result<(), RestoreError> {
        let payload = self.sidecar_payload();
        let checksum = digest_text(&payload);
        let contents = format!("{payload}checksum={checksum}\n");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(io_error)?;
        }
        file.write_all(contents.as_bytes()).map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }

    pub fn write_sidecar_for(&self, recovered: &Path) -> Result<PathBuf, RestoreError> {
        let path = Self::sidecar_path(recovered)?;
        self.write_sidecar(&path)?;
        Ok(path)
    }

    pub fn read_sidecar(path: &Path) -> Result<Self, RestoreError> {
        let contents = fs::read_to_string(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RestoreError::SidecarInvalid("recovery provenance sidecar is missing".into())
            } else {
                io_error(error)
            }
        })?;
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
                "action_id"
                    | "peer_hex"
                    | "root_hex"
                    | "relative_hex"
                    | "run_id"
                    | "removed_at_unix_nanos"
                    | "recovery_method"
                    | "verification_state"
                    | "item_type"
                    | "content"
                    | "source_identity"
                    | "symlink_target_hex"
            ) || values.insert(key, value).is_some()
            {
                return Err(RestoreError::SidecarInvalid(
                    "sidecar has an unknown or duplicate field".into(),
                ));
            }
        }

        let action_id = values
            .get("action_id")
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| RestoreError::SidecarInvalid("action id is invalid".into()))
            })
            .transpose()?;
        let peer = decode_string(required(&values, "peer_hex", "peer")?)?;
        let root = decode_path(required(&values, "root_hex", "original root")?)?;
        let relative = decode_path(required(&values, "relative_hex", "relative path")?)?;
        let run_id = values
            .get("run_id")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| RestoreError::SidecarInvalid("run id is invalid".into()))?;
        let removed_at_unix_nanos = values
            .get("removed_at_unix_nanos")
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| RestoreError::SidecarInvalid("removal time is invalid".into()))?;
        let recovery_method = decode_deletion_method(required(
            &values,
            "recovery_method",
            "recovery method",
        )?)?;
        let verification_state = decode_verification_state(required(
            &values,
            "verification_state",
            "verification state",
        )?)?;
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
        let symlink_target = values
            .get("symlink_target_hex")
            .filter(|value| !value.is_empty())
            .map(|value| decode_path(value))
            .transpose()?;
        if item_type == ItemType::Symlink && symlink_target.is_none() {
            return Err(RestoreError::SidecarInvalid(
                "symlink recovery provenance is missing its target".into(),
            ));
        }

        Self::from_record_with_details(
            action_id,
            peer,
            root,
            relative,
            crate::RunId::new(run_id),
            removed_at_unix_nanos,
            recovery_method,
            verification_state,
            item_type,
            content,
            source_identity,
            symlink_target,
        )
        .map_err(|error| RestoreError::SidecarInvalid(error.to_string()))
    }

    fn sidecar_payload(&self) -> String {
        let item_type = match self.item_type {
            ItemType::RegularFile => "regular_file",
            ItemType::Directory => "directory",
            ItemType::Symlink => "symlink",
            ItemType::Unsupported => "unsupported",
        };
        let content = self
            .content
            .map(|proof| format!("{}:{}", proof.size(), hex_hash(proof.sha256())))
            .unwrap_or_default();
        let identity = self
            .source_identity
            .map(|identity| format!("{}:{}", identity.device(), identity.inode()))
            .unwrap_or_default();
        let action_id = self.action_id.map(|value| value.to_string()).unwrap_or_default();
        let symlink_target = self
            .symlink_target
            .as_deref()
            .map(encode_path)
            .unwrap_or_default();
        format!(
            "action_id={action_id}\npeer_hex={}\nroot_hex={}\nrelative_hex={}\nrun_id={}\nremoved_at_unix_nanos={}\nrecovery_method={}\nverification_state={}\nitem_type={item_type}\ncontent={content}\nsource_identity={identity}\nsymlink_target_hex={symlink_target}\n",
            encode_string(&self.peer),
            encode_path(&self.original_root),
            encode_path(&self.relative_path),
            self.run_id.value(),
            self.removed_at_unix_nanos,
            encode_deletion_method(self.recovery_method),
            encode_verification_state(self.verification_state),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    InvalidProvenance(String),
    SidecarInvalid(String),
    Collision(PathBuf, String),
    Io(String),
    Verification(String),
    Cancelled,
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProvenance(reason) => {
                write!(formatter, "invalid recovery provenance: {reason}")
            }
            Self::SidecarInvalid(reason) => write!(formatter, "invalid recovery sidecar: {reason}"),
            Self::Collision(path, reason) => {
                write!(formatter, "restore refused at {path:?}: {reason}")
            }
            Self::Io(reason) => write!(formatter, "restore filesystem error: {reason}"),
            Self::Verification(reason) => write!(formatter, "restore verification failed: {reason}"),
            Self::Cancelled => formatter.write_str("restore cancelled"),
        }
    }
}

impl std::error::Error for RestoreError {}

fn io_error(error: io::Error) -> RestoreError {
    RestoreError::Io(error.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreJournalEvent {
    Decision {
        run_id: crate::RunId,
        path: PathBuf,
    },
    Completed {
        run_id: crate::RunId,
        path: PathBuf,
        outcome: RestoreOutcome,
    },
    Refused {
        run_id: crate::RunId,
        path: PathBuf,
        reason: String,
    },
}

pub struct CollisionSafeRestore;

impl CollisionSafeRestore {
    pub fn restore_from_sidecar<C>(
        recovered: &Path,
        sidecar: &Path,
        should_cancel: C,
    ) -> Result<RestoreOutcome, RestoreError>
    where
        C: Fn() -> bool,
    {
        let expected_sidecar = RecoveryProvenance::sidecar_path(recovered)?;
        if sidecar != expected_sidecar {
            return Err(RestoreError::SidecarInvalid(
                "recovery sidecar does not belong to the recovered item".into(),
            ));
        }
        let provenance = RecoveryProvenance::read_sidecar(sidecar)?;
        Self::restore(recovered, &provenance, should_cancel)
    }

    pub fn restore<C>(
        recovered: &Path,
        provenance: &RecoveryProvenance,
        should_cancel: C,
    ) -> Result<RestoreOutcome, RestoreError>
    where
        C: Fn() -> bool,
    {
        validate_relative_path(provenance.relative_path())?;
        if provenance.verification_state() != RecoveryVerificationState::Verified {
            return Err(RestoreError::InvalidProvenance(
                "recovery provenance is not independently verified and remains in Recovery Review"
                    .into(),
            ));
        }
        let destination = provenance.destination()?;
        let recovered_meta = fs::symlink_metadata(recovered).map_err(io_error)?;
        if provenance.item_type() != ItemType::RegularFile || !recovered_meta.file_type().is_file() {
            return Err(RestoreError::Verification(
                "only regular-file restore is supported and the recovered item type must match provenance"
                    .into(),
            ));
        }
        let expected = provenance.content().ok_or_else(|| {
            RestoreError::InvalidProvenance(
                "regular-file recovery is missing its content verification proof".into(),
            )
        })?;
        let actual = ContentProof::from_path(recovered)
            .map_err(|error| RestoreError::Verification(error.to_string()))?;
        if !expected.matches(&actual) {
            return Err(RestoreError::Verification(
                "recovered content does not match provenance".into(),
            ));
        }

        match fs::symlink_metadata(&destination) {
            Ok(existing) => {
                if existing.file_type().is_file() {
                    let actual = ContentProof::from_path(&destination)
                        .map_err(|error| RestoreError::Verification(error.to_string()))?;
                    if expected.matches(&actual) {
                        return Ok(RestoreOutcome::AlreadyPresent);
                    }
                }
                return Err(RestoreError::Collision(
                    destination,
                    "destination is newer, different, or lacks matching proof; no overwrite was performed"
                        .into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        if should_cancel() {
            return Err(RestoreError::Cancelled);
        }

        let parent = destination
            .parent()
            .ok_or_else(|| RestoreError::InvalidProvenance("destination has no parent".into()))?;
        ensure_parent_within_root(provenance, parent)?;
        fs::create_dir_all(parent).map_err(io_error)?;
        ensure_parent_within_root(provenance, parent)?;
        let name = destination
            .file_name()
            .ok_or_else(|| RestoreError::InvalidProvenance("destination has no name".into()))?;
        let temporary = parent.join(format!(".syncplus-restore-{}", encode_path(Path::new(name.to_string_lossy().as_ref()))));
        if fs::symlink_metadata(&temporary).is_ok() {
            return Err(RestoreError::Collision(
                temporary,
                "restore temporary path already exists".into(),
            ));
        }

        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io_error)?;
        let mut input = fs::File::open(recovered).map_err(io_error)?;
        if let Err(error) = io::copy(&mut input, &mut output) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(error));
        }
        output.sync_all().map_err(|error| {
            let _ = fs::remove_file(&temporary);
            io_error(error)
        })?;
        let temporary_proof = ContentProof::from_path(&temporary)
            .map_err(|error| RestoreError::Verification(error.to_string()))?;
        if !expected.matches(&temporary_proof) {
            let _ = fs::remove_file(&temporary);
            return Err(RestoreError::Verification(
                "temporary restore content changed before installation".into(),
            ));
        }
        if fs::symlink_metadata(&destination).is_ok() {
            let _ = fs::remove_file(&temporary);
            return Err(RestoreError::Collision(
                destination,
                "destination appeared during restore; no overwrite was performed".into(),
            ));
        }
        let result = install_without_replacement(&temporary, &destination);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map(|()| RestoreOutcome::Restored)
    }

    pub fn restore_with_journal<C, J>(
        recovered: &Path,
        provenance: &RecoveryProvenance,
        should_cancel: C,
        mut journal: J,
    ) -> Result<RestoreOutcome, RestoreError>
    where
        C: Fn() -> bool,
        J: FnMut(RestoreJournalEvent),
    {
        let path = provenance.destination()?;
        journal(RestoreJournalEvent::Decision {
            run_id: provenance.run_id(),
            path: path.clone(),
        });
        match Self::restore(recovered, provenance, should_cancel) {
            Ok(outcome) => {
                journal(RestoreJournalEvent::Completed {
                    run_id: provenance.run_id(),
                    path,
                    outcome,
                });
                Ok(outcome)
            }
            Err(error) => {
                journal(RestoreJournalEvent::Refused {
                    run_id: provenance.run_id(),
                    path,
                    reason: error.to_string(),
                });
                Err(error)
            }
        }
    }
}

fn ensure_parent_within_root(
    provenance: &RecoveryProvenance,
    parent: &Path,
) -> Result<(), RestoreError> {
    let root = fs::canonicalize(provenance.original_root()).map_err(io_error)?;
    let mut existing = parent;
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| RestoreError::InvalidProvenance("destination parent is unavailable".into()))?;
    }
    let canonical = fs::canonicalize(existing).map_err(io_error)?;
    if !canonical.starts_with(&root) {
        return Err(RestoreError::InvalidProvenance(
            "destination parent escapes its original peer root".into(),
        ));
    }
    Ok(())
}

fn install_without_replacement(temporary: &Path, destination: &Path) -> Result<(), RestoreError> {
    fs::hard_link(temporary, destination).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            RestoreError::Collision(
                destination.to_path_buf(),
                "destination appeared during restore; no overwrite was performed".into(),
            )
        } else {
            io_error(error)
        }
    })?;
    fs::remove_file(temporary).map_err(io_error)
}

fn validate_relative_path(path: &Path) -> Result<(), RestoreError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RestoreError::InvalidProvenance(
            "original path must be a non-empty normalized relative path".into(),
        ));
    }
    Ok(())
}

fn validate_original_root(path: &Path) -> Result<(), RestoreError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(RestoreError::InvalidProvenance(
            "original peer root must be an absolute path".into(),
        ));
    }
    Ok(())
}

fn validate_peer(peer: &str) -> Result<(), RestoreError> {
    if peer.trim().is_empty() || peer.chars().any(|character| character == '\n' || character == '\r') {
        return Err(RestoreError::InvalidProvenance(
            "recovery peer is missing or malformed".into(),
        ));
    }
    Ok(())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
        .unwrap_or_default()
}

fn digest_text(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn required<'a>(
    values: &'a BTreeMap<&str, &str>,
    key: &str,
    label: &str,
) -> Result<&'a str, RestoreError> {
    values
        .get(key)
        .copied()
        .ok_or_else(|| RestoreError::SidecarInvalid(format!("{label} is missing")))
}

fn encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, RestoreError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RestoreError::SidecarInvalid(
            "encoded sidecar value is invalid".into(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or_default(), 16)
                .map_err(|_| RestoreError::SidecarInvalid("encoded sidecar value is invalid".into()))
        })
        .collect()
}

fn encode_string(value: &str) -> String {
    encode_bytes(value.as_bytes())
}

fn decode_string(value: &str) -> Result<String, RestoreError> {
    String::from_utf8(decode_bytes(value)?).map_err(|_| {
        RestoreError::SidecarInvalid("peer is not valid UTF-8".into())
    })
}

fn encode_path(path: &Path) -> String {
    #[cfg(unix)]
    {
        encode_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        encode_string(&path.as_os_str().to_string_lossy())
    }
}

fn decode_path(value: &str) -> Result<PathBuf, RestoreError> {
    let bytes = decode_bytes(value)?;
    #[cfg(unix)]
    {
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| RestoreError::SidecarInvalid("path is not valid for this platform".into()))
    }
}

fn hex_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_deletion_method(method: DeletionMethod) -> &'static str {
    match method {
        DeletionMethod::Trash => "trash",
        DeletionMethod::PermanentRemoval => "permanent_removal",
    }
}

fn decode_deletion_method(value: &str) -> Result<DeletionMethod, RestoreError> {
    match value {
        "trash" => Ok(DeletionMethod::Trash),
        "permanent_removal" => Ok(DeletionMethod::PermanentRemoval),
        _ => Err(RestoreError::SidecarInvalid("recovery method is invalid".into())),
    }
}

fn encode_verification_state(state: RecoveryVerificationState) -> &'static str {
    match state {
        RecoveryVerificationState::Verified => "verified",
        RecoveryVerificationState::ReviewRequired => "review_required",
        RecoveryVerificationState::Unverified => "unverified",
    }
}

fn decode_verification_state(value: &str) -> Result<RecoveryVerificationState, RestoreError> {
    match value {
        "verified" => Ok(RecoveryVerificationState::Verified),
        "review_required" => Ok(RecoveryVerificationState::ReviewRequired),
        "unverified" => Ok(RecoveryVerificationState::Unverified),
        _ => Err(RestoreError::SidecarInvalid("verification state is invalid".into())),
    }
}

fn parse_content(value: &str) -> Result<ContentProof, RestoreError> {
    let (size, hash) = value
        .split_once(':')
        .ok_or_else(|| RestoreError::SidecarInvalid("content proof is malformed".into()))?;
    let size = size
        .parse()
        .map_err(|_| RestoreError::SidecarInvalid("content size is invalid".into()))?;
    let bytes = hash.as_bytes();
    if bytes.len() != 64 {
        return Err(RestoreError::SidecarInvalid("content digest is invalid".into()));
    }
    let mut digest = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(
            std::str::from_utf8(chunk)
                .map_err(|_| RestoreError::SidecarInvalid("content digest is invalid".into()))?,
            16,
        )
        .map_err(|_| RestoreError::SidecarInvalid("content digest is invalid".into()))?;
    }
    Ok(ContentProof::new(size, digest))
}

fn parse_identity(value: &str) -> Result<FileIdentity, RestoreError> {
    let (device, inode) = value
        .split_once(':')
        .ok_or_else(|| RestoreError::SidecarInvalid("source identity is malformed".into()))?;
    Ok(FileIdentity::new(
        device
            .parse()
            .map_err(|_| RestoreError::SidecarInvalid("source device is invalid".into()))?,
        inode
            .parse()
            .map_err(|_| RestoreError::SidecarInvalid("source inode is invalid".into()))?,
    ))
}
