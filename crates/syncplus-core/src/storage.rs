use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, OptionalExtension, Row, Transaction};

use crate::{
    AuthorizationSnapshot, DeletionMethod,
    MetadataRequirements, OneWaySource, Peer, PeerEndpoint, PartialTransferPolicy,
    ProcessSpecification, SavedSecretReference, SpecialistMetadataRequirements,
    RetryPolicy, SshAuthentication, SyncMode, SyncOptions, SyncProfile,
};
use crate::evidence::{RunEvidenceStore, StorageError};

/// A stable identifier for a persisted Sync Profile. The display name is
/// editable and therefore is not used as the profile identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SyncProfileId(u64);

impl SyncProfileId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The UI presentation mode remembered for the current OS user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplicationMode {
    #[default]
    Simple,
    Advanced,
}

/// Nonsecret application settings persisted in the Application Database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationSettings {
    mode: ApplicationMode,
    theme: ThemePreference,
}

impl ApplicationSettings {
    pub const fn new(mode: ApplicationMode, theme: ThemePreference) -> Self {
        Self { mode, theme }
    }

    pub const fn mode(self) -> ApplicationMode {
        self.mode
    }

    pub const fn theme(self) -> ThemePreference {
        self.theme
    }
}

impl Default for ApplicationSettings {
    fn default() -> Self {
        Self::new(ApplicationMode::Simple, ThemePreference::System)
    }
}

/// A nonsecret theme preference. The UI owns the visual rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

/// A persisted profile together with policy fields that are intentionally
/// disabled for new profiles. Scheduling and unattended authorization are
/// expanded by the scheduler persistence slice while retaining this safe
/// storage boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedSyncProfile {
    id: SyncProfileId,
    profile: SyncProfile,
    schedule_enabled: bool,
    authorizations: AuthorizationSnapshot,
}

impl PersistedSyncProfile {
    pub const fn id(&self) -> SyncProfileId {
        self.id
    }

    pub fn profile(&self) -> &SyncProfile {
        &self.profile
    }

    pub const fn schedule_enabled(&self) -> bool {
        self.schedule_enabled
    }

    pub const fn authorizations(&self) -> AuthorizationSnapshot {
        self.authorizations
    }
}

impl RunEvidenceStore {
    pub fn load_settings(&self) -> Result<ApplicationSettings, StorageError> {
        let mode = self
            .connection()
            .query_row(
                "SELECT value FROM application_settings WHERE key = 'ui_mode'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| decode_application_mode(&value))
            .transpose()?
            .unwrap_or_default();
        let theme = self
            .connection()
            .query_row(
                "SELECT value FROM application_settings WHERE key = 'theme'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| decode_theme_preference(&value))
            .transpose()?
            .unwrap_or_default();
        Ok(ApplicationSettings::new(mode, theme))
    }

    pub fn save_settings(&mut self, settings: &ApplicationSettings) -> Result<(), StorageError> {
        let transaction = self.connection_mut().transaction()?;
        transaction.execute(
            "INSERT INTO application_settings (key, value) VALUES ('ui_mode', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![encode_application_mode(settings.mode())],
        )?;
        transaction.execute(
            "INSERT INTO application_settings (key, value) VALUES ('theme', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![encode_theme_preference(settings.theme())],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_profile(
        &mut self,
        profile: &SyncProfile,
    ) -> Result<PersistedSyncProfile, StorageError> {
        self.create_profile_with_authorizations(profile, AuthorizationSnapshot::default())
    }

    pub fn create_profile_with_authorizations(
        &mut self,
        profile: &SyncProfile,
        authorizations: AuthorizationSnapshot,
    ) -> Result<PersistedSyncProfile, StorageError> {
        validate_profile(profile)?;
        self.reject_duplicate_endpoint_pair(profile, None)?;
        let values = ProfileValues::from_profile(profile);
        let transaction = self.connection_mut().transaction()?;
        let id = insert_profile(&transaction, &values, authorizations)?;
        insert_exclusions(&transaction, id, profile)?;
        transaction.commit()?;
        let id = SyncProfileId::new(
            u64::try_from(id).map_err(|_| StorageError::CorruptEvidence("invalid profile identifier".to_owned()))?,
        );
        Ok(PersistedSyncProfile {
            id,
            profile: profile.clone(),
            schedule_enabled: false,
            authorizations,
        })
    }

    pub fn update_profile(
        &mut self,
        id: SyncProfileId,
        profile: &SyncProfile,
    ) -> Result<PersistedSyncProfile, StorageError> {
        validate_profile(profile)?;
        let existing = self
            .load_profile(id)?
            .ok_or(StorageError::ProfileNotFound { id: id.value() })?;
        self.reject_duplicate_endpoint_pair(profile, Some(id))?;
        let values = ProfileValues::from_profile(profile);
        let transaction = self.connection_mut().transaction()?;
        let changed = update_profile_row(&transaction, id, &values)?;
        if changed != 1 {
            return Err(StorageError::ProfileNotFound { id: id.value() });
        }
        transaction.execute(
            "DELETE FROM sync_profile_exclusions WHERE profile_id = ?1",
            params![id.value_as_i64()?],
        )?;
        insert_exclusions(&transaction, id.value_as_i64()?, profile)?;
        transaction.commit()?;
        Ok(PersistedSyncProfile {
            id,
            profile: profile.clone(),
            schedule_enabled: existing.schedule_enabled,
            authorizations: existing.authorizations,
        })
    }

    pub fn load_profile(
        &self,
        id: SyncProfileId,
    ) -> Result<Option<PersistedSyncProfile>, StorageError> {
        let raw = self
            .connection()
            .query_row(
                &format!("{PROFILE_SELECT} WHERE profile_id = ?1"),
                params![id.value_as_i64()?],
                RawProfile::from_row,
            )
            .optional()?;
        raw.map(|raw| self.materialize_profile(raw)).transpose()
    }

    pub fn list_profiles(&self) -> Result<Vec<PersistedSyncProfile>, StorageError> {
        let mut statement = self
            .connection()
            .prepare(&format!("{PROFILE_SELECT} ORDER BY profile_id"))?;
        let rows = statement.query_map([], RawProfile::from_row)?;
        let raw_profiles = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        raw_profiles
            .into_iter()
            .map(|raw| self.materialize_profile(raw))
            .collect()
    }

    pub fn remove_profile(&mut self, id: SyncProfileId) -> Result<bool, StorageError> {
        let changed = self.connection_mut().execute(
            "DELETE FROM sync_profiles WHERE profile_id = ?1",
            params![id.value_as_i64()?],
        )?;
        Ok(changed == 1)
    }

    fn reject_duplicate_endpoint_pair(
        &self,
        profile: &SyncProfile,
        excluded_id: Option<SyncProfileId>,
    ) -> Result<(), StorageError> {
        let duplicate = self.list_profiles()?.into_iter().any(|persisted| {
            Some(persisted.id()) != excluded_id
                && persisted.profile().peer_a().same_endpoint(profile.peer_a())
                && persisted.profile().peer_b().same_endpoint(profile.peer_b())
        });
        if duplicate {
            return Err(StorageError::DuplicateEndpointPair);
        }
        Ok(())
    }

    fn materialize_profile(&self, raw: RawProfile) -> Result<PersistedSyncProfile, StorageError> {
        let exclusions = self.load_exclusions(raw.id)?;
        let id = SyncProfileId::new(
            u64::try_from(raw.id)
                .map_err(|_| StorageError::CorruptEvidence("invalid profile identifier".to_owned()))?,
        );
        let schedule_enabled = decode_profile_bool(raw.schedule_enabled)?;
        let authorizations = AuthorizationSnapshot::new(
            decode_profile_bool(raw.allow_unattended_destructive)?,
            decode_profile_bool(raw.allow_unattended_permanent_removal)?,
        );
        let profile = raw.into_profile(exclusions)?;
        Ok(PersistedSyncProfile {
            id,
            profile,
            schedule_enabled,
            authorizations,
        })
    }

    fn load_exclusions(&self, profile_id: i64) -> Result<Vec<String>, StorageError> {
        let mut statement = self.connection().prepare(
            "SELECT pattern FROM sync_profile_exclusions
             WHERE profile_id = ?1 ORDER BY ordinal",
        )?;
        let exclusions = statement
            .query_map(params![profile_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(exclusions)
    }
}

impl SyncProfileId {
    fn value_as_i64(self) -> Result<i64, StorageError> {
        i64::try_from(self.0)
            .map_err(|_| StorageError::CorruptEvidence("profile identifier is out of range".to_owned()))
    }
}

const PROFILE_SELECT: &str = "SELECT
    profile_id, name, mode, source,
    peer_a_name, peer_a_endpoint_kind, peer_a_root, peer_a_server,
    peer_a_username, peer_a_port, peer_a_identity, peer_a_authentication,
    peer_b_name, peer_b_endpoint_kind, peer_b_root, peer_b_server,
    peer_b_username, peer_b_port, peer_b_identity, peer_b_authentication,
    safe_delete, destination_cleanup, deletion_method,
    metadata_file_type, metadata_executable_permissions, metadata_symlink_targets,
    metadata_timestamps, metadata_ownership, metadata_access_control_lists,
    metadata_extended_attributes, partial_transfer_policy, retry_max_attempts,
    retry_initial_delay_millis, schedule_enabled, allow_unattended_destructive,
    allow_unattended_permanent_removal
    FROM sync_profiles";

struct ProfileValues {
    name: String,
    mode: &'static str,
    source: &'static str,
    peer_a: PersistedPeer,
    peer_b: PersistedPeer,
    options: PersistedOptions,
}

struct PersistedPeer {
    name: String,
    kind: &'static str,
    root: Vec<u8>,
    server: Option<String>,
    username: Option<String>,
    port: Option<i64>,
    identity: Option<Vec<u8>>,
    authentication: Option<String>,
}

struct PersistedOptions {
    safe_delete: i64,
    destination_cleanup: i64,
    deletion_method: Option<&'static str>,
    metadata_file_type: i64,
    metadata_executable_permissions: i64,
    metadata_symlink_targets: i64,
    metadata_timestamps: i64,
    metadata_ownership: i64,
    metadata_access_control_lists: i64,
    metadata_extended_attributes: i64,
    partial_transfer_policy: &'static str,
    retry_max_attempts: i64,
    retry_initial_delay_millis: i64,
}

impl ProfileValues {
    fn from_profile(profile: &SyncProfile) -> Self {
        let options = profile.options();
        let metadata = options.metadata;
        let specialist = metadata.specialist_metadata();
        Self {
            name: profile.name().to_owned(),
            mode: encode_sync_mode(profile.mode()),
            source: encode_source(profile.source()),
            peer_a: PersistedPeer::from_peer(profile.peer_a()),
            peer_b: PersistedPeer::from_peer(profile.peer_b()),
            options: PersistedOptions {
                safe_delete: i64::from(options.safe_delete),
                destination_cleanup: i64::from(options.destination_cleanup),
                deletion_method: options.deletion_method.map(encode_deletion_method),
                metadata_file_type: i64::from(metadata.file_type()),
                metadata_executable_permissions: i64::from(metadata.executable_permissions()),
                metadata_symlink_targets: i64::from(metadata.symlink_targets()),
                metadata_timestamps: i64::from(metadata.timestamps()),
                metadata_ownership: i64::from(specialist.ownership()),
                metadata_access_control_lists: i64::from(specialist.access_control_lists()),
                metadata_extended_attributes: i64::from(specialist.extended_attributes()),
                partial_transfer_policy: encode_partial_transfer_policy(options.partial_transfer_policy),
                retry_max_attempts: i64::from(options.retry_policy.max_attempts()),
                retry_initial_delay_millis: i64::try_from(options.retry_policy.initial_delay().as_millis())
                    .unwrap_or(i64::MAX),
            },
        }
    }
}

impl PersistedPeer {
    fn from_peer(peer: &Peer) -> Self {
        match peer.endpoint() {
            PeerEndpoint::Local { root } => Self {
                name: peer.name().to_owned(),
                kind: "local",
                root: path_to_blob(root),
                server: None,
                username: None,
                port: None,
                identity: None,
                authentication: None,
            },
            PeerEndpoint::Ssh(ssh) => Self {
                name: peer.name().to_owned(),
                kind: "ssh",
                root: path_to_blob(ssh.remote_path()),
                server: Some(ssh.server().to_owned()),
                username: Some(ssh.username().to_owned()),
                port: Some(i64::from(ssh.port())),
                identity: ssh.identity().map(path_to_blob),
                authentication: Some(encode_authentication(ssh.authentication())),
            },
        }
    }
}

fn insert_profile(
    transaction: &Transaction<'_>,
    values: &ProfileValues,
    authorizations: AuthorizationSnapshot,
) -> Result<i64, StorageError> {
    let mut parameters = profile_params(values);
    parameters.push(Box::new(i64::from(authorizations.allow_unattended_destructive())));
    parameters.push(Box::new(i64::from(authorizations.allow_unattended_permanent_removal())));
    transaction.execute(
        "INSERT INTO sync_profiles (
            name, mode, source,
            peer_a_name, peer_a_endpoint_kind, peer_a_root, peer_a_server,
            peer_a_username, peer_a_port, peer_a_identity, peer_a_authentication,
            peer_b_name, peer_b_endpoint_kind, peer_b_root, peer_b_server,
            peer_b_username, peer_b_port, peer_b_identity, peer_b_authentication,
            safe_delete, destination_cleanup, deletion_method,
            metadata_file_type, metadata_executable_permissions, metadata_symlink_targets,
            metadata_timestamps, metadata_ownership, metadata_access_control_lists,
            metadata_extended_attributes, partial_transfer_policy, retry_max_attempts,
            retry_initial_delay_millis, schedule_enabled, allow_unattended_destructive,
            allow_unattended_permanent_removal
        ) VALUES (
            ?1, ?2, ?3,
            ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
            ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29,
            ?30, ?31, ?32, 0, ?33, ?34
        )",
        rusqlite::params_from_iter(parameters.iter().map(|value| value.as_ref())),
    )?;
    Ok(transaction.last_insert_rowid())
}

fn update_profile_row(
    transaction: &Transaction<'_>,
    id: SyncProfileId,
    values: &ProfileValues,
) -> Result<usize, StorageError> {
    let mut parameters = profile_params(values);
    parameters.push(Box::new(id.value_as_i64()?));
    Ok(transaction.execute(
        "UPDATE sync_profiles SET
            name = ?1, mode = ?2, source = ?3,
            peer_a_name = ?4, peer_a_endpoint_kind = ?5, peer_a_root = ?6,
            peer_a_server = ?7, peer_a_username = ?8, peer_a_port = ?9,
            peer_a_identity = ?10, peer_a_authentication = ?11,
            peer_b_name = ?12, peer_b_endpoint_kind = ?13, peer_b_root = ?14,
            peer_b_server = ?15, peer_b_username = ?16, peer_b_port = ?17,
            peer_b_identity = ?18, peer_b_authentication = ?19,
            safe_delete = ?20, destination_cleanup = ?21, deletion_method = ?22,
            metadata_file_type = ?23, metadata_executable_permissions = ?24,
            metadata_symlink_targets = ?25, metadata_timestamps = ?26,
            metadata_ownership = ?27, metadata_access_control_lists = ?28,
            metadata_extended_attributes = ?29, partial_transfer_policy = ?30,
            retry_max_attempts = ?31, retry_initial_delay_millis = ?32
        WHERE profile_id = ?33",
        rusqlite::params_from_iter(parameters.iter().map(|value| value.as_ref())),
    )?)
}

fn profile_params(values: &ProfileValues) -> Vec<Box<dyn rusqlite::ToSql>> {
    vec![
        Box::new(values.name.clone()),
        Box::new(values.mode),
        Box::new(values.source),
        Box::new(values.peer_a.name.clone()),
        Box::new(values.peer_a.kind),
        Box::new(values.peer_a.root.clone()),
        Box::new(values.peer_a.server.clone()),
        Box::new(values.peer_a.username.clone()),
        Box::new(values.peer_a.port),
        Box::new(values.peer_a.identity.clone()),
        Box::new(values.peer_a.authentication.clone()),
        Box::new(values.peer_b.name.clone()),
        Box::new(values.peer_b.kind),
        Box::new(values.peer_b.root.clone()),
        Box::new(values.peer_b.server.clone()),
        Box::new(values.peer_b.username.clone()),
        Box::new(values.peer_b.port),
        Box::new(values.peer_b.identity.clone()),
        Box::new(values.peer_b.authentication.clone()),
        Box::new(values.options.safe_delete),
        Box::new(values.options.destination_cleanup),
        Box::new(values.options.deletion_method),
        Box::new(values.options.metadata_file_type),
        Box::new(values.options.metadata_executable_permissions),
        Box::new(values.options.metadata_symlink_targets),
        Box::new(values.options.metadata_timestamps),
        Box::new(values.options.metadata_ownership),
        Box::new(values.options.metadata_access_control_lists),
        Box::new(values.options.metadata_extended_attributes),
        Box::new(values.options.partial_transfer_policy),
        Box::new(values.options.retry_max_attempts),
        Box::new(values.options.retry_initial_delay_millis),
    ]
}

fn insert_exclusions(
    transaction: &Transaction<'_>,
    profile_id: i64,
    profile: &SyncProfile,
) -> Result<(), StorageError> {
    for (ordinal, pattern) in profile.exclusions().iter().enumerate() {
        transaction.execute(
            "INSERT INTO sync_profile_exclusions (profile_id, ordinal, pattern)
             VALUES (?1, ?2, ?3)",
            params![profile_id, ordinal as i64, pattern],
        )?;
    }
    Ok(())
}

fn validate_profile(profile: &SyncProfile) -> Result<(), StorageError> {
    if profile.name().trim().is_empty()
        || profile.name().len() > 255
        || profile.name().contains('\0')
    {
        return Err(StorageError::InvalidProfileName);
    }
    for peer in [profile.peer_a(), profile.peer_b()] {
        if peer.name().trim().is_empty() || peer.name().len() > 255 || peer.name().contains('\0') {
            return Err(StorageError::InvalidPeerName);
        }
    }
    ProcessSpecification::from_profile(profile).map_err(StorageError::InvalidProfile)?;
    Ok(())
}

struct RawProfile {
    id: i64,
    name: String,
    mode: String,
    source: String,
    peer_a: RawPeer,
    peer_b: RawPeer,
    safe_delete: i64,
    destination_cleanup: i64,
    deletion_method: Option<String>,
    metadata_file_type: i64,
    metadata_executable_permissions: i64,
    metadata_symlink_targets: i64,
    metadata_timestamps: i64,
    metadata_ownership: i64,
    metadata_access_control_lists: i64,
    metadata_extended_attributes: i64,
    partial_transfer_policy: String,
    retry_max_attempts: i64,
    retry_initial_delay_millis: i64,
    schedule_enabled: i64,
    allow_unattended_destructive: i64,
    allow_unattended_permanent_removal: i64,
}

struct RawPeer {
    name: String,
    kind: String,
    root: Vec<u8>,
    server: Option<String>,
    username: Option<String>,
    port: Option<i64>,
    identity: Option<Vec<u8>>,
    authentication: Option<String>,
}

impl RawProfile {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            mode: row.get(2)?,
            source: row.get(3)?,
            peer_a: RawPeer {
                name: row.get(4)?,
                kind: row.get(5)?,
                root: row.get(6)?,
                server: row.get(7)?,
                username: row.get(8)?,
                port: row.get(9)?,
                identity: row.get(10)?,
                authentication: row.get(11)?,
            },
            peer_b: RawPeer {
                name: row.get(12)?,
                kind: row.get(13)?,
                root: row.get(14)?,
                server: row.get(15)?,
                username: row.get(16)?,
                port: row.get(17)?,
                identity: row.get(18)?,
                authentication: row.get(19)?,
            },
            safe_delete: row.get(20)?,
            destination_cleanup: row.get(21)?,
            deletion_method: row.get(22)?,
            metadata_file_type: row.get(23)?,
            metadata_executable_permissions: row.get(24)?,
            metadata_symlink_targets: row.get(25)?,
            metadata_timestamps: row.get(26)?,
            metadata_ownership: row.get(27)?,
            metadata_access_control_lists: row.get(28)?,
            metadata_extended_attributes: row.get(29)?,
            partial_transfer_policy: row.get(30)?,
            retry_max_attempts: row.get(31)?,
            retry_initial_delay_millis: row.get(32)?,
            schedule_enabled: row.get(33)?,
            allow_unattended_destructive: row.get(34)?,
            allow_unattended_permanent_removal: row.get(35)?,
        })
    }

    fn into_profile(self, exclusions: Vec<String>) -> Result<SyncProfile, StorageError> {
        let peer_a = decode_peer(self.peer_a)?;
        let peer_b = decode_peer(self.peer_b)?;
        let mode = decode_sync_mode(&self.mode)?;
        let source = decode_source(&self.source)?;
        let options = SyncOptions {
            safe_delete: decode_profile_bool(self.safe_delete)?,
            destination_cleanup: decode_profile_bool(self.destination_cleanup)?,
            deletion_method: self
                .deletion_method
                .as_deref()
                .map(decode_deletion_method)
                .transpose()?,
            metadata: MetadataRequirements::new(
                decode_profile_bool(self.metadata_file_type)?,
                decode_profile_bool(self.metadata_executable_permissions)?,
                decode_profile_bool(self.metadata_symlink_targets)?,
                decode_profile_bool(self.metadata_timestamps)?,
            )
            .with_specialist_metadata(SpecialistMetadataRequirements::new(
                decode_profile_bool(self.metadata_ownership)?,
                decode_profile_bool(self.metadata_access_control_lists)?,
                decode_profile_bool(self.metadata_extended_attributes)?,
            )),
            partial_transfer_policy: decode_partial_transfer_policy(&self.partial_transfer_policy)?,
            retry_policy: RetryPolicy::new(
                u8::try_from(self.retry_max_attempts)
                    .map_err(|_| corrupt_profile())?,
                Duration::from_millis(
                    u64::try_from(self.retry_initial_delay_millis)
                        .map_err(|_| corrupt_profile())?,
                ),
            ),
        };
        let profile = SyncProfile::new(self.name, peer_a, peer_b)
            .with_mode(mode)
            .with_source(source)
            .with_options(options)
            .with_exclusions(exclusions);
        validate_profile(&profile)?;
        Ok(profile)
    }
}

fn decode_peer(raw: RawPeer) -> Result<Peer, StorageError> {
    let root = blob_to_path(&raw.root)?;
    match raw.kind.as_str() {
        "local" => {
            if raw.server.is_some()
                || raw.username.is_some()
                || raw.port.is_some()
                || raw.identity.is_some()
                || raw.authentication.is_some()
            {
                return Err(corrupt_profile());
            }
            Ok(Peer::new(raw.name, root))
        }
        "ssh" => {
            let server = raw.server.ok_or_else(corrupt_profile)?;
            let username = raw.username.ok_or_else(corrupt_profile)?;
            let port = u16::try_from(raw.port.ok_or_else(corrupt_profile)?)
                .map_err(|_| corrupt_profile())?;
            let authentication = decode_authentication(raw.authentication.as_deref())?;
            let remote_path = root.to_str().ok_or_else(corrupt_profile)?;
            let peer = Peer::ssh(
                raw.name,
                server,
                username,
                port,
                raw.identity.map(|identity| blob_to_path(&identity)).transpose()?,
                authentication,
                remote_path,
            )
            .map_err(|_| corrupt_profile())?;
            Ok(peer)
        }
        _ => Err(corrupt_profile()),
    }
}

fn decode_authentication(value: Option<&str>) -> Result<SshAuthentication, StorageError> {
    match value {
        Some("key") => Ok(SshAuthentication::Key),
        Some("agent") => Ok(SshAuthentication::Agent),
        Some("interactive_password") => Ok(SshAuthentication::InteractivePassword),
        Some(value) => {
            let reference = value.strip_prefix("saved_password:").ok_or_else(corrupt_profile)?;
            SavedSecretReference::new(reference)
                .map(SshAuthentication::SavedPassword)
                .map_err(|_| corrupt_profile())
        }
        None => Err(corrupt_profile()),
    }
}

fn decode_profile_bool(value: i64) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt_profile()),
    }
}

fn corrupt_profile() -> StorageError {
    StorageError::CorruptEvidence("corrupt Sync Profile record".to_owned())
}

fn encode_application_mode(mode: ApplicationMode) -> &'static str {
    match mode {
        ApplicationMode::Simple => "simple",
        ApplicationMode::Advanced => "advanced",
    }
}

fn decode_application_mode(value: &str) -> Result<ApplicationMode, StorageError> {
    match value {
        "simple" => Ok(ApplicationMode::Simple),
        "advanced" => Ok(ApplicationMode::Advanced),
        _ => Err(StorageError::CorruptEvidence("corrupt application settings".to_owned())),
    }
}

fn encode_theme_preference(theme: ThemePreference) -> &'static str {
    match theme {
        ThemePreference::System => "system",
        ThemePreference::Light => "light",
        ThemePreference::Dark => "dark",
    }
}

fn decode_theme_preference(value: &str) -> Result<ThemePreference, StorageError> {
    match value {
        "system" => Ok(ThemePreference::System),
        "light" => Ok(ThemePreference::Light),
        "dark" => Ok(ThemePreference::Dark),
        _ => Err(StorageError::CorruptEvidence("corrupt application settings".to_owned())),
    }
}

fn encode_sync_mode(mode: SyncMode) -> &'static str {
    match mode {
        SyncMode::OneWay => "one_way",
        SyncMode::Mirror => "mirror",
    }
}

fn decode_sync_mode(value: &str) -> Result<SyncMode, StorageError> {
    match value {
        "one_way" => Ok(SyncMode::OneWay),
        "mirror" => Ok(SyncMode::Mirror),
        _ => Err(corrupt_profile()),
    }
}

fn encode_source(source: OneWaySource) -> &'static str {
    match source {
        OneWaySource::PeerA => "peer_a",
        OneWaySource::PeerB => "peer_b",
    }
}

fn decode_source(value: &str) -> Result<OneWaySource, StorageError> {
    match value {
        "peer_a" => Ok(OneWaySource::PeerA),
        "peer_b" => Ok(OneWaySource::PeerB),
        _ => Err(corrupt_profile()),
    }
}

fn encode_deletion_method(method: DeletionMethod) -> &'static str {
    match method {
        DeletionMethod::Trash => "trash",
        DeletionMethod::PermanentRemoval => "permanent_removal",
    }
}

fn decode_deletion_method(value: &str) -> Result<DeletionMethod, StorageError> {
    match value {
        "trash" => Ok(DeletionMethod::Trash),
        "permanent_removal" => Ok(DeletionMethod::PermanentRemoval),
        _ => Err(corrupt_profile()),
    }
}

fn encode_partial_transfer_policy(policy: PartialTransferPolicy) -> &'static str {
    match policy {
        PartialTransferPolicy::Cleanup => "cleanup",
        PartialTransferPolicy::KeepPartialForResume => "keep_partial_for_resume",
    }
}

fn decode_partial_transfer_policy(value: &str) -> Result<PartialTransferPolicy, StorageError> {
    match value {
        "cleanup" => Ok(PartialTransferPolicy::Cleanup),
        "keep_partial_for_resume" => Ok(PartialTransferPolicy::KeepPartialForResume),
        _ => Err(corrupt_profile()),
    }
}

fn encode_authentication(authentication: SshAuthentication) -> String {
    match authentication {
        SshAuthentication::Key => "key".to_owned(),
        SshAuthentication::Agent => "agent".to_owned(),
        SshAuthentication::InteractivePassword => "interactive_password".to_owned(),
        SshAuthentication::SavedPassword(reference) => {
            format!("saved_password:{}", reference.as_str())
        }
    }
}

fn path_to_blob(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

fn blob_to_path(bytes: &[u8]) -> Result<PathBuf, StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes.to_vec())
            .map(PathBuf::from)
            .map_err(|_| corrupt_profile())
    }
}
