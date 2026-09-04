//! Explicit migration/backup transfer for nonsecret application configuration.
//!
//! The JSON document deliberately has no representation for run evidence,
//! host-trust records, recovery state, or credential references. Import is a
//! replacement of editable configuration and is applied only after the whole
//! document has been parsed, validated, and previewed.

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    ApplicationMode, ApplicationSettings, DeletionMethod, MetadataRequirements, OneWaySource,
    PartialTransferPolicy, Peer, PeerEndpoint, RetryPolicy, SpecialistMetadataRequirements,
    SshAuthentication, SyncMode, SyncOptions, SyncProfile, ThemePreference,
    storage::{ConfigurationImport, ImportedProfile},
};
use crate::{ProcessSpecification, RunEvidenceStore, ScheduleDefinition, StorageError};

const CURRENT_SCHEMA_VERSION: u32 = 1;
const MAX_PROFILES: usize = 1_000;
const MAX_EXCLUSIONS_PER_PROFILE: usize = 10_000;

/// A safe summary shown before an import is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationImportPreview {
    profile_names: Vec<String>,
    schedule_count: usize,
    replaces_existing_profiles: bool,
    destructive_options_stripped: usize,
    credentials_requiring_reconfiguration: usize,
    enabled_schedules_disabled: usize,
}

impl ConfigurationImportPreview {
    pub fn profile_names(&self) -> &[String] {
        &self.profile_names
    }

    pub const fn profile_count(&self) -> usize {
        self.profile_names.len()
    }

    pub const fn schedule_count(&self) -> usize {
        self.schedule_count
    }

    pub const fn replaces_existing_profiles(&self) -> bool {
        self.replaces_existing_profiles
    }

    pub const fn destructive_options_stripped(&self) -> usize {
        self.destructive_options_stripped
    }

    pub const fn credentials_requiring_reconfiguration(&self) -> usize {
        self.credentials_requiring_reconfiguration
    }

    pub const fn enabled_schedules_disabled(&self) -> usize {
        self.enabled_schedules_disabled
    }
}

/// Errors from explicit JSON configuration transfer. Messages identify the
/// configuration field and remediation without including JSON values.
#[derive(Debug)]
pub enum ConfigurationTransferError {
    Json(serde_json::Error),
    UnsupportedSchemaVersion(u32),
    InvalidConfiguration { field: String, reason: String },
    Storage(StorageError),
}

impl fmt::Display for ConfigurationTransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "configuration JSON is invalid: {error}"),
            Self::UnsupportedSchemaVersion(version) => write!(
                formatter,
                "configuration schema version {version} is unsupported; export a fresh file from this SyncPlus version"
            ),
            Self::InvalidConfiguration { field, reason } => {
                write!(
                    formatter,
                    "configuration field {field} is invalid: {reason}"
                )
            }
            Self::Storage(error) => write!(
                formatter,
                "configuration could not be stored atomically: {error}"
            ),
        }
    }
}

impl std::error::Error for ConfigurationTransferError {}

impl From<StorageError> for ConfigurationTransferError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportConfiguration {
    schema_version: u32,
    settings: ExportSettings,
    profiles: Vec<ExportProfile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportSettings {
    mode: ExportApplicationMode,
    theme: ExportTheme,
    #[serde(default = "default_hide_to_tray_on_close")]
    hide_to_tray_on_close: bool,
}

fn default_hide_to_tray_on_close() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportApplicationMode {
    Simple,
    Advanced,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportTheme {
    System,
    Light,
    Dark,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportProfile {
    name: String,
    peer_a: ExportPeer,
    peer_b: ExportPeer,
    mode: ExportSyncMode,
    source: ExportOneWaySource,
    options: ExportOptions,
    exclusions: Vec<String>,
    schedule: Option<ExportSchedule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ExportPeer {
    Local {
        name: String,
        root: String,
    },
    Ssh {
        name: String,
        server: String,
        username: String,
        port: u16,
        identity: Option<String>,
        authentication: ExportAuthentication,
        remote_path: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportAuthentication {
    Key,
    Agent,
    Interactive,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportSyncMode {
    OneWay,
    Mirror,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportOneWaySource {
    PeerA,
    PeerB,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportOptions {
    safe_delete: bool,
    destination_cleanup: bool,
    deletion_method: Option<ExportDeletionMethod>,
    metadata: ExportMetadata,
    partial_transfer_policy: ExportPartialTransferPolicy,
    retry_max_attempts: u8,
    retry_initial_delay_millis: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportDeletionMethod {
    Trash,
    PermanentRemoval,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportMetadata {
    file_type: bool,
    executable_permissions: bool,
    symlink_targets: bool,
    timestamps: bool,
    ownership: bool,
    access_control_lists: bool,
    extended_attributes: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportPartialTransferPolicy {
    Cleanup,
    KeepPartialForResume,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportSchedule {
    interval_minutes: u32,
    timezone: String,
    enabled: bool,
}

struct PreparedImport {
    configuration: ConfigurationImport,
    preview: ConfigurationImportPreview,
}

impl RunEvidenceStore {
    /// Export only validated editable configuration as explicit JSON. Run
    /// evidence, host fingerprints, recovery state, and all credential data
    /// remain in the Application Database or desktop keyring.
    pub fn export_configuration(&self) -> Result<String, ConfigurationTransferError> {
        let settings = self.load_settings()?;
        let profiles = self
            .list_profiles()?
            .iter()
            .map(ExportProfile::from_persisted)
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_string_pretty(&ExportConfiguration {
            schema_version: CURRENT_SCHEMA_VERSION,
            settings: ExportSettings::from_settings(settings),
            profiles,
        })
        .map_err(ConfigurationTransferError::Json)
    }

    /// Validate an import and return the changes that would be made. This is
    /// read-only and does not alter the live Application Database.
    pub fn preview_configuration_import(
        &self,
        json: &str,
    ) -> Result<ConfigurationImportPreview, ConfigurationTransferError> {
        Ok(prepare_import(json, self.list_profiles()?.len())?.preview)
    }

    /// Validate and atomically replace editable configuration. Any malformed,
    /// incompatible, duplicate, or storage-invalid profile aborts before the
    /// SQLite transaction commits, leaving existing settings and profiles
    /// unchanged.
    pub fn import_configuration(
        &mut self,
        json: &str,
    ) -> Result<ConfigurationImportPreview, ConfigurationTransferError> {
        let prepared = prepare_import(json, self.list_profiles()?.len())?;
        let preview = prepared.preview.clone();
        self.replace_configuration(prepared.configuration)?;
        Ok(preview)
    }
}

fn prepare_import(
    json: &str,
    existing_profile_count: usize,
) -> Result<PreparedImport, ConfigurationTransferError> {
    let document: ExportConfiguration =
        serde_json::from_str(json).map_err(ConfigurationTransferError::Json)?;
    if document.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(ConfigurationTransferError::UnsupportedSchemaVersion(
            document.schema_version,
        ));
    }
    if document.profiles.len() > MAX_PROFILES {
        return Err(invalid(
            "profiles",
            format!("must contain at most {MAX_PROFILES} profiles"),
        ));
    }

    let settings = document.settings.into_settings();
    let mut names = HashSet::with_capacity(document.profiles.len());
    let mut profile_names = Vec::with_capacity(document.profiles.len());
    let mut endpoint_pairs = Vec::with_capacity(document.profiles.len());
    let mut imported_profiles = Vec::with_capacity(document.profiles.len());
    let mut schedule_count = 0;
    let mut destructive_options_stripped = 0;
    let mut credentials_requiring_reconfiguration = 0;
    let mut enabled_schedules_disabled = 0;

    for (index, exported) in document.profiles.into_iter().enumerate() {
        let field = format!("profiles[{index}]");
        if !names.insert(exported.name.clone()) {
            return Err(invalid(
                format!("{field}.name"),
                "profile names must be unique",
            ));
        }
        profile_names.push(exported.name.clone());
        if exported.name.trim().is_empty()
            || exported.name.len() > 255
            || exported.name.contains('\0')
        {
            return Err(invalid(
                format!("{field}.name"),
                "must be a nonempty value of at most 255 characters",
            ));
        }
        if exported.exclusions.len() > MAX_EXCLUSIONS_PER_PROFILE {
            return Err(invalid(
                format!("{field}.exclusions"),
                format!("must contain at most {MAX_EXCLUSIONS_PER_PROFILE} patterns"),
            ));
        }

        let (peer_a, peer_a_requires_reconfiguration) =
            exported.peer_a.into_peer(&format!("{field}.peer_a"))?;
        let (peer_b, peer_b_requires_reconfiguration) =
            exported.peer_b.into_peer(&format!("{field}.peer_b"))?;
        for (peer_field, peer) in [("peer_a", &peer_a), ("peer_b", &peer_b)] {
            if peer.name().trim().is_empty()
                || peer.name().len() > 255
                || peer.name().contains('\0')
            {
                return Err(invalid(
                    format!("{field}.{peer_field}.name"),
                    "must be a nonempty value of at most 255 characters",
                ));
            }
        }
        if endpoint_pairs
            .iter()
            .any(|(existing_a, existing_b): &(Peer, Peer)| {
                existing_a.same_endpoint(&peer_a) && existing_b.same_endpoint(&peer_b)
            })
        {
            return Err(invalid(
                field,
                "the endpoint pair duplicates another imported Sync Profile",
            ));
        }
        endpoint_pairs.push((peer_a.clone(), peer_b.clone()));

        let (options, stripped_destructive) = exported.options.into_safe_options();
        if stripped_destructive {
            destructive_options_stripped += 1;
        }
        if peer_a_requires_reconfiguration || peer_b_requires_reconfiguration {
            credentials_requiring_reconfiguration += 1;
        }

        let schedule = exported
            .schedule
            .map(|schedule| {
                schedule_count += 1;
                let was_enabled = schedule.enabled;
                let schedule =
                    ScheduleDefinition::new(schedule.interval_minutes, schedule.timezone, false)
                        .map_err(|error| invalid(format!("{field}.schedule"), error.to_string()))?;
                if was_enabled {
                    enabled_schedules_disabled += 1;
                }
                Ok::<ScheduleDefinition, ConfigurationTransferError>(schedule)
            })
            .transpose()?;

        let profile = SyncProfile::new(exported.name, peer_a, peer_b)
            .with_mode(exported.mode.into())
            .with_source(exported.source.into())
            .with_options(options)
            .with_exclusions(exported.exclusions);
        ProcessSpecification::from_profile(&profile).map_err(|error| {
            invalid(
                format!("{field}.options"),
                format!("profile is not executable: {error}"),
            )
        })?;
        imported_profiles.push(ImportedProfile { profile, schedule });
    }

    Ok(PreparedImport {
        configuration: ConfigurationImport {
            settings,
            profiles: imported_profiles,
        },
        preview: ConfigurationImportPreview {
            profile_names,
            schedule_count,
            replaces_existing_profiles: existing_profile_count > 0,
            destructive_options_stripped,
            credentials_requiring_reconfiguration,
            enabled_schedules_disabled,
        },
    })
}

impl ExportSettings {
    fn from_settings(settings: ApplicationSettings) -> Self {
        Self {
            mode: match settings.mode() {
                ApplicationMode::Simple => ExportApplicationMode::Simple,
                ApplicationMode::Advanced => ExportApplicationMode::Advanced,
            },
            theme: match settings.theme() {
                ThemePreference::System => ExportTheme::System,
                ThemePreference::Light => ExportTheme::Light,
                ThemePreference::Dark => ExportTheme::Dark,
            },
            hide_to_tray_on_close: settings.hide_to_tray_on_window_close(),
        }
    }

    fn into_settings(self) -> ApplicationSettings {
        ApplicationSettings::new(
            match self.mode {
                ExportApplicationMode::Simple => ApplicationMode::Simple,
                ExportApplicationMode::Advanced => ApplicationMode::Advanced,
            },
            match self.theme {
                ExportTheme::System => ThemePreference::System,
                ExportTheme::Light => ThemePreference::Light,
                ExportTheme::Dark => ThemePreference::Dark,
            },
        )
        .with_hide_to_tray_on_window_close(self.hide_to_tray_on_close)
    }
}

impl ExportProfile {
    fn from_persisted(
        persisted: &crate::PersistedSyncProfile,
    ) -> Result<Self, ConfigurationTransferError> {
        Ok(Self {
            name: persisted.profile().name().to_owned(),
            peer_a: ExportPeer::from_peer(persisted.profile().peer_a(), "peer_a")?,
            peer_b: ExportPeer::from_peer(persisted.profile().peer_b(), "peer_b")?,
            mode: persisted.profile().mode().into(),
            source: persisted.profile().source().into(),
            options: ExportOptions::from_options(persisted.profile().options()),
            exclusions: persisted.profile().exclusions().to_vec(),
            schedule: persisted.schedule().map(ExportSchedule::from_schedule),
        })
    }
}

impl ExportPeer {
    fn from_peer(peer: &Peer, field: &str) -> Result<Self, ConfigurationTransferError> {
        match peer.endpoint() {
            PeerEndpoint::Local { root } => Ok(Self::Local {
                name: peer.name().to_owned(),
                root: path_to_string(root, field)?,
            }),
            PeerEndpoint::Ssh(ssh) => Ok(Self::Ssh {
                name: peer.name().to_owned(),
                server: ssh.server().to_owned(),
                username: ssh.username().to_owned(),
                port: ssh.port(),
                identity: ssh
                    .identity()
                    .map(|path| path_to_string(path, field))
                    .transpose()?,
                authentication: match ssh.authentication() {
                    SshAuthentication::Key => ExportAuthentication::Key,
                    SshAuthentication::Agent => ExportAuthentication::Agent,
                    SshAuthentication::InteractivePassword
                    | SshAuthentication::SavedPassword(_) => ExportAuthentication::Interactive,
                },
                remote_path: path_to_string(ssh.remote_path(), field)?,
            }),
        }
    }

    fn into_peer(self, field: &str) -> Result<(Peer, bool), ConfigurationTransferError> {
        match self {
            Self::Local { name, root } => Ok((Peer::new(name, PathBuf::from(root)), false)),
            Self::Ssh {
                name,
                server,
                username,
                port,
                identity,
                authentication,
                remote_path,
            } => {
                let requires_reconfiguration =
                    matches!(authentication, ExportAuthentication::Interactive);
                let authentication = match authentication {
                    ExportAuthentication::Key => SshAuthentication::Key,
                    ExportAuthentication::Agent => SshAuthentication::Agent,
                    ExportAuthentication::Interactive => SshAuthentication::InteractivePassword,
                };
                let peer = Peer::ssh(
                    name,
                    server,
                    username,
                    port,
                    identity.map(PathBuf::from),
                    authentication,
                    remote_path,
                )
                .map_err(|error| invalid(field, error.to_string()))?;
                Ok((peer, requires_reconfiguration))
            }
        }
    }
}

impl ExportOptions {
    fn from_options(options: SyncOptions) -> Self {
        let metadata = options.metadata;
        let specialist = metadata.specialist_metadata();
        Self {
            safe_delete: options.safe_delete,
            destination_cleanup: options.destination_cleanup,
            deletion_method: options.deletion_method.map(Into::into),
            metadata: ExportMetadata {
                file_type: metadata.file_type(),
                executable_permissions: metadata.executable_permissions(),
                symlink_targets: metadata.symlink_targets(),
                timestamps: metadata.timestamps(),
                ownership: specialist.ownership(),
                access_control_lists: specialist.access_control_lists(),
                extended_attributes: specialist.extended_attributes(),
            },
            partial_transfer_policy: options.partial_transfer_policy.into(),
            retry_max_attempts: options.retry_policy.max_attempts(),
            retry_initial_delay_millis: options.retry_policy.initial_delay().as_millis() as u64,
        }
    }

    fn into_safe_options(self) -> (SyncOptions, bool) {
        let stripped_destructive =
            self.safe_delete || self.destination_cleanup || self.deletion_method.is_some();
        let metadata = MetadataRequirements::new(
            self.metadata.file_type,
            self.metadata.executable_permissions,
            self.metadata.symlink_targets,
            self.metadata.timestamps,
        )
        .with_specialist_metadata(SpecialistMetadataRequirements::new(
            self.metadata.ownership,
            self.metadata.access_control_lists,
            self.metadata.extended_attributes,
        ));
        (
            SyncOptions {
                safe_delete: false,
                destination_cleanup: false,
                deletion_method: None,
                metadata,
                partial_transfer_policy: self.partial_transfer_policy.into(),
                retry_policy: RetryPolicy::new(
                    self.retry_max_attempts,
                    Duration::from_millis(self.retry_initial_delay_millis),
                ),
            },
            stripped_destructive,
        )
    }
}

impl ExportSchedule {
    fn from_schedule(schedule: &ScheduleDefinition) -> Self {
        Self {
            interval_minutes: schedule.interval_minutes(),
            timezone: schedule.timezone().to_owned(),
            enabled: schedule.enabled(),
        }
    }
}

impl From<SyncMode> for ExportSyncMode {
    fn from(mode: SyncMode) -> Self {
        match mode {
            SyncMode::OneWay => Self::OneWay,
            SyncMode::Mirror => Self::Mirror,
        }
    }
}

impl From<ExportSyncMode> for SyncMode {
    fn from(mode: ExportSyncMode) -> Self {
        match mode {
            ExportSyncMode::OneWay => Self::OneWay,
            ExportSyncMode::Mirror => Self::Mirror,
        }
    }
}

impl From<OneWaySource> for ExportOneWaySource {
    fn from(source: OneWaySource) -> Self {
        match source {
            OneWaySource::PeerA => Self::PeerA,
            OneWaySource::PeerB => Self::PeerB,
        }
    }
}

impl From<ExportOneWaySource> for OneWaySource {
    fn from(source: ExportOneWaySource) -> Self {
        match source {
            ExportOneWaySource::PeerA => Self::PeerA,
            ExportOneWaySource::PeerB => Self::PeerB,
        }
    }
}

impl From<DeletionMethod> for ExportDeletionMethod {
    fn from(method: DeletionMethod) -> Self {
        match method {
            DeletionMethod::Trash => Self::Trash,
            DeletionMethod::PermanentRemoval => Self::PermanentRemoval,
        }
    }
}

impl From<PartialTransferPolicy> for ExportPartialTransferPolicy {
    fn from(policy: PartialTransferPolicy) -> Self {
        match policy {
            PartialTransferPolicy::Cleanup => Self::Cleanup,
            PartialTransferPolicy::KeepPartialForResume => Self::KeepPartialForResume,
        }
    }
}

impl From<ExportPartialTransferPolicy> for PartialTransferPolicy {
    fn from(policy: ExportPartialTransferPolicy) -> Self {
        match policy {
            ExportPartialTransferPolicy::Cleanup => Self::Cleanup,
            ExportPartialTransferPolicy::KeepPartialForResume => Self::KeepPartialForResume,
        }
    }
}

fn path_to_string(path: &Path, field: &str) -> Result<String, ConfigurationTransferError> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        invalid(
            field,
            "contains a non-Unicode path that cannot be represented in JSON",
        )
    })
}

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> ConfigurationTransferError {
    ConfigurationTransferError::InvalidConfiguration {
        field: field.into(),
        reason: reason.into(),
    }
}
