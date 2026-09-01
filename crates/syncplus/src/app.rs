use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use eframe::egui;
use syncplus_core::{
    AnalysisOutcome, ApplicationMode, ApplicationSettings, ConflictDecision, ConflictEntry,
    ConflictEntryKey,
    ConflictResolution, ConflictReview, DeletionMethod, FreshAnalysis, LocalPrecheckProbe,
    MetadataRequirements, OneWaySource, PartialTransferPolicy, Peer, PeerEndpoint,
    PersistedSyncProfile, PrecheckErrorKind, PrecheckResult, ResolutionRun, RetryPolicy,
    RunEvidenceStore, RunPrecheck, SavedSecretReference, SecretStore, SecretStoreError,
    SpecialistMetadataRequirements, SshAuthentication, SyncMode, SyncOptions, SyncProfile,
    SyncProfileId, ThemePreference,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Local,
    Ssh,
}

impl Default for EndpointKind {
    fn default() -> Self {
        Self::Local
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiValidationError {
    EmptyProfileName,
    EmptyPeerName { peer: &'static str },
    EmptyLocalPath { peer: &'static str },
    EmptySshServer,
    EmptySshUsername,
    InvalidSshPort,
    EmptySshRemotePath,
    MissingIdentity,
    InvalidSavedSecretReference,
    SavedSecretUnavailable,
    InvalidRetryAttempts,
    InvalidRetryDelay,
    PrecheckBlocked,
    ReviewNotReady,
    StrongerConfirmationRequired,
    UnresolvedItems,
    ConflictReviewNotReady,
    ResolutionRequiresMirror,
    Resolution(String),
    Analysis(String),
    Core(String),
}

impl std::fmt::Display for UiValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyProfileName => formatter.write_str("Profile name is required."),
            Self::EmptyPeerName { peer } => write!(formatter, "{peer} name is required."),
            Self::EmptyLocalPath { peer } => write!(formatter, "{peer} folder is required."),
            Self::EmptySshServer => formatter.write_str("SSH server is required."),
            Self::EmptySshUsername => formatter.write_str("SSH username is required."),
            Self::InvalidSshPort => formatter.write_str("SSH port must be a number from 1 to 65535."),
            Self::EmptySshRemotePath => formatter.write_str("SSH remote folder is required."),
            Self::MissingIdentity => formatter.write_str("Key authentication requires an identity file."),
            Self::InvalidSavedSecretReference => {
                formatter.write_str("Saved password authentication requires a valid keyring reference.")
            }
            Self::SavedSecretUnavailable => {
                formatter.write_str("The saved SSH credential is unavailable in the desktop keyring.")
            }
            Self::InvalidRetryAttempts => {
                formatter.write_str("Retry attempts must be a whole number from 1 to 10.")
            }
            Self::InvalidRetryDelay => {
                formatter.write_str("Retry delay must be between 0 and 3,600,000 milliseconds.")
            }
            Self::PrecheckBlocked => {
                formatter.write_str("The non-mutating precheck found blockers; execution is not available.")
            }
            Self::ReviewNotReady => {
                formatter.write_str("Run Fresh Analysis before requesting Execution Confirmation.")
            }
            Self::StrongerConfirmationRequired => {
                formatter.write_str("Type the exact high-risk source path before confirming this review.")
            }
            Self::UnresolvedItems => {
                formatter.write_str("Unresolved or unsupported items must be resolved before confirmation.")
            }
            Self::ConflictReviewNotReady => {
                formatter.write_str("Run Fresh Analysis for a Mirror Sync before opening Conflict Review.")
            }
            Self::ResolutionRequiresMirror => {
                formatter.write_str("Conflict Review and Resolution Runs require Mirror Sync.")
            }
            Self::Resolution(message) => write!(formatter, "Resolution Run could not proceed: {message}"),
            Self::Analysis(message) => write!(formatter, "Fresh Analysis could not be completed: {message}"),
            Self::Core(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UiValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointForm {
    name: String,
    kind: EndpointKind,
    local_path: String,
    server: String,
    username: String,
    port: String,
    identity: String,
    secret_reference: String,
    remote_path: String,
    authentication: AuthenticationForm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticationForm {
    Key,
    Agent,
    InteractivePassword,
    SavedPassword,
}

impl Default for AuthenticationForm {
    fn default() -> Self {
        Self::Key
    }
}

impl Default for EndpointForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: EndpointKind::Local,
            local_path: String::new(),
            server: String::new(),
            username: String::new(),
            port: "22".to_owned(),
            identity: String::new(),
            secret_reference: String::new(),
            remote_path: String::new(),
            authentication: AuthenticationForm::default(),
        }
    }
}

impl EndpointForm {
    fn source_defaults() -> Self {
        Self {
            name: "Source".to_owned(),
            ..Self::default()
        }
    }

    fn destination_defaults() -> Self {
        Self {
            name: "Destination".to_owned(),
            ..Self::default()
        }
    }

    fn from_peer(peer: &Peer) -> Self {
        let mut form = Self {
            name: peer.name().to_owned(),
            ..Self::default()
        };
        match peer.endpoint() {
            PeerEndpoint::Local { root } => form.local_path = root.display().to_string(),
            PeerEndpoint::Ssh(ssh) => {
                form.kind = EndpointKind::Ssh;
                form.server = ssh.server().to_owned();
                form.username = ssh.username().to_owned();
                form.port = ssh.port().to_string();
                form.identity = ssh
                    .identity()
                    .map(|identity| identity.display().to_string())
                    .unwrap_or_default();
                form.remote_path = ssh.remote_path().display().to_string();
                form.authentication = match ssh.authentication() {
                    SshAuthentication::Key => AuthenticationForm::Key,
                    SshAuthentication::Agent => AuthenticationForm::Agent,
                    SshAuthentication::InteractivePassword => AuthenticationForm::InteractivePassword,
                    SshAuthentication::SavedPassword(reference) => {
                        form.secret_reference = reference.as_str().to_owned();
                        AuthenticationForm::SavedPassword
                    }
                };
            }
        }
        form
    }

    fn build(&self, label: &'static str) -> Result<Peer, UiValidationError> {
        if self.name.trim().is_empty() {
            return Err(UiValidationError::EmptyPeerName { peer: label });
        }
        match self.kind {
            EndpointKind::Local => {
                if self.local_path.trim().is_empty() {
                    return Err(UiValidationError::EmptyLocalPath { peer: label });
                }
                Ok(Peer::new(self.name.trim(), PathBuf::from(&self.local_path)))
            }
            EndpointKind::Ssh => {
                if self.server.trim().is_empty() {
                    return Err(UiValidationError::EmptySshServer);
                }
                if self.username.trim().is_empty() {
                    return Err(UiValidationError::EmptySshUsername);
                }
                let port = self
                    .port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or(UiValidationError::InvalidSshPort)?;
                if self.remote_path.trim().is_empty() {
                    return Err(UiValidationError::EmptySshRemotePath);
                }
                let entered_identity = (!self.identity.trim().is_empty())
                    .then(|| PathBuf::from(self.identity.trim()));
                let authentication = match self.authentication {
                    AuthenticationForm::Key => {
                        if entered_identity.is_none() {
                            return Err(UiValidationError::MissingIdentity);
                        }
                        SshAuthentication::Key
                    }
                    AuthenticationForm::Agent => SshAuthentication::Agent,
                    AuthenticationForm::InteractivePassword => SshAuthentication::InteractivePassword,
                    AuthenticationForm::SavedPassword => {
                        let reference = SavedSecretReference::new(self.secret_reference.trim())
                            .map_err(|_| UiValidationError::InvalidSavedSecretReference)?;
                        SshAuthentication::SavedPassword(reference)
                    }
                };
                let identity = matches!(&authentication, SshAuthentication::Key)
                    .then_some(entered_identity)
                    .flatten();
                Peer::ssh(
                    self.name.trim(),
                    self.server.trim(),
                    self.username.trim(),
                    port,
                    identity,
                    authentication,
                    self.remote_path.trim(),
                )
                .map_err(|error| UiValidationError::Core(error.to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileForm {
    id: Option<SyncProfileId>,
    name: String,
    peer_a: EndpointForm,
    peer_b: EndpointForm,
    mode: SyncMode,
    source: OneWaySource,
    safe_delete: bool,
    destination_cleanup: bool,
    exclusions: String,
    timestamps: bool,
    ownership: bool,
    access_control_lists: bool,
    extended_attributes: bool,
    partial_transfer_policy: PartialTransferPolicy,
    retry_attempts: String,
    retry_delay_millis: String,
}

impl Default for ProfileForm {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            peer_a: EndpointForm::source_defaults(),
            peer_b: EndpointForm::destination_defaults(),
            mode: SyncMode::OneWay,
            source: OneWaySource::PeerA,
            safe_delete: false,
            destination_cleanup: false,
            exclusions: String::new(),
            timestamps: false,
            ownership: false,
            access_control_lists: false,
            extended_attributes: false,
            partial_transfer_policy: PartialTransferPolicy::Cleanup,
            retry_attempts: RetryPolicy::default().max_attempts().to_string(),
            retry_delay_millis: RetryPolicy::default().initial_delay().as_millis().to_string(),
        }
    }
}

impl ProfileForm {
    fn from_persisted(profile: &PersistedSyncProfile) -> Self {
        let value = profile.profile();
        let options = value.options();
        let metadata = options.metadata;
        let specialist = metadata.specialist_metadata();
        Self {
            id: Some(profile.id()),
            name: value.name().to_owned(),
            peer_a: EndpointForm::from_peer(value.peer_a()),
            peer_b: EndpointForm::from_peer(value.peer_b()),
            mode: value.mode(),
            source: value.source(),
            safe_delete: options.safe_delete,
            destination_cleanup: options.destination_cleanup,
            exclusions: value.exclusions().join("\n"),
            timestamps: metadata.timestamps(),
            ownership: specialist.ownership(),
            access_control_lists: specialist.access_control_lists(),
            extended_attributes: specialist.extended_attributes(),
            partial_transfer_policy: options.partial_transfer_policy,
            retry_attempts: options.retry_policy.max_attempts().to_string(),
            retry_delay_millis: options.retry_policy.initial_delay().as_millis().to_string(),
        }
    }

    fn build(&self) -> Result<SyncProfile, UiValidationError> {
        if self.name.trim().is_empty() {
            return Err(UiValidationError::EmptyProfileName);
        }
        let peer_a = self.peer_a.build("Source")?;
        let peer_b = self.peer_b.build("Destination")?;
        let retry_attempts = self
            .retry_attempts
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|attempts| (1..=10).contains(attempts))
            .ok_or(UiValidationError::InvalidRetryAttempts)?;
        let retry_delay_millis = self
            .retry_delay_millis
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|delay| *delay <= 3_600_000)
            .ok_or(UiValidationError::InvalidRetryDelay)?;
        let mut options = SyncOptions::default();
        options.safe_delete = self.safe_delete;
        options.destination_cleanup = self.destination_cleanup;
        options.deletion_method = self.safe_delete.then_some(DeletionMethod::Trash);
        options.metadata = MetadataRequirements::new(true, true, true, self.timestamps)
            .with_specialist_metadata(SpecialistMetadataRequirements::new(
                self.ownership,
                self.access_control_lists,
                self.extended_attributes,
            ));
        options.partial_transfer_policy = self.partial_transfer_policy;
        options.retry_policy = RetryPolicy::new(retry_attempts, Duration::from_millis(retry_delay_millis));
        let exclusions = self
            .exclusions
            .lines()
            .map(str::trim)
            .filter(|pattern| !pattern.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Ok(SyncProfile::new(self.name.trim(), peer_a, peer_b)
            .with_mode(self.mode)
            .with_source(self.source)
            .with_options(options)
            .with_exclusions(exclusions))
    }
}

#[derive(Debug, Clone)]
struct ConflictReviewState {
    review: ConflictReview,
    decisions: BTreeMap<ConflictEntryKey, ConflictResolution>,
    resolution_run: Option<ResolutionRun>,
    confirmed: bool,
    error: Option<String>,
}

impl ConflictReviewState {
    fn from_analysis(analysis: &FreshAnalysis) -> Self {
        Self {
            review: analysis.conflict_review(),
            decisions: BTreeMap::new(),
            resolution_run: None,
            confirmed: false,
            error: None,
        }
    }

    fn has_all_decisions(&self) -> bool {
        self.review
            .entries()
            .iter()
            .filter(|entry| !entry.available_resolutions().is_empty())
            .all(|entry| self.decisions.contains_key(&entry.key()))
    }
}

#[derive(Debug, Clone)]
struct PlanReviewState {
    profile: SyncProfile,
    precheck: Option<PrecheckResult>,
    analysis: Option<FreshAnalysis>,
    conflicts: Option<ConflictReviewState>,
    error: Option<String>,
    stronger_confirmation_path: String,
    confirmed: bool,
}

pub struct SyncPlusApp {
    store: RunEvidenceStore,
    secret_store: Box<dyn SecretStore>,
    settings: ApplicationSettings,
    profiles: Vec<PersistedSyncProfile>,
    form: ProfileForm,
    status: String,
    review: Option<PlanReviewState>,
}

impl SyncPlusApp {
    pub fn new() -> Result<Self, syncplus_core::StorageError> {
        Self::new_with_store(RunEvidenceStore::open_canonical()?)
    }

    pub fn new_with_store(store: RunEvidenceStore) -> Result<Self, syncplus_core::StorageError> {
        Self::new_with_store_and_secret_store(store, syncplus_core::DesktopKeyring::new())
    }

    pub fn new_with_store_and_secret_store<S: SecretStore + 'static>(
        store: RunEvidenceStore,
        secret_store: S,
    ) -> Result<Self, syncplus_core::StorageError> {
        let settings = store.load_settings()?;
        let profiles = store.list_profiles()?;
        Ok(Self {
            store,
            secret_store: Box::new(secret_store),
            settings,
            profiles,
            form: ProfileForm::default(),
            status: "Ready. Create a Sync Profile to begin.".to_owned(),
            review: None,
        })
    }

    pub fn mode(&self) -> ApplicationMode {
        self.settings.mode()
    }

    pub fn theme(&self) -> ThemePreference {
        self.settings.theme()
    }

    pub fn profiles(&self) -> &[PersistedSyncProfile] {
        &self.profiles
    }

    pub fn status(&self) -> &str {
        &self.status
    }

    pub fn start_new_profile(&mut self) {
        self.form = ProfileForm::default();
        self.review = None;
        self.status = "New profile: One-Way Sync is selected and destructive actions are off.".to_owned();
    }

    pub fn set_mode(&mut self, mode: ApplicationMode) {
        self.settings = ApplicationSettings::new(mode, self.settings.theme());
        if let Err(error) = self.store.save_settings(&self.settings) {
            self.status = format!("Could not save mode preference: {error}");
        } else {
            self.status = format!("{} Mode enabled.", mode_label(mode));
        }
    }

    pub fn set_theme(&mut self, theme: ThemePreference) {
        self.settings = ApplicationSettings::new(self.settings.mode(), theme);
        if let Err(error) = self.store.save_settings(&self.settings) {
            self.status = format!("Could not save theme preference: {error}");
        }
    }

    pub fn validate_profile(&mut self) -> Result<(), UiValidationError> {
        self.validated_profile()?;
        self.status = "Profile is valid. No run has been started.".to_owned();
        Ok(())
    }

    pub fn save_profile(&mut self) -> Result<SyncProfileId, UiValidationError> {
        let profile = self.validated_profile()?;
        let persisted = match self.form.id {
            Some(id) => self
                .store
                .update_profile(id, &profile)
                .map_err(|error| UiValidationError::Core(error.to_string()))?,
            None => self
                .store
                .create_profile(&profile)
                .map_err(|error| UiValidationError::Core(error.to_string()))?,
        };
        let id = persisted.id();
        self.form = ProfileForm::from_persisted(&persisted);
        self.review = None;
        self.profiles = self
            .store
            .list_profiles()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        self.status = "Profile saved. Changes apply to future runs; an active run keeps its Profile Snapshot.".to_owned();
        Ok(id)
    }

    fn validated_profile(&self) -> Result<SyncProfile, UiValidationError> {
        let profile = self.form.build()?;
        syncplus_core::ProcessSpecification::from_profile(&profile)
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        for peer in [profile.peer_a(), profile.peer_b()] {
            if let Some(ssh) = peer.ssh_peer() {
                if let SshAuthentication::SavedPassword(reference) = ssh.authentication() {
                    self.secret_store
                        .load(&reference)
                        .map(|_| ())
                        .map_err(|error| match error {
                            SecretStoreError::Missing | SecretStoreError::Unavailable => {
                                UiValidationError::SavedSecretUnavailable
                            }
                        })?;
                }
            }
        }
        Ok(profile)
    }

    pub fn analyze_profile(&mut self) -> Result<(), UiValidationError> {
        let profile = self.validated_profile()?;
        let precheck = match Self::fresh_local_precheck(&profile) {
            Ok(result) => result,
            Err(message) => {
                self.store_review_failure(profile, None, message.clone());
                self.status = format!("Fresh precheck could not complete: {message}");
                return Err(UiValidationError::Core(message));
            }
        };

        if !precheck.can_execute() {
            let analysis = FreshAnalysis::analyze(&profile).ok();
            let conflicts = analysis.as_ref().and_then(|analysis| {
                (profile.mode() == SyncMode::Mirror).then(|| {
                    ConflictReviewState::from_analysis(analysis)
                })
            });
            self.review = Some(PlanReviewState {
                profile,
                precheck: Some(precheck),
                analysis,
                conflicts,
                error: None,
                stronger_confirmation_path: String::new(),
                confirmed: false,
            });
            self.status = "Fresh precheck found blockers; execution is not available.".to_owned();
            return Err(UiValidationError::PrecheckBlocked);
        }

        let analysis = match FreshAnalysis::analyze(&profile) {
            Ok(analysis) => analysis,
            Err(error) => {
                let message = error.to_string();
                self.store_review_failure(profile, Some(precheck), message.clone());
                self.status = format!("Fresh Analysis could not complete: {message}");
                return Err(UiValidationError::Analysis(message));
            }
        };
        let conflicts = (profile.mode() == SyncMode::Mirror)
            .then(|| ConflictReviewState::from_analysis(&analysis));

        self.review = Some(PlanReviewState {
            profile,
            precheck: Some(precheck),
            conflicts,
            analysis: Some(analysis),
            error: None,
            stronger_confirmation_path: String::new(),
            confirmed: false,
        });
        self.status = "Fresh Analysis ready. Review the plan and consequences before confirmation.".to_owned();
        Ok(())
    }

    pub fn conflict_entries(&self) -> Option<&[ConflictEntry]> {
        self.review
            .as_ref()
            .and_then(|review| review.conflicts.as_ref())
            .map(|conflicts| conflicts.review.entries())
    }

    pub fn conflict_resolution(&self, relative_path: impl Into<PathBuf>) -> Option<ConflictResolution> {
        let relative_path = relative_path.into();
        let review = self.review.as_ref()?;
        let conflicts = review.conflicts.as_ref()?;
        let entries = conflicts
            .review
            .entries()
            .iter()
            .filter(|entry| entry.relative_path() == relative_path)
            .collect::<Vec<_>>();
        (entries.len() == 1)
            .then(|| conflicts.decisions.get(&entries[0].key()).copied())
            .flatten()
    }

    pub fn conflict_entry_resolution(
        &self,
        key: &ConflictEntryKey,
    ) -> Option<ConflictResolution> {
        self.review
            .as_ref()
            .and_then(|review| review.conflicts.as_ref())
            .and_then(|conflicts| conflicts.decisions.get(key).copied())
    }

    pub fn set_conflict_resolution(
        &mut self,
        relative_path: impl Into<PathBuf>,
        resolution: ConflictResolution,
    ) -> Result<(), UiValidationError> {
        let relative_path = relative_path.into();
        let key = {
            let review = self
                .review
                .as_ref()
                .ok_or(UiValidationError::ConflictReviewNotReady)?;
            let conflicts = review
                .conflicts
                .as_ref()
                .ok_or(UiValidationError::ConflictReviewNotReady)?;
            let mut entries = conflicts
                .review
                .entries()
                .iter()
                .filter(|entry| entry.relative_path() == relative_path);
            let entry = entries
                .next()
                .ok_or_else(|| UiValidationError::Resolution(format!("no reviewed conflict exists for {}", relative_path.display())))?;
            if entries.next().is_some() {
                return Err(UiValidationError::Resolution(format!(
                    "multiple reviewed conflicts use {}; select the typed conflict row",
                    relative_path.display()
                )));
            }
            entry.key()
        };
        self.set_conflict_entry_resolution(&key, resolution)
    }

    pub fn set_conflict_entry_resolution(
        &mut self,
        key: &ConflictEntryKey,
        resolution: ConflictResolution,
    ) -> Result<(), UiValidationError> {
        let conflicts = self
            .review
            .as_mut()
            .and_then(|review| review.conflicts.as_mut())
            .ok_or(UiValidationError::ConflictReviewNotReady)?;
        let entry = conflicts
            .review
            .entries()
            .iter()
            .find(|entry| entry.key() == *key)
            .ok_or_else(|| {
                UiValidationError::Resolution(format!(
                    "no reviewed conflict exists for {}",
                    key.relative_path().display()
                ))
            })?;
        if !entry.available_resolutions().contains(&resolution) {
            return Err(UiValidationError::Resolution(format!(
                "{} is not a safe decision for a {} conflict; preserve or defer it for review",
                resolution_label(resolution),
                conflict_kind_label(entry.kind())
            )));
        }
        conflicts.decisions.insert(key.clone(), resolution);
        conflicts.resolution_run = None;
        conflicts.confirmed = false;
        conflicts.error = None;
        self.status = format!(
            "Selected {} for {}. Start a fresh Resolution Run review before any confirmation.",
            resolution_label(resolution),
            key.relative_path().display()
        );
        Ok(())
    }

    pub fn start_resolution_run(&mut self) -> Result<(), UiValidationError> {
        let current_profile = self.validated_profile()?;
        let precheck = Self::fresh_local_precheck(&current_profile).map_err(|message| {
            self.status = format!("Fresh precheck could not complete: {message}");
            UiValidationError::Core(message)
        })?;
        if !precheck.can_execute() {
            if let Some(review) = self.review.as_mut() {
                review.precheck = Some(precheck);
                review.confirmed = false;
                review.error = Some("fresh precheck found blockers".to_owned());
            }
            self.status = "Fresh precheck found blockers; Resolution Run remains unavailable.".to_owned();
            return Err(UiValidationError::PrecheckBlocked);
        }
        let (reviewed_profile, reviewed_analysis, decisions) = {
            let review = self
                .review
                .as_ref()
                .ok_or(UiValidationError::ConflictReviewNotReady)?;
            let conflicts = review
                .conflicts
                .as_ref()
                .ok_or(UiValidationError::ResolutionRequiresMirror)?;
            if review.profile.mode() != SyncMode::Mirror {
                return Err(UiValidationError::ResolutionRequiresMirror);
            }
            if review.profile != current_profile {
                return Err(UiValidationError::Resolution(
                    "the profile changed; run Fresh Analysis again before reviewing conflicts".to_owned(),
                ));
            }
            if !conflicts.has_all_decisions() {
                return Err(UiValidationError::UnresolvedItems);
            }
            let decisions = conflicts
                .review
                .entries()
                .iter()
                .map(|entry| {
                    ConflictDecision::for_entry(entry, conflicts.decisions[&entry.key()])
                })
                .collect::<Vec<_>>();
            let reviewed_analysis = review
                .analysis
                .clone()
                .ok_or(UiValidationError::ConflictReviewNotReady)?;
            (review.profile.clone(), reviewed_analysis, decisions)
        };

        let fresh_analysis = FreshAnalysis::analyze(&reviewed_profile)
            .map_err(|error| UiValidationError::Resolution(error.to_string()))?;
        let changed_paths = reviewed_analysis
            .revision()
            .changed_paths(&fresh_analysis.revision());
        if !changed_paths.is_empty() {
            let message = format!(
                "the reviewed conflict state changed for {changed_paths:?}; run Fresh Analysis again"
            );
            if let Some(review) = self.review.as_mut() {
                if let Some(conflicts) = review.conflicts.as_mut() {
                    conflicts.confirmed = false;
                    conflicts.error = Some(message.clone());
                }
            }
            self.status = format!("Resolution Run was not started: {message}");
            return Err(UiValidationError::Resolution(message));
        }
        let plan = fresh_analysis
            .resolve_conflicts(decisions)
            .map_err(|error| UiValidationError::Resolution(error.to_string()))?;
        let resolution_run = ResolutionRun::from_analysis(&fresh_analysis, plan, None)
            .map_err(|error| UiValidationError::Resolution(error.to_string()))?;
        if let Some(review) = self.review.as_mut() {
            if let Some(conflicts) = review.conflicts.as_mut() {
                conflicts.resolution_run = Some(resolution_run);
                conflicts.confirmed = false;
                conflicts.error = None;
            }
            review.precheck = Some(precheck);
        }
        self.status = "Resolution Run review started after Fresh Analysis. Review every whole-file decision before confirmation.".to_owned();
        Ok(())
    }

    pub fn confirm_resolution_run(&mut self) -> Result<(), UiValidationError> {
        let current_profile = self.validated_profile()?;
        let precheck = Self::fresh_local_precheck(&current_profile).map_err(|message| {
            self.status = format!("Fresh precheck could not complete: {message}");
            UiValidationError::Core(message)
        })?;
        if !precheck.can_execute() {
            if let Some(review) = self.review.as_mut() {
                review.precheck = Some(precheck);
                if let Some(conflicts) = review.conflicts.as_mut() {
                    conflicts.confirmed = false;
                    conflicts.error = Some("fresh precheck found blockers".to_owned());
                }
            }
            self.status = "Fresh precheck found blockers; Resolution Run confirmation remains unavailable.".to_owned();
            return Err(UiValidationError::PrecheckBlocked);
        }
        let resolution_run = self
            .review
            .as_ref()
            .and_then(|review| review.conflicts.as_ref())
            .and_then(|conflicts| conflicts.resolution_run.as_ref())
            .cloned()
            .ok_or(UiValidationError::ConflictReviewNotReady)?;
        if let Some(review) = self.review.as_mut() {
            review.precheck = Some(precheck);
        }
        resolution_run
            .prepare(&current_profile, None, true)
            .map_err(|error| {
                if let Some(review) = self.review.as_mut() {
                    if let Some(conflicts) = review.conflicts.as_mut() {
                        conflicts.confirmed = false;
                        conflicts.error = Some(error.to_string());
                    }
                }
                UiValidationError::Resolution(error.to_string())
            })?;
        if let Some(review) = self.review.as_mut() {
            if let Some(conflicts) = review.conflicts.as_mut() {
                conflicts.confirmed = true;
                conflicts.error = None;
            }
        }
        self.status = "Resolution Run confirmation recorded for this exact reviewed scope; no filesystem mutation has started.".to_owned();
        Ok(())
    }

    pub fn resolution_is_confirmed(&self) -> bool {
        self.review
            .as_ref()
            .and_then(|review| review.conflicts.as_ref())
            .is_some_and(|conflicts| conflicts.confirmed)
    }

    pub fn confirm_review(&mut self) -> Result<(), UiValidationError> {
        if self.review.is_none() {
            return Err(UiValidationError::ReviewNotReady);
        }

        let current_profile = self.validated_profile()?;
        let precheck = match Self::fresh_local_precheck(&current_profile) {
            Ok(result) => result,
            Err(message) => {
                if let Some(review) = self.review.as_mut() {
                    review.precheck = None;
                    review.confirmed = false;
                    review.error = Some(message.clone());
                }
                self.status = format!("Fresh precheck could not complete: {message}");
                return Err(UiValidationError::Core(message));
            }
        };

        if let Some(review) = self.review.as_mut() {
            review.precheck = Some(precheck.clone());
            review.confirmed = false;
            review.error = None;
        }
        if !precheck.can_execute() {
            self.status = "Fresh precheck found blockers; execution remains unavailable.".to_owned();
            return Err(UiValidationError::PrecheckBlocked);
        }

        let unresolved = self
            .review
            .as_ref()
            .and_then(|review| review.analysis.as_ref())
            .is_some_and(analysis_has_unresolved_items);
        if unresolved {
            self.status = "Unresolved or unsupported items remain; execution is unavailable.".to_owned();
            return Err(UiValidationError::UnresolvedItems);
        }

        let stronger_confirmation = self
            .review
            .as_ref()
            .is_some_and(|review| stronger_confirmation_satisfied(review, &precheck));
        if !precheck.is_confirmation_sufficient(stronger_confirmation) {
            self.status = "The high-risk precheck warning requires the exact source path before confirmation.".to_owned();
            return Err(UiValidationError::StrongerConfirmationRequired);
        }

        let confirmation = self
            .review
            .as_ref()
            .and_then(|review| review.analysis.as_ref())
            .ok_or(UiValidationError::ReviewNotReady)
            .and_then(|analysis| {
                analysis
                    .confirm(&current_profile)
                    .map(|_| ())
                    .map_err(|error| UiValidationError::Analysis(error.to_string()))
            });
        if let Err(error) = confirmation {
            if let Some(review) = self.review.as_mut() {
                review.confirmed = false;
                review.error = Some(error.to_string());
            }
            self.status = format!("Execution Confirmation is no longer valid: {error}");
            return Err(error);
        }

        if let Some(review) = self.review.as_mut() {
            review.confirmed = true;
        }
        self.status = "Execution Confirmation recorded for this reviewed scope; no filesystem mutation has started.".to_owned();
        Ok(())
    }

    fn fresh_local_precheck(profile: &SyncProfile) -> Result<PrecheckResult, String> {
        if profile.peer_a().is_ssh() || profile.peer_b().is_ssh() {
            return Err(
                "SSH review is blocked until the typed SSH host-identity, credential, remote capability, and recovery precheck is supplied by the SSH workflow.".to_owned(),
            );
        }
        RunPrecheck::check(profile, &LocalPrecheckProbe::default())
            .map_err(|error| format_precheck_error(&error))
    }

    fn store_review_failure(
        &mut self,
        profile: SyncProfile,
        precheck: Option<PrecheckResult>,
        message: String,
    ) {
        self.review = Some(PlanReviewState {
            profile,
            precheck,
            analysis: None,
            conflicts: None,
            error: Some(message),
            stronger_confirmation_path: String::new(),
            confirmed: false,
        });
    }

    fn clear_review(&mut self) {
        self.review = None;
    }

    fn select_profile(&mut self, id: SyncProfileId) {
        if let Some(profile) = self.profiles.iter().find(|profile| profile.id() == id) {
            self.form = ProfileForm::from_persisted(profile);
            self.review = None;
            self.status = format!("Editing {}. Changes apply to future runs.", profile.profile().name());
        }
    }

    fn apply_theme(&self, context: &egui::Context) {
        let preference = match self.settings.theme() {
            ThemePreference::System => egui::ThemePreference::System,
            ThemePreference::Light => egui::ThemePreference::Light,
            ThemePreference::Dark => egui::ThemePreference::Dark,
        };
        context.set_theme(preference);
    }

    fn draw_settings(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Mode:");
            if ui
                .radio(self.settings.mode() == ApplicationMode::Simple, "Simple")
                .clicked()
            {
                self.set_mode(ApplicationMode::Simple);
            }
            if ui
                .radio(self.settings.mode() == ApplicationMode::Advanced, "Advanced")
                .clicked()
            {
                self.set_mode(ApplicationMode::Advanced);
            }
            ui.separator();
            ui.label("Theme:");
            for (theme, label) in [
                (ThemePreference::System, "System"),
                (ThemePreference::Light, "Light"),
                (ThemePreference::Dark, "Dark"),
            ] {
                if ui.radio(self.settings.theme() == theme, label).clicked() {
                    self.set_theme(theme);
                }
            }
        });
    }

    fn draw_profile_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Sync Profiles");
        if ui.button("New profile").clicked() {
            self.start_new_profile();
        }
        ui.separator();
        let profiles = self
            .profiles
            .iter()
            .map(|profile| (profile.id(), profile.profile().name().to_owned()))
            .collect::<Vec<_>>();
        for (id, name) in &profiles {
            if ui
                .selectable_label(self.form.id == Some(*id), name)
                .clicked()
            {
                self.select_profile(*id);
            }
        }
        if profiles.is_empty() {
            ui.label("No profiles saved yet.");
        }
    }

    fn draw_profile_form(&mut self, ui: &mut egui::Ui) {
        let form_before_draw = self.form.clone();
        ui.heading("Sync Profile");
        ui.label("Define named endpoints and safety settings. SyncPlus never accepts arbitrary rsync arguments.");
        ui.horizontal(|ui| {
            ui.label("Profile name");
            ui.text_edit_singleline(&mut self.form.name);
        });
        ui.separator();
        draw_endpoint(ui, "Source endpoint", &mut self.form.peer_a);
        draw_endpoint(ui, "Destination endpoint", &mut self.form.peer_b);
        ui.separator();
        ui.label("Sync method");
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.form.mode, SyncMode::OneWay, "One-Way Sync (recommended)");
            ui.radio_value(&mut self.form.mode, SyncMode::Mirror, "Mirror Sync (review required)");
        });
        if self.form.mode == SyncMode::OneWay {
            ui.horizontal(|ui| {
                ui.label("Authoritative source");
                ui.radio_value(&mut self.form.source, OneWaySource::PeerA, "Source endpoint");
                ui.radio_value(&mut self.form.source, OneWaySource::PeerB, "Destination endpoint");
            });
        }
        ui.collapsing("Exclusion Rules", |ui| {
            ui.label("One pattern per line. Excluded items are neither synchronized nor deleted.");
            ui.add(egui::TextEdit::multiline(&mut self.form.exclusions).desired_rows(3));
        });
        if self.settings.mode() == ApplicationMode::Advanced {
            ui.collapsing("Advanced safety options", |ui| {
                ui.checkbox(&mut self.form.safe_delete, "One-Way Safe-Delete Sync");
                ui.checkbox(&mut self.form.destination_cleanup, "Destination Cleanup");
                ui.separator();
                ui.label("Metadata preservation (validated named options)");
                ui.checkbox(&mut self.form.timestamps, "Preserve and verify timestamps");
                ui.checkbox(&mut self.form.ownership, "Preserve ownership");
                ui.checkbox(&mut self.form.access_control_lists, "Preserve access-control lists");
                ui.checkbox(&mut self.form.extended_attributes, "Preserve extended attributes");
                ui.separator();
                ui.label("Transfer resilience");
                ui.horizontal(|ui| {
                    ui.label("Partial transfer");
                    ui.radio_value(
                        &mut self.form.partial_transfer_policy,
                        PartialTransferPolicy::Cleanup,
                        "Clean up failed partial files",
                    );
                    ui.radio_value(
                        &mut self.form.partial_transfer_policy,
                        PartialTransferPolicy::KeepPartialForResume,
                        "Keep for reviewed resume",
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Retry attempts");
                    ui.add(egui::TextEdit::singleline(&mut self.form.retry_attempts).desired_width(55.0));
                    ui.label("Initial delay (ms)");
                    ui.add(egui::TextEdit::singleline(&mut self.form.retry_delay_millis).desired_width(75.0));
                });
                ui.label("Transport is selected through the typed Local or SSH endpoint fields. Command editing is not available.");
                ui.label("These options remain subject to Fresh Analysis, verification, and explicit Execution Confirmation.");
            });
        } else {
            ui.label("Simple Mode keeps destructive options hidden. Switch to Advanced Mode to review them.");
        }
        ui.collapsing("Help & safety", |ui| {
            ui.label("What: Simple Mode provides a calm, non-destructive One-Way Sync profile editor.");
            ui.label("Why: new profiles start with source-authoritative copying and no deletion, cleanup, schedules, or unattended destructive authorization.");
            ui.label("How: choose named local folders or one SSH peer, validate the fields, then save. The core creates the same typed Process Specification used later for execution.");
            ui.label("When: Fresh Analysis, precheck, and one final Execution Confirmation are required before a file-changing run.");
            ui.label("Limits: Mirror Sync has no implicit winner; excluded, unavailable, changed, or ambiguous items remain visible for review. Passwords stay in the desktop keyring and only an opaque reference is kept in the profile.");
        });
        ui.horizontal(|ui| {
            if ui.button("Analyze current state").clicked() {
                if let Err(error) = self.analyze_profile() {
                    self.status = format!("Plan review is not ready: {error}");
                }
            }
            if ui.button("Validate").clicked() {
                if let Err(error) = self.validate_profile() {
                    self.status = format!("Profile is not valid: {error}");
                }
            }
            if ui.button("Save profile").clicked() {
                if let Err(error) = self.save_profile() {
                    self.status = format!("Profile was not saved: {error}");
                }
            }
        });
        if self.form != form_before_draw {
            self.clear_review();
            self.status = "Profile changed. Fresh Analysis and confirmation are required again.".to_owned();
        }
    }

    fn draw_review(&mut self, ui: &mut egui::Ui) {
        let mut request_confirmation = false;
        let mut request_resolution_start = false;
        let mut request_resolution_confirmation = false;
        ui.separator();
        ui.heading("Plan review and Execution Confirmation");

        if let Some(review) = self.review.as_mut() {
            ui.label("This is a read-only review of the current profile. No filesystem mutation starts from this view.");
            ui.group(|ui| {
                ui.label("Folder mapping");
                let (source_peer, destination_peer) = mapped_peers(&review.profile);
                let source = source_peer.root().display().to_string();
                let destination = destination_peer.root().display().to_string();
                if review.profile.mode() == SyncMode::OneWay {
                    ui.label(format!("Selected source folder: {source}"));
                    ui.label(format!("Selected destination folder: {destination}"));
                    ui.label("One-Way Sync copies the selected source folder's contents into the selected destination folder.");
                } else {
                    ui.label(format!("Peer A folder: {}", review.profile.peer_a().root().display()));
                    ui.label(format!("Peer B folder: {}", review.profile.peer_b().root().display()));
                    ui.label("Mirror Sync reviews both folder directions independently; neither folder is an implicit winner.");
                }
                ui.label("A trailing separator marks the selected path as a folder; it does not select a parent folder or widen the reviewed root. Actions below are relative to these exact selected roots.");
                ui.label("The reviewed typed Process Specification below is authoritative for execution.");
            });

            if let Some(error) = &review.error {
                ui.group(|ui| {
                    ui.label("Review status: not ready");
                    ui.label(error);
                });
            }

            if let Some(precheck) = &review.precheck {
                ui.group(|ui| {
                    ui.label(if precheck.can_execute() {
                        "Fresh precheck: passed (no blockers)"
                    } else {
                        "Fresh precheck: blocked"
                    });
                    for blocker in precheck.blockers() {
                        ui.label(format!(
                            "BLOCKER [{:?}] {} — {}. Remediation: {}",
                            blocker.kind(),
                            blocker.path().display(),
                            blocker.reason(),
                            blocker.remediation()
                        ));
                        ui.label(format!("Requirement: {}", blocker.requirement()));
                    }
                    for warning in precheck.warnings() {
                        ui.label(format!("WARNING: {}", warning.explanation()));
                    }
                    if precheck.blockers().is_empty() && precheck.warnings().is_empty() {
                        ui.label("No precheck warnings or blockers were reported.");
                    }
                    draw_compatibility_review(ui, precheck);
                });
            }

            if let Some(analysis) = review.analysis.clone() {
                draw_analysis_review(ui, review, &analysis);
                if review.profile.mode() == SyncMode::Mirror {
                    match draw_conflict_review(ui, review) {
                        ConflictReviewAction::StartResolutionRun => request_resolution_start = true,
                        ConflictReviewAction::ConfirmResolutionRun => {
                            request_resolution_confirmation = true;
                        }
                        ConflictReviewAction::None => {}
                    }
                }
                let unresolved = analysis_has_unresolved_items(&analysis);
                let conflicts_pending = review
                    .conflicts
                    .as_ref()
                    .is_some_and(|conflicts| !conflicts.review.entries().is_empty());
                let precheck_ready = review
                    .precheck
                    .as_ref()
                    .is_some_and(PrecheckResult::can_execute);
                let stronger_required = review
                    .precheck
                    .as_ref()
                    .is_some_and(PrecheckResult::requires_stronger_confirmation);
                let stronger_confirmation = review
                    .precheck
                    .as_ref()
                    .is_some_and(|precheck| stronger_confirmation_satisfied(review, precheck));
                let can_confirm = precheck_ready
                    && !unresolved
                    && !conflicts_pending
                    && (!stronger_required || stronger_confirmation);
                ui.group(|ui| {
                    ui.label("Final Execution Confirmation");
                    draw_confirmation_summary(ui, review, &analysis);
                    if stronger_required {
                        ui.label("This high-risk source scope requires stronger confirmation. Type the exact source path shown in the mapping above:");
                        ui.text_edit_singleline(&mut review.stronger_confirmation_path);
                    }
                    if review.confirmed {
                        ui.label("Execution Confirmation recorded. No filesystem mutation has started.");
                    } else if ui
                        .add_enabled(
                            can_confirm,
                            egui::Button::new("Confirm this exact reviewed scope"),
                        )
                        .clicked()
                    {
                        request_confirmation = true;
                    }
                    if unresolved && !review.confirmed {
                        ui.label("Confirmation is unavailable while unresolved or unsupported items remain.");
                    } else if conflicts_pending && !review.confirmed {
                        ui.label("Ordinary sync confirmation is unavailable while Mirror conflicts await Resolution Run review.");
                    } else if stronger_required && !stronger_confirmation && !review.confirmed {
                        ui.label("Confirmation is unavailable until the exact high-risk source path is entered.");
                    } else if !can_confirm && !review.confirmed {
                        ui.label("Confirmation is unavailable until Fresh Analysis and the fresh precheck are complete.");
                    }
                });
            } else {
                ui.label("No explainable plan is available until the precheck and Fresh Analysis pass.");
            }
        } else {
            ui.label("No plan has been analyzed. Select Analyze current state to review the intended work.");
        }

        if request_resolution_start {
            if let Err(error) = self.start_resolution_run() {
                self.status = format!("Resolution Run was not started: {error}");
            }
        }
        if request_resolution_confirmation {
            if let Err(error) = self.confirm_resolution_run() {
                self.status = format!("Resolution Run confirmation was not recorded: {error}");
            }
        }
        if request_confirmation {
            if let Err(error) = self.confirm_review() {
                self.status = format!("Execution Confirmation was not recorded: {error}");
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictReviewAction {
    None,
    StartResolutionRun,
    ConfirmResolutionRun,
}

fn draw_conflict_review(ui: &mut egui::Ui, review: &mut PlanReviewState) -> ConflictReviewAction {
    let Some(conflicts) = review.conflicts.as_mut() else {
        return ConflictReviewAction::None;
    };
    let entries = conflicts.review.entries().to_vec();
    let mut decisions_changed = false;
    let mut action = ConflictReviewAction::None;

    ui.group(|ui| {
        ui.heading("Conflict Review (read-only)");
        ui.label("Mirror Sync has no implicit winner. Inspect both peer versions and choose one explicit whole-file decision for every entry.");
        ui.label("This review never edits file content. Preserve Both, Rename/Preserve for Review, and Defer keep the run open for later review.");
        if entries.is_empty() {
            ui.label("No Mirror conflicts require a whole-file decision in this Fresh Analysis.");
        }

        for entry in &entries {
            let path = entry.relative_path().to_path_buf();
            let key = entry.key();
            ui.push_id(format!("{:?}:{:?}", entry.kind(), key), |ui| {
                ui.separator();
                ui.label(format!("Conflict path: {}", path.display()));
                ui.label(format!("Conflict kind: {}", conflict_kind_label(entry.kind())));
                if let Some(related_path) = entry.related_path() {
                    ui.label(format!("Related possible rename/duplicate path: {}", related_path.display()));
                }
                if let Some(destination_path) = entry.destination_path() {
                    ui.label(format!("Destination path under review: {}", destination_path.display()));
                }
                if let Some(rule) = entry.compatibility_rule() {
                    ui.label(format!("Destination compatibility rule: {:?}", rule));
                }

                if entry.evidence().is_empty() {
                    ui.label("No file content is shown for this destination-compatibility blocker.");
                } else {
                    ui.columns(entry.evidence().len().min(2), |columns| {
                        for (column, evidence) in columns.iter_mut().zip(entry.evidence()) {
                            draw_conflict_evidence(column, evidence);
                        }
                    });
                }

                ui.label(conflict_next_action(entry.kind()));
                let previous = conflicts.decisions.get(&key).copied();
                let mut selected = previous;
                for resolution in entry.available_resolutions().iter().copied() {
                    ui.radio_value(
                        &mut selected,
                        Some(resolution),
                        resolution_label(resolution),
                    );
                }
                if selected != previous {
                    if let Some(resolution) = selected {
                        conflicts.decisions.insert(key.clone(), resolution);
                    } else {
                        conflicts.decisions.remove(&key);
                    }
                    decisions_changed = true;
                }
                ui.label(format!(
                    "Decision status: {}",
                    selected
                        .map_or("unresolved".to_owned(), |resolution| {
                            format!("selected {}", resolution_label(resolution))
                        })
                ));
            });
        }

        if decisions_changed {
            conflicts.resolution_run = None;
            conflicts.confirmed = false;
            conflicts.error = None;
        }

        let all_decisions = conflicts.has_all_decisions();
        let precheck_ready = review
            .precheck
            .as_ref()
            .is_some_and(PrecheckResult::can_execute);
        if let Some(error) = &conflicts.error {
            ui.label(format!("Resolution status: blocked — {error}"));
        }
        if let Some(resolution_run) = &conflicts.resolution_run {
            ui.separator();
            ui.label("Resolution Run confirmation");
            ui.label("The following whole-file actions were freshly rechecked. Confirming them records approval only; execution is a separate core workflow boundary.");
            for resolution in resolution_run.plan().actions() {
                ui.label(format!(
                    "{}: {} — {}",
                    resolution.relative_path().display(),
                    resolution_label(resolution.resolution()),
                    resolution_consequence(resolution)
                ));
            }
            if conflicts.confirmed {
                ui.label("Resolution Run confirmation recorded. No filesystem mutation has started.");
            } else if ui.button("Confirm this exact Resolution Run").clicked() {
                action = ConflictReviewAction::ConfirmResolutionRun;
            }
        } else if entries.is_empty() {
            ui.label("Resolution Run is not needed because Fresh Analysis found no conflicts.");
        } else if ui
            .add_enabled(
                all_decisions && precheck_ready,
                egui::Button::new("Start Resolution Run review (fresh-check decisions)"),
            )
            .clicked()
        {
            action = ConflictReviewAction::StartResolutionRun;
        } else {
            if !precheck_ready {
                ui.label("Resolution Run is blocked until the fresh precheck has no blockers.");
            } else {
                ui.label("Resolution Run is blocked until every conflict has one explicit decision.");
            }
        }
    });

    action
}

fn draw_conflict_evidence(ui: &mut egui::Ui, evidence: &syncplus_core::ConflictEvidence) {
    ui.group(|ui| {
        ui.label(format!("{} evidence", peer_side_label(evidence.side())));
        ui.label(format!("Path: {}", evidence.relative_path().display()));
        ui.label(format!("Type: {:?} | Size: {} bytes", evidence.item_type(), evidence.size()));
        ui.label(format!(
            "Review classification: {}",
            file_review_classification_label(evidence.classification())
        ));
        ui.label(format!(
            "Metadata: modified {:?}, read-only {}, permissions {:?}",
            evidence.modified_at_unix_nanos(),
            evidence.is_readonly(),
            evidence.permissions()
        ));
        if let Some(target) = evidence.symlink_target() {
            ui.label(format!("Symlink target: {}", target.display()));
        }
        if let Some(hash) = evidence.sha256() {
            ui.label(format!("SHA-256 evidence: {}", format_hash(hash)));
        } else {
            ui.label("SHA-256 evidence: unavailable; do not assume the contents match.");
        }
        ui.label("File contents are not shown. Conflict Review uses safe classification, metadata, and hash evidence only.");
    });
}

fn draw_compatibility_review(ui: &mut egui::Ui, precheck: &PrecheckResult) {
    if precheck.naming_conflicts().is_empty() {
        return;
    }
    ui.group(|ui| {
        ui.heading("Destination Compatibility Review (blocked)");
        ui.label("These names cannot be represented safely at the destination. No resolution choice can bypass this blocker.");
        for conflict in precheck.naming_conflicts() {
            ui.label(format!(
                "Source path: {} → destination path: {}",
                conflict.source_path().display(),
                conflict.destination_path().display()
            ));
            if let Some(related_path) = conflict.related_path() {
                ui.label(format!("Conflicting destination path: {}", related_path.display()));
            }
            ui.label(format!(
                "Rule: {:?}. Next action: rename or exclude the item, or choose compatible destination storage; retry Fresh Analysis afterward.",
                conflict.rule()
            ));
        }
    });
}

fn conflict_kind_label(kind: syncplus_core::ConflictKind) -> &'static str {
    match kind {
        syncplus_core::ConflictKind::SamePath => "same path differs",
        syncplus_core::ConflictKind::PossibleDuplicateOrRename => "possible duplicate or rename",
        syncplus_core::ConflictKind::DestinationCompatibility => "destination compatibility",
    }
}

fn file_review_classification_label(
    classification: syncplus_core::FileReviewClassification,
) -> &'static str {
    match classification {
        syncplus_core::FileReviewClassification::Text => "text file",
        syncplus_core::FileReviewClassification::Binary => "binary file",
        syncplus_core::FileReviewClassification::Large => "large file; metadata only",
        syncplus_core::FileReviewClassification::Unreadable => "unreadable; content unavailable",
        syncplus_core::FileReviewClassification::NonRegular => "non-regular item",
    }
}

fn conflict_next_action(kind: syncplus_core::ConflictKind) -> &'static str {
    match kind {
        syncplus_core::ConflictKind::SamePath => {
            "Next action: choose which complete peer file to keep, preserve both, rename for review, or defer."
        }
        syncplus_core::ConflictKind::PossibleDuplicateOrRename => {
            "Next action: inspect both paths; equal hashes are evidence only and never authorize an automatic move or deletion."
        }
        syncplus_core::ConflictKind::DestinationCompatibility => {
            "Next action: correct the naming conflict, exclude the item, or preserve it for review; compatibility blockers cannot be bypassed silently."
        }
    }
}

fn resolution_label(resolution: ConflictResolution) -> &'static str {
    match resolution {
        ConflictResolution::KeepPeerA => "Keep Peer A whole file",
        ConflictResolution::KeepPeerB => "Keep Peer B whole file",
        ConflictResolution::PreserveBoth => "Preserve both files",
        ConflictResolution::RenamePreserveForReview => "Rename/preserve for review",
        ConflictResolution::Defer => "Defer for later review",
    }
}

fn resolution_consequence(action: &syncplus_core::ConflictResolutionAction) -> &'static str {
    match action.resolution() {
        ConflictResolution::KeepPeerA => "copy Peer A's verified whole file to Peer B; Peer A is preserved",
        ConflictResolution::KeepPeerB => "copy Peer B's verified whole file to Peer A; Peer B is preserved",
        ConflictResolution::PreserveBoth => "keep both existing peer versions without an implicit winner",
        ConflictResolution::RenamePreserveForReview => "preserve both versions for a later explicit review",
        ConflictResolution::Defer => "make no file change and keep this conflict unresolved",
    }
}

fn peer_side_label(side: syncplus_core::PeerSide) -> &'static str {
    match side {
        syncplus_core::PeerSide::PeerA => "Peer A",
        syncplus_core::PeerSide::PeerB => "Peer B",
    }
}

fn format_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn draw_analysis_review(ui: &mut egui::Ui, review: &PlanReviewState, analysis: &FreshAnalysis) {
    let summary = analysis.plan().summary();
    let unsupported_count = analysis
        .source_inventory()
        .items()
        .iter()
        .chain(analysis.destination_inventory().items())
        .filter(|item| item.outcome() == AnalysisOutcome::Unsupported)
        .count();
    let excluded_count = analysis
        .source_inventory()
        .excluded_items()
        .count()
        + analysis.destination_inventory().excluded_items().count();

    ui.group(|ui| {
        ui.label("Fresh Analysis: Explainable Actions");
        ui.label(format!(
            "Considered: {} | Included: {} | Excluded: {} | Unresolved or unsupported: {}",
            summary.considered_count(),
            summary.included_count(),
            summary.excluded_count(),
            unsupported_count
        ));
        ui.label(format!(
            "Copies: {} ({}) | Overwrites: {} ({}) | Destination removals: {} ({}) | Source removals: {} ({})",
            summary.copy_count(),
            format_bytes(summary.copy_bytes()),
            summary.overwrite_count(),
            format_bytes(summary.overwrite_bytes()),
            summary.destination_removal_count(),
            format_bytes(summary.destination_removal_bytes()),
            summary.source_removal_count(),
            format_bytes(summary.source_removal_bytes())
        ));
        ui.label(format!("Transfer data: {}", format_bytes(summary.total_bytes())));
    });

    ui.collapsing(format!("Explainable Actions ({})", analysis.plan().action_count()), |ui| {
        if analysis.plan().actions().is_empty() {
            ui.label("No file actions are planned for this current state.");
        }
        for action in analysis.plan().actions() {
            ui.label(format!(
                "{:?}: {}{} — {}",
                action.kind(),
                action.relative_path().display(),
                action
                    .size()
                    .map(|size| format!(" ({})", format_bytes(size)))
                    .unwrap_or_default(),
                action.consequence()
            ));
        }
    });

    ui.collapsing(
        format!("Exclusion Rules ({})", review.profile.exclusions().len()),
        |ui| {
            if review.profile.exclusions().is_empty() {
                ui.label("No exclusion rules are configured.");
            } else {
                ui.label(format!("Excluded inventory items matched: {excluded_count}"));
                for rule in review.profile.exclusions() {
                    ui.label(format!("Validated rule: {rule}"));
                }
                for item in analysis
                    .source_inventory()
                    .excluded_items()
                    .chain(analysis.destination_inventory().excluded_items())
                {
                    ui.label(format!("Excluded item: {}", item.relative_path().display()));
                }
                ui.label("Excluded items remain outside the Approved Sync Scope and are never silently synchronized or deleted.");
            }
        },
    );

    ui.collapsing("Approved Sync Scope", |ui| {
        ui.label(format!(
            "Included items: {} | Explicitly excluded items: {}",
            analysis.plan().approved_scope().included_count(),
            analysis.plan().approved_scope().excluded_count()
        ));
    });

    let unresolved_count = analysis
        .source_inventory()
        .items()
        .iter()
        .chain(analysis.destination_inventory().items())
        .filter(|item| item.outcome() == AnalysisOutcome::Unsupported)
        .count();
    ui.collapsing(
        format!("Unresolved or unsupported items ({unresolved_count})"),
        |ui| {
            if unresolved_count == 0 {
                ui.label("No unresolved or unsupported inventory items were found.");
            } else {
                for item in analysis
                    .source_inventory()
                    .items()
                    .iter()
                    .chain(analysis.destination_inventory().items())
                    .filter(|item| item.outcome() == AnalysisOutcome::Unsupported)
                {
                    ui.label(format!(
                        "Unresolved unsupported item: {} ({:?}); execution must remain blocked.",
                        item.relative_path().display(),
                        item.item_type()
                    ));
                }
            }
        },
    );

    ui.collapsing("Advanced technical preview", |ui| {
        ui.label("Generated from the reviewed typed Process Specification; arbitrary command editing is unavailable.");
        let mut preview = analysis.specification().preview();
        ui.add(egui::TextEdit::multiline(&mut preview).desired_rows(2).interactive(false));
        ui.label("Any secret binding is redacted in this diagnostic preview.");
    });
}

fn mapped_peers(profile: &SyncProfile) -> (&Peer, &Peer) {
    match profile.mode() {
        SyncMode::OneWay => match profile.source() {
            OneWaySource::PeerA => (profile.peer_a(), profile.peer_b()),
            OneWaySource::PeerB => (profile.peer_b(), profile.peer_a()),
        },
        SyncMode::Mirror => (profile.peer_a(), profile.peer_b()),
    }
}

fn analysis_has_unresolved_items(analysis: &FreshAnalysis) -> bool {
    analysis
        .source_inventory()
        .items()
        .iter()
        .chain(analysis.destination_inventory().items())
        .any(|item| item.outcome() == AnalysisOutcome::Unsupported)
}

fn stronger_confirmation_satisfied(
    review: &PlanReviewState,
    precheck: &PrecheckResult,
) -> bool {
    let typed_path = review.stronger_confirmation_path.trim();
    precheck
        .warnings()
        .iter()
        .filter(|warning| warning.requires_stronger_confirmation())
        .all(|warning| warning.source().display().to_string() == typed_path)
}

fn draw_confirmation_summary(ui: &mut egui::Ui, review: &PlanReviewState, analysis: &FreshAnalysis) {
    let summary = analysis.plan().summary();
    let (source, destination) = mapped_peers(&review.profile);
    if review.profile.mode() == SyncMode::OneWay {
        ui.label(format!(
            "Exact reviewed mapping: {} → {}",
            source.root().display(),
            destination.root().display()
        ));
    } else {
        ui.label(format!(
            "Exact reviewed roots: Peer A {} and Peer B {}; actions may be in either direction.",
            review.profile.peer_a().root().display(),
            review.profile.peer_b().root().display()
        ));
    }
    ui.label(format!(
        "Exact reviewed actions: {} total; {} copies ({}), {} overwrites ({}), {} destination removals, {} source removals.",
        analysis.plan().action_count(),
        summary.copy_count(),
        format_bytes(summary.copy_bytes()),
        summary.overwrite_count(),
        format_bytes(summary.overwrite_bytes()),
        summary.destination_removal_count(),
        summary.source_removal_count()
    ));
    let options = review.profile.options();
    if options.safe_delete {
        match options.deletion_method {
            Some(DeletionMethod::Trash) => {
                ui.label("Consequence: verified source removals move to the selected local Trash; an unavailable Trash blocks the run and is never replaced silently.");
            }
            Some(DeletionMethod::PermanentRemoval) => {
                ui.label("Consequence: verified source removals are irreversible Permanent Removal and require this explicit Advanced confirmation.");
            }
            None => {
                ui.label("Consequence: Safe Delete is selected but its deletion method is not valid, so confirmation remains unavailable.");
            }
        }
    }
    if options.destination_cleanup {
        ui.label("Consequence: Destination Cleanup may remove destination items absent from the authoritative source; each removal remains visible above.");
    }
    if !options.safe_delete && !options.destination_cleanup {
        ui.label("Consequence: no deletion or cleanup action is enabled; planned copies and overwrites affect only the displayed destination paths.");
    }
    if review.profile.mode() == SyncMode::Mirror {
        ui.label("Mirror Sync has no implicit winner; any action direction is shown in the Explainable Actions list above.");
    }
    ui.label("A fresh precheck and Fresh Analysis validation run again when this explicit confirmation action is pressed; this view itself performs no filesystem mutation.");
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_precheck_error(error: &PrecheckErrorKind) -> String {
    match error {
        PrecheckErrorKind::InvalidSpecification(error) => format!("invalid profile: {error}"),
        PrecheckErrorKind::Probe(error) => format!("precheck probe failed: {error}"),
    }
}

impl eframe::App for SyncPlusApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.apply_theme(ui.ctx());
        egui::Panel::top("settings").show(ui, |ui| self.draw_settings(ui));
        egui::Panel::left("profiles").show(ui, |ui| self.draw_profile_list(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.draw_profile_form(ui));
            egui::ScrollArea::vertical().show(ui, |ui| self.draw_review(ui));
            ui.separator();
            ui.label(egui::RichText::new(&self.status).strong());
        });
    }
}

fn draw_endpoint(ui: &mut egui::Ui, title: &str, endpoint: &mut EndpointForm) {
    ui.collapsing(title, |ui| {
        ui.horizontal(|ui| {
            ui.label("Name");
            ui.text_edit_singleline(&mut endpoint.name);
        });
        ui.horizontal(|ui| {
            ui.label("Location type");
            ui.radio_value(&mut endpoint.kind, EndpointKind::Local, "Local folder");
            ui.radio_value(&mut endpoint.kind, EndpointKind::Ssh, "SSH peer");
        });
        match endpoint.kind {
            EndpointKind::Local => {
                ui.horizontal(|ui| {
                    ui.label("Folder path");
                    ui.text_edit_singleline(&mut endpoint.local_path);
                });
                ui.label("The folder is passed as a validated path argument; no shell command is accepted.");
            }
            EndpointKind::Ssh => {
                ui.horizontal(|ui| {
                    ui.label("Server");
                    ui.text_edit_singleline(&mut endpoint.server);
                    ui.label("Username");
                    ui.text_edit_singleline(&mut endpoint.username);
                    ui.label("Port");
                    ui.add(egui::TextEdit::singleline(&mut endpoint.port).desired_width(55.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Remote folder");
                    ui.text_edit_singleline(&mut endpoint.remote_path);
                });
                ui.label("SSH host identity is checked by the core preflight before any mutation.");
                ui.horizontal(|ui| {
                    ui.label("Authentication");
                    ui.radio_value(&mut endpoint.authentication, AuthenticationForm::Key, "Identity file");
                    ui.radio_value(&mut endpoint.authentication, AuthenticationForm::Agent, "SSH agent");
                    ui.radio_value(
                        &mut endpoint.authentication,
                        AuthenticationForm::InteractivePassword,
                        "Interactive password",
                    );
                    ui.radio_value(
                        &mut endpoint.authentication,
                        AuthenticationForm::SavedPassword,
                        "Saved keyring reference",
                    );
                });
                match endpoint.authentication {
                    AuthenticationForm::Key => {
                        ui.horizontal(|ui| {
                            ui.label("Identity file");
                            ui.text_edit_singleline(&mut endpoint.identity);
                        });
                    }
                    AuthenticationForm::SavedPassword => {
                        ui.horizontal(|ui| {
                            ui.label("Keyring reference");
                            ui.text_edit_singleline(&mut endpoint.secret_reference);
                        });
                        ui.label("Only the nonsecret reference is saved. Passwords and passphrases stay in the desktop keyring.");
                    }
                    AuthenticationForm::Agent | AuthenticationForm::InteractivePassword => {}
                }
            }
        }
    });
}

fn mode_label(mode: ApplicationMode) -> &'static str {
    match mode {
        ApplicationMode::Simple => "Simple",
        ApplicationMode::Advanced => "Advanced",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

    use super::*;

    fn app() -> SyncPlusApp {
        SyncPlusApp::new_with_store(RunEvidenceStore::open_in_memory().expect("database"))
            .expect("app")
    }

    struct AvailableSecretStore;

    impl SecretStore for AvailableSecretStore {
        fn save(
            &self,
            _reference: &SavedSecretReference,
            _secret: &syncplus_core::SecretValue,
        ) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn load(
            &self,
            _reference: &SavedSecretReference,
        ) -> Result<syncplus_core::SecretValue, SecretStoreError> {
            Ok(syncplus_core::SecretValue::new("test-only-secret"))
        }

        fn delete(&self, _reference: &SavedSecretReference) -> Result<(), SecretStoreError> {
            Ok(())
        }
    }

    fn valid_form() -> ProfileForm {
        ProfileForm {
            name: "Documents backup".to_owned(),
            peer_a: EndpointForm {
                name: "Laptop".to_owned(),
                local_path: "/home/user/Documents".to_owned(),
                ..EndpointForm::default()
            },
            peer_b: EndpointForm {
                name: "Backup disk".to_owned(),
                local_path: "/mnt/backup/Documents".to_owned(),
                ..EndpointForm::default()
            },
            ..ProfileForm::default()
        }
    }

    fn filesystem_form() -> (ProfileForm, PathBuf, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("syncplus-ui-{unique}-{}", std::process::id()));
        let source = base.join("source");
        let destination = base.join("destination");
        fs::create_dir_all(&source).expect("source directory");
        fs::create_dir_all(&destination).expect("destination directory");
        fs::write(source.join("keep.txt"), b"new contents").expect("included file");
        fs::write(source.join("ignored.tmp"), b"excluded file").expect("excluded file");
        fs::write(destination.join("keep.txt"), b"old contents").expect("existing file");

        let mut form = ProfileForm::default();
        form.name = "Filesystem review".to_owned();
        form.peer_a.local_path = source.display().to_string();
        form.peer_b.local_path = destination.display().to_string();
        form.exclusions = "*.tmp".to_owned();
        (form, source, base)
    }

    #[test]
    fn first_launch_is_simple_and_new_profiles_are_safe() {
        let mut app = app();
        assert_eq!(app.mode(), ApplicationMode::Simple);
        app.form = valid_form();
        let profile = app.form.build().expect("safe profile");
        assert_eq!(profile.mode(), SyncMode::OneWay);
        assert_eq!(profile.source(), OneWaySource::PeerA);
        assert!(!profile.options().safe_delete);
        assert!(!profile.options().destination_cleanup);
        assert_eq!(profile.options().deletion_method, None);
    }

    #[test]
    fn mode_preference_is_persisted_in_application_database() {
        let store = RunEvidenceStore::open_in_memory().expect("database");
        let mut app = SyncPlusApp::new_with_store(store).expect("app");
        app.set_mode(ApplicationMode::Advanced);
        assert_eq!(app.mode(), ApplicationMode::Advanced);
    }

    #[test]
    fn invalid_endpoints_are_rejected_before_save() {
        let mut app = app();
        app.form = valid_form();
        app.form.peer_b.local_path.clear();
        let error = app.validate_profile().expect_err("empty path must block");
        assert_eq!(error, UiValidationError::EmptyLocalPath { peer: "Destination" });
        assert!(app.profiles().is_empty());
    }

    #[test]
    fn profiles_round_trip_without_secret_input_or_arbitrary_arguments() {
        let mut app = app();
        app.form = valid_form();
        let id = app.save_profile().expect("save");
        assert_eq!(app.profiles().len(), 1);
        assert_eq!(app.profiles()[0].id(), id);
        assert_eq!(app.profiles()[0].profile().name(), "Documents backup");
        assert_eq!(app.profiles()[0].profile().peer_a().root(), PathBuf::from("/home/user/Documents"));
        assert!(app.status().contains("future runs"));
    }

    #[test]
    fn saved_password_form_accepts_only_a_keyring_reference() {
        let mut form = valid_form();
        form.peer_b.kind = EndpointKind::Ssh;
        form.peer_b.server = "backup.example.com".to_owned();
        form.peer_b.username = "sync-user".to_owned();
        form.peer_b.remote_path = "/srv/backup".to_owned();
        form.peer_b.authentication = AuthenticationForm::SavedPassword;
        form.peer_b.secret_reference = "backup-password".to_owned();
        let profile = form.build().expect("reference is valid");
        assert!(matches!(
            profile.peer_b().ssh_peer().expect("ssh").authentication(),
            SshAuthentication::SavedPassword(_)
        ));
        form.peer_b.secret_reference = "top secret password".to_owned();
        assert_eq!(
            form.build().expect_err("secret-like invalid reference"),
            UiValidationError::InvalidSavedSecretReference
        );
    }

    #[test]
    fn saved_password_profiles_require_an_available_keyring_entry() {
        let store = RunEvidenceStore::open_in_memory().expect("database");
        let mut app = SyncPlusApp::new_with_store_and_secret_store(store, AvailableSecretStore)
            .expect("app");
        app.form = valid_form();
        app.form.peer_b.kind = EndpointKind::Ssh;
        app.form.peer_b.server = "backup.example.com".to_owned();
        app.form.peer_b.username = "sync-user".to_owned();
        app.form.peer_b.remote_path = "/srv/backup".to_owned();
        app.form.peer_b.authentication = AuthenticationForm::SavedPassword;
        app.form.peer_b.secret_reference = "backup-password".to_owned();

        app.save_profile().expect("keyring entry is available");
        assert!(matches!(
            app.profiles()[0]
                .profile()
                .peer_b()
                .ssh_peer()
                .expect("ssh")
                .authentication(),
            SshAuthentication::SavedPassword(_)
        ));
    }

    #[test]
    fn analyze_profile_builds_reviewable_plan_with_exclusions_and_preview() {
        let (form, _source, base) = filesystem_form();
        let mut app = app();
        app.form = form;

        app.analyze_profile().expect("local analysis should pass");
        let review = app.review.as_ref().expect("review state");
        let analysis = review.analysis.as_ref().expect("fresh analysis");
        assert!(review.precheck.as_ref().expect("precheck").can_execute());
        assert!(analysis
            .source_inventory()
            .excluded_items()
            .any(|item| item.relative_path() == std::path::Path::new("ignored.tmp")));
        assert!(analysis.plan().summary().overwrite_count() >= 1);
        assert!(analysis.specification().preview().contains("rsync"));
        assert!(!analysis.specification().preview().contains("test-only-secret"));
        assert!(app.status().contains("Fresh Analysis ready"));

        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[test]
    fn unavailable_source_is_a_precheck_blocker_and_cannot_be_confirmed() {
        let (mut form, _source, base) = filesystem_form();
        let missing = base.join("missing-source");
        form.peer_a.local_path = missing.display().to_string();
        let mut app = app();
        app.form = form;

        assert_eq!(app.analyze_profile(), Err(UiValidationError::PrecheckBlocked));
        let review = app.review.as_ref().expect("blocked review state");
        let precheck = review.precheck.as_ref().expect("precheck result");
        assert!(!precheck.can_execute());
        assert!(!precheck.blockers().is_empty());
        assert!(app.confirm_review().is_err());

        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[test]
    fn explicit_confirmation_rechecks_stale_analysis() {
        let (form, source, base) = filesystem_form();
        let mut app = app();
        app.form = form;
        app.analyze_profile().expect("local analysis should pass");

        app.confirm_review()
            .expect("the explicit confirmation method approves a clean review");
        assert!(app.review.as_ref().expect("review state").confirmed);
        fs::write(source.join("keep.txt"), b"changed after review").expect("change source");

        let error = app.confirm_review().expect_err("stale analysis must block");
        assert!(matches!(error, UiValidationError::Analysis(message) if message.contains("stale")));
        assert!(!app.review.as_ref().expect("review state").confirmed);

        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[test]
    fn mirror_conflict_review_requires_explicit_decision_and_fresh_resolution_confirmation() {
        let (mut form, source, base) = filesystem_form();
        form.mode = SyncMode::Mirror;
        let mut app = app();
        app.form = form;

        app.analyze_profile().expect("mirror analysis should pass");
        let entries = app.conflict_entries().expect("mirror conflict review");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_read_only());
        assert!(app.start_resolution_run().is_err(), "missing decisions must block");

        app.set_conflict_resolution("keep.txt", ConflictResolution::KeepPeerA)
            .expect("whole-file decision");
        fs::write(source.join("keep.txt"), b"changed before resolution start").expect("change source");
        assert!(app.start_resolution_run().is_err(), "stale resolution must block before start");

        app.analyze_profile().expect("fresh mirror analysis should pass");
        app.set_conflict_resolution("keep.txt", ConflictResolution::KeepPeerA)
            .expect("whole-file decision after fresh analysis");
        app.start_resolution_run()
            .expect("selected decision starts a fresh Resolution Run");
        assert!(!app.resolution_is_confirmed());
        let source_before = fs::read(source.join("keep.txt")).expect("source contents");
        let destination_before = fs::read(base.join("destination/keep.txt")).expect("destination contents");
        app.confirm_resolution_run()
            .expect("fresh Resolution Run confirmation should pass");
        assert!(app.resolution_is_confirmed());
        assert_eq!(fs::read(source.join("keep.txt")).expect("source contents"), source_before);
        assert_eq!(
            fs::read(base.join("destination/keep.txt")).expect("destination contents"),
            destination_before
        );

        fs::write(source.join("keep.txt"), b"changed after conflict review").expect("change source");
        assert!(app.confirm_resolution_run().is_err(), "stale resolution must block");
        assert!(!app.resolution_is_confirmed());

        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[test]
    fn advanced_options_are_typed_and_round_trip_without_command_editing() {
        let mut form = valid_form();
        form.timestamps = true;
        form.ownership = true;
        form.access_control_lists = true;
        form.extended_attributes = true;
        form.partial_transfer_policy = PartialTransferPolicy::KeepPartialForResume;
        form.retry_attempts = "5".to_owned();
        form.retry_delay_millis = "250".to_owned();

        let profile = form.build().expect("typed advanced options");
        let options = profile.options();
        assert!(options.metadata.timestamps());
        assert!(options.metadata.specialist_metadata().ownership());
        assert!(options.metadata.specialist_metadata().access_control_lists());
        assert!(options.metadata.specialist_metadata().extended_attributes());
        assert_eq!(options.partial_transfer_policy, PartialTransferPolicy::KeepPartialForResume);
        assert_eq!(options.retry_policy.max_attempts(), 5);
        assert_eq!(options.retry_policy.initial_delay(), Duration::from_millis(250));
        assert!(!syncplus_core::ProcessSpecification::from_profile(&profile)
            .expect("validated specification")
            .preview()
            .contains("--arbitrary"));

        form.retry_attempts = "11".to_owned();
        assert_eq!(form.build(), Err(UiValidationError::InvalidRetryAttempts));
        form.retry_attempts = "5".to_owned();
        form.retry_delay_millis = "3600001".to_owned();
        assert_eq!(form.build(), Err(UiValidationError::InvalidRetryDelay));
    }
}
