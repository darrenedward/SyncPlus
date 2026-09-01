use std::path::PathBuf;

use eframe::egui;
use syncplus_core::{
    ApplicationMode, ApplicationSettings, DeletionMethod, OneWaySource, Peer, PeerEndpoint,
    PersistedSyncProfile, RunEvidenceStore, SavedSecretReference, SshAuthentication, SyncMode,
    SecretStore, SecretStoreError, SyncOptions, SyncProfile, SyncProfileId, ThemePreference,
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
            Self::Core(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UiValidationError {}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
        }
    }
}

impl ProfileForm {
    fn from_persisted(profile: &PersistedSyncProfile) -> Self {
        let value = profile.profile();
        Self {
            id: Some(profile.id()),
            name: value.name().to_owned(),
            peer_a: EndpointForm::from_peer(value.peer_a()),
            peer_b: EndpointForm::from_peer(value.peer_b()),
            mode: value.mode(),
            source: value.source(),
            safe_delete: value.options().safe_delete,
            destination_cleanup: value.options().destination_cleanup,
            exclusions: value.exclusions().join("\n"),
        }
    }

    fn build(&self) -> Result<SyncProfile, UiValidationError> {
        if self.name.trim().is_empty() {
            return Err(UiValidationError::EmptyProfileName);
        }
        let peer_a = self.peer_a.build("Source")?;
        let peer_b = self.peer_b.build("Destination")?;
        let mut options = SyncOptions::default();
        options.safe_delete = self.safe_delete;
        options.destination_cleanup = self.destination_cleanup;
        options.deletion_method = self.safe_delete.then_some(DeletionMethod::Trash);
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

pub struct SyncPlusApp {
    store: RunEvidenceStore,
    secret_store: Box<dyn SecretStore>,
    settings: ApplicationSettings,
    profiles: Vec<PersistedSyncProfile>,
    form: ProfileForm,
    status: String,
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

    fn select_profile(&mut self, id: SyncProfileId) {
        if let Some(profile) = self.profiles.iter().find(|profile| profile.id() == id) {
            self.form = ProfileForm::from_persisted(profile);
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
    }
}

impl eframe::App for SyncPlusApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.apply_theme(ui.ctx());
        egui::Panel::top("settings").show(ui, |ui| self.draw_settings(ui));
        egui::Panel::left("profiles").show(ui, |ui| self.draw_profile_list(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.draw_profile_form(ui));
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
    use std::path::PathBuf;

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
}
