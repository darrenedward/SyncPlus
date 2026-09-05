use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread,
    time::Duration,
};

use eframe::egui;
use notify_rust::Notification;
use rfd::FileDialog;
use syncplus_core::{
    ActionOutcome, AnalysisOutcome, ApplicationMode, ApplicationSettings, AuthorizationSnapshot,
    BackgroundScheduler, ConfirmedPlan, ConflictDecision, ConflictEntry, ConflictEntryKey,
    ConflictResolution, ConflictReview, DeletionMethod, FreshAnalysis, LocalPrecheckProbe,
    MetadataRequirements, MissedScheduleDecision, MissedScheduleNotice, OneWaySource,
    PartialTransferPolicy, Peer, PeerEndpoint, PersistedSyncProfile, PrecheckErrorKind,
    PrecheckResult, RecoveryMethod, RemotePrecheckRequest, ResolutionRun, RetryPolicy,
    RunEvidenceStore, RunExecutionResult, RunId, RunLifecycle, RunPrecheck, RunReport,
    RunReportStatus, SavedSecretReference, ScheduleDefinition, SchedulerEvent,
    SchedulerNotification, SchedulerNotificationAction, SchedulerNotificationSink, SecretStore,
    SecretStoreError, SpecialistMetadataRequirements, SshAuthentication, SyncMode, SyncOptions,
    SyncProfile, SyncProfileId, ThemePreference,
};

use crate::chrome::{self, ChromeAccent, ChromeSurface, OverviewAction};
use crate::theme::BrandTheme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointKind {
    #[default]
    Local,
    Ssh,
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
    SshAuthenticationRequired,
    InvalidSavedSecretReference,
    SavedSecretUnavailable,
    InvalidRetryAttempts,
    InvalidRetryDelay,
    InvalidScheduleInterval,
    InvalidScheduleTimezone,
    CloneEndpointsUnchanged,
    DuplicateEndpointPair,
    CloneAuthorizationConfirmationRequired,
    PermanentRemovalRequiresAdvanced,
    PermanentRemovalAuthorizationRequired,
    PrecheckBlocked,
    ReviewNotReady,
    StrongerConfirmationRequired,
    UnresolvedItems,
    ConflictReviewNotReady,
    ResolutionRequiresMirror,
    ProfileChangedDuringEdit,
    Resolution(String),
    Analysis(String),
    Core(String),
}

const MISSED_SCHEDULE_RUN_NOW_LABEL: &str = "Yes, Run Now";
const MISSED_SCHEDULE_NOT_NOW_LABEL: &str = "No, Not Now";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowCloseDecision {
    HideToTray,
    KeepVisible,
}

fn window_close_decision(tray_available: bool) -> WindowCloseDecision {
    if tray_available {
        WindowCloseDecision::HideToTray
    } else {
        WindowCloseDecision::KeepVisible
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuitDecision {
    Exit,
    AskBeforeStopping,
}

fn quit_decision(manual_run_active: bool) -> QuitDecision {
    if manual_run_active {
        QuitDecision::AskBeforeStopping
    } else {
        QuitDecision::Exit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppView {
    Welcome,
    Profiles,
    Settings,
    Wizard,
    Sync,
    Reports,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidebarIcon {
    Overview,
    Profiles,
    SyncWorkspace,
    Reports,
    Settings,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileWizardStep {
    SyncMethod,
    SourceEndpoint,
    DestinationEndpoint,
    ReviewAndSave,
}

fn ui_palette(ui: &egui::Ui) -> BrandTheme {
    BrandTheme::from_ui(ui)
}

impl ProfileWizardStep {
    const ALL: [Self; 4] = [
        Self::SyncMethod,
        Self::SourceEndpoint,
        Self::DestinationEndpoint,
        Self::ReviewAndSave,
    ];

    const fn number(self) -> usize {
        match self {
            Self::SyncMethod => 1,
            Self::SourceEndpoint => 2,
            Self::DestinationEndpoint => 3,
            Self::ReviewAndSave => 4,
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::SyncMethod => "Sync method",
            Self::SourceEndpoint => "Source folder",
            Self::DestinationEndpoint => "Destination folder",
            Self::ReviewAndSave => "Review & save",
        }
    }

    const fn previous(self) -> Option<Self> {
        match self {
            Self::SyncMethod => None,
            Self::SourceEndpoint => Some(Self::SyncMethod),
            Self::DestinationEndpoint => Some(Self::SourceEndpoint),
            Self::ReviewAndSave => Some(Self::DestinationEndpoint),
        }
    }

    const fn next(self) -> Option<Self> {
        match self {
            Self::SyncMethod => Some(Self::SourceEndpoint),
            Self::SourceEndpoint => Some(Self::DestinationEndpoint),
            Self::DestinationEndpoint => Some(Self::ReviewAndSave),
            Self::ReviewAndSave => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotificationTemplate {
    title: &'static str,
    reason: &'static str,
    next_action: &'static str,
}

fn notification_template_for_status(status: RunReportStatus) -> NotificationTemplate {
    match status {
        RunReportStatus::Completed => NotificationTemplate {
            title: "Sync Run completed",
            reason: "All approved actions passed verification and reconciliation.",
            next_action: "Open the Run Report to review the safety evidence.",
        },
        RunReportStatus::Failed => NotificationTemplate {
            title: "Sync Run failed",
            reason: "At least one approved action did not complete safely.",
            next_action: "Open the Run Report and resolve the failure before retrying.",
        },
        RunReportStatus::Cancelled => NotificationTemplate {
            title: "Sync Run cancelled",
            reason: "The run stopped before all approved actions completed.",
            next_action: "Open the Run Report and review unfinished actions before retrying.",
        },
        RunReportStatus::Interrupted => NotificationTemplate {
            title: "Sync Run interrupted",
            reason: "The run stopped at an unexpected process or connection boundary.",
            next_action: "Open Recovery Review before resuming or retrying.",
        },
        RunReportStatus::CompletedWithReviewRequired | RunReportStatus::RecoveryReview => {
            NotificationTemplate {
                title: "Sync Run needs review",
                reason: "Work remains unresolved or crossed an uncertain filesystem boundary.",
                next_action: "Open the Run Report and complete Recovery Review before clearing it.",
            }
        }
        RunReportStatus::ReviewCleared => NotificationTemplate {
            title: "Sync Run review cleared",
            reason: "The required review was explicitly completed after reconciliation.",
            next_action: "Open the Run Report to review the final safety evidence.",
        },
        RunReportStatus::Blocked => NotificationTemplate {
            title: "Sync Run blocked",
            reason: "A safety precheck prevented filesystem mutation.",
            next_action: "Open the Run Report, resolve the blocker, and analyze again.",
        },
        RunReportStatus::InProgress => NotificationTemplate {
            title: "Sync Run started",
            reason: "The approved run is in progress.",
            next_action: "Keep the source protected and review the Run Report when it settles.",
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiNotification {
    title: String,
    reason: String,
    next_action: String,
    run_id: Option<RunId>,
}

impl UiNotification {
    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn next_action(&self) -> &str {
        &self.next_action
    }

    pub const fn run_id(&self) -> Option<RunId> {
        self.run_id
    }
}

fn notification_for_report(report: &RunReport) -> UiNotification {
    let template = notification_template_for_status(report.status());
    UiNotification {
        title: template.title.to_owned(),
        reason: template.reason.to_owned(),
        next_action: template.next_action.to_owned(),
        run_id: Some(report.run_id()),
    }
}

fn notification_for_scheduler_event(event: &SchedulerEvent) -> UiNotification {
    let notification = event.notification();
    UiNotification {
        title: notification.title().to_owned(),
        reason: notification.reason().to_owned(),
        next_action: notification.next_action().to_owned(),
        run_id: Some(notification.run_id()),
    }
}

struct DesktopNotificationSink;

impl SchedulerNotificationSink for DesktopNotificationSink {
    fn deliver(
        &mut self,
        notification: &SchedulerNotification,
    ) -> Result<(), syncplus_core::NotificationDeliveryError> {
        deliver_desktop_notification(
            notification.title(),
            notification.reason(),
            notification.next_action(),
        )
        .map_err(|_| syncplus_core::NotificationDeliveryError::Unavailable)
    }
}

fn deliver_desktop_notification(title: &str, reason: &str, next_action: &str) -> Result<(), ()> {
    Notification::new()
        .appname("SyncPlus")
        .summary(title)
        .body(&format!("Reason: {reason}\nNext action: {next_action}"))
        .show()
        .map(|_| ())
        .map_err(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayCommand {
    ShowWindow,
    Quit,
}

struct SyncPlusTray {
    commands: Sender<TrayCommand>,
    repaint_context: Arc<Mutex<Option<egui::Context>>>,
}

impl SyncPlusTray {
    fn dispatch(&self, command: TrayCommand) {
        let _ = self.commands.send(command);
        if let Ok(context) = self.repaint_context.lock()
            && let Some(context) = context.as_ref()
        {
            context.request_repaint();
        }
    }
}

impl ksni::Tray for SyncPlusTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "syncplus".to_owned()
    }

    fn title(&self) -> String {
        "SyncPlus".to_owned()
    }

    fn icon_name(&self) -> String {
        "folder".to_owned()
    }

    fn status(&self) -> ksni::Status {
        ksni::Status::Active
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::{MenuItem, StandardItem};

        vec![
            StandardItem {
                label: "_Show SyncPlus".to_owned(),
                shortcut: vec![vec!["Control".to_owned(), "S".to_owned()]],
                activate: Box::new(|tray: &mut SyncPlusTray| {
                    tray.dispatch(TrayCommand::ShowWindow)
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "_Quit SyncPlus".to_owned(),
                shortcut: vec![vec!["Control".to_owned(), "Q".to_owned()]],
                activate: Box::new(|tray: &mut SyncPlusTray| tray.dispatch(TrayCommand::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

struct TrayRuntime {
    _handle: ksni::blocking::Handle<SyncPlusTray>,
    receiver: Receiver<TrayCommand>,
    repaint_context: Arc<Mutex<Option<egui::Context>>>,
}

impl TrayRuntime {
    fn start() -> Result<Self, String> {
        use ksni::blocking::TrayMethods;

        let (commands, receiver) = mpsc::channel();
        let repaint_context = Arc::new(Mutex::new(None));
        let tray = SyncPlusTray {
            commands,
            repaint_context: repaint_context.clone(),
        };
        let handle = tray.spawn().map_err(|error| error.to_string())?;
        Ok(Self {
            _handle: handle,
            receiver,
            repaint_context,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuitFlow {
    None,
    ConfirmActive(RunId),
    Stopping(RunId),
}

struct ManualRunCompletion {
    run_id: RunId,
    result: Result<RunReport, String>,
}

struct ProfileAnalysisResult {
    profile: SyncProfile,
    precheck: Result<PrecheckResult, String>,
    analysis: Option<Result<FreshAnalysis, String>>,
}

struct AnalysisCompletion {
    result: ProfileAnalysisResult,
}

struct ActiveAnalysis {
    receiver: Receiver<AnalysisCompletion>,
}

struct ActiveManualRun {
    run_id: RunId,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<ManualRunCompletion>,
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
            Self::SshAuthenticationRequired => {
                formatter.write_str("Choose an SSH authentication method for this cloned endpoint before saving.")
            }
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
            Self::InvalidScheduleInterval => {
                formatter.write_str("Schedule interval must be a whole number from 1 minute to 7 days.")
            }
            Self::InvalidScheduleTimezone => {
                formatter.write_str("Schedule timezone must be a nonempty value of at most 128 characters.")
            }
            Self::CloneEndpointsUnchanged => {
                formatter.write_str("A cloned profile must change at least one endpoint before it can be saved.")
            }
            Self::DuplicateEndpointPair => {
                formatter.write_str("The source and destination endpoint pair is already used by another Sync Profile.")
            }
            Self::CloneAuthorizationConfirmationRequired => formatter.write_str(
                "Review and explicitly confirm the cloned profile's unattended authorization choice before saving.",
            ),
            Self::PermanentRemovalRequiresAdvanced => {
                formatter.write_str("Permanent Removal is available only in Advanced Mode.")
            }
            Self::PermanentRemovalAuthorizationRequired => formatter.write_str(
                "Permanent Removal requires its separate explicit unattended authorization before saving.",
            ),
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
            Self::ProfileChangedDuringEdit => formatter.write_str(
                "This Sync Profile changed elsewhere. Reload it before saving your edits.",
            ),
            Self::Resolution(message) => write!(formatter, "Resolution Run could not proceed: {message}"),
            Self::Analysis(message) => write!(formatter, "Fresh Analysis could not be completed: {message}"),
            Self::Core(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UiValidationError {}

/// Run one due scheduler poll as the invoking OS user. This is the fixed
/// command surface intended for a user-level scheduler registration; it has
/// no shell, root-service, or interactive credential fallback.
pub fn run_background_scheduler_once() -> Result<usize, String> {
    let database_path = RunEvidenceStore::canonical_path().map_err(|error| error.to_string())?;
    let data_home = database_path
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| "canonical database has no XDG data parent".to_owned())?
        .to_path_buf();
    let mut store = RunEvidenceStore::open_canonical().map_err(|error| error.to_string())?;
    let known_event_ids = store
        .list_scheduler_events()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|event| event.event_id())
        .collect::<BTreeSet<_>>();
    let scheduler = BackgroundScheduler::new();
    let scope_locks = scheduler.scope_lock_registry();
    let due_runs = scheduler
        .poll_due(&mut store)
        .map_err(|error| error.to_string())?;
    let mut launched = 0;
    let mut failures = Vec::new();
    for scheduled_run in due_runs {
        let recovery_method = if scheduled_run.snapshot().profile().options().deletion_method
            == Some(DeletionMethod::PermanentRemoval)
        {
            RecoveryMethod::permanent_removal()
        } else {
            RecoveryMethod::native_trash(data_home.clone())
        };
        let workflow = syncplus_core::RunWorkflow::with_scope_lock_registry(
            syncplus_core::ProcessSupervisor::default(),
            recovery_method,
            scope_locks.clone(),
        );
        match scheduled_run.execute(
            &workflow,
            &LocalPrecheckProbe::default(),
            &mut store,
            || false,
        ) {
            Ok(_) => launched += 1,
            Err(error) => failures.push(format!(
                "Sync Run {}: {error}",
                scheduled_run.run_id().value()
            )),
        }
    }
    if let Ok(events) = store.list_scheduler_events() {
        let mut sink = DesktopNotificationSink;
        for event in events {
            if !known_event_ids.contains(&event.event_id()) {
                let _ = store.deliver_scheduler_notification(event.event_id(), &mut sink);
            }
        }
    }
    if failures.is_empty() {
        Ok(launched)
    } else {
        Err(failures.join("; "))
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AuthenticationForm {
    #[default]
    Key,
    Agent,
    InteractivePassword,
    SavedPassword,
    NeedsConfiguration,
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
                    SshAuthentication::InteractivePassword => {
                        AuthenticationForm::InteractivePassword
                    }
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
                let entered_identity =
                    (!self.identity.trim().is_empty()).then(|| PathBuf::from(self.identity.trim()));
                let authentication = match self.authentication {
                    AuthenticationForm::Key => {
                        if entered_identity.is_none() {
                            return Err(UiValidationError::MissingIdentity);
                        }
                        SshAuthentication::Key
                    }
                    AuthenticationForm::Agent => SshAuthentication::Agent,
                    AuthenticationForm::InteractivePassword => {
                        SshAuthentication::InteractivePassword
                    }
                    AuthenticationForm::SavedPassword => {
                        let reference = SavedSecretReference::new(self.secret_reference.trim())
                            .map_err(|_| UiValidationError::InvalidSavedSecretReference)?;
                        SshAuthentication::SavedPassword(reference)
                    }
                    AuthenticationForm::NeedsConfiguration => {
                        return Err(UiValidationError::SshAuthenticationRequired);
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

    fn without_saved_credentials(mut self) -> Self {
        if matches!(self.authentication, AuthenticationForm::SavedPassword) {
            self.authentication = AuthenticationForm::NeedsConfiguration;
            self.secret_reference.clear();
            self.identity.clear();
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloneAuthorizationChoice {
    Reset,
    CopyUnattendedDestructive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileForm {
    id: Option<SyncProfileId>,
    profile_revision: Option<u64>,
    name: String,
    peer_a: EndpointForm,
    peer_b: EndpointForm,
    mode: SyncMode,
    source: OneWaySource,
    safe_delete: bool,
    deletion_method: Option<DeletionMethod>,
    destination_cleanup: bool,
    exclusions: String,
    timestamps: bool,
    ownership: bool,
    access_control_lists: bool,
    extended_attributes: bool,
    partial_transfer_policy: PartialTransferPolicy,
    retry_attempts: String,
    retry_delay_millis: String,
    schedule_enabled: bool,
    schedule_interval_minutes: String,
    schedule_timezone: String,
    clone_source: Option<SyncProfileId>,
    clone_source_endpoints: Option<(Peer, Peer)>,
    clone_source_authorizations: AuthorizationSnapshot,
    profile_authorizations: AuthorizationSnapshot,
    clone_authorization_choice: CloneAuthorizationChoice,
    clone_authorization_confirmed: bool,
}

impl Default for ProfileForm {
    fn default() -> Self {
        Self {
            id: None,
            profile_revision: None,
            name: String::new(),
            peer_a: EndpointForm::source_defaults(),
            peer_b: EndpointForm::destination_defaults(),
            mode: SyncMode::OneWay,
            source: OneWaySource::PeerA,
            safe_delete: false,
            deletion_method: None,
            destination_cleanup: false,
            exclusions: String::new(),
            timestamps: false,
            ownership: false,
            access_control_lists: false,
            extended_attributes: false,
            partial_transfer_policy: PartialTransferPolicy::Cleanup,
            retry_attempts: RetryPolicy::default().max_attempts().to_string(),
            retry_delay_millis: RetryPolicy::default()
                .initial_delay()
                .as_millis()
                .to_string(),
            schedule_enabled: false,
            schedule_interval_minutes: "60".to_owned(),
            schedule_timezone: "UTC".to_owned(),
            clone_source: None,
            clone_source_endpoints: None,
            clone_source_authorizations: AuthorizationSnapshot::default(),
            profile_authorizations: AuthorizationSnapshot::default(),
            clone_authorization_choice: CloneAuthorizationChoice::Reset,
            clone_authorization_confirmed: false,
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
            profile_revision: Some(profile.revision()),
            name: value.name().to_owned(),
            peer_a: EndpointForm::from_peer(value.peer_a()),
            peer_b: EndpointForm::from_peer(value.peer_b()),
            mode: value.mode(),
            source: value.source(),
            safe_delete: options.safe_delete,
            deletion_method: options.deletion_method,
            destination_cleanup: options.destination_cleanup,
            exclusions: value.exclusions().join("\n"),
            timestamps: metadata.timestamps(),
            ownership: specialist.ownership(),
            access_control_lists: specialist.access_control_lists(),
            extended_attributes: specialist.extended_attributes(),
            partial_transfer_policy: options.partial_transfer_policy,
            retry_attempts: options.retry_policy.max_attempts().to_string(),
            retry_delay_millis: options.retry_policy.initial_delay().as_millis().to_string(),
            schedule_enabled: profile.schedule_enabled(),
            schedule_interval_minutes: profile
                .schedule()
                .map(|schedule| schedule.interval_minutes().to_string())
                .unwrap_or_else(|| "60".to_owned()),
            schedule_timezone: profile
                .schedule()
                .map(|schedule| schedule.timezone().to_owned())
                .unwrap_or_else(|| "UTC".to_owned()),
            clone_source: None,
            clone_source_endpoints: None,
            clone_source_authorizations: AuthorizationSnapshot::default(),
            profile_authorizations: profile.authorizations(),
            clone_authorization_choice: CloneAuthorizationChoice::Reset,
            clone_authorization_confirmed: false,
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
            .filter(|attempts| (1..=RetryPolicy::MAX_ATTEMPTS).contains(attempts))
            .ok_or(UiValidationError::InvalidRetryAttempts)?;
        let retry_delay_millis = self
            .retry_delay_millis
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|delay| *delay <= 3_600_000)
            .ok_or(UiValidationError::InvalidRetryDelay)?;
        let options = SyncOptions {
            safe_delete: self.safe_delete,
            destination_cleanup: self.destination_cleanup,
            deletion_method: self
                .safe_delete
                .then(|| self.deletion_method.unwrap_or(DeletionMethod::Trash)),
            metadata: MetadataRequirements::new(true, true, true, self.timestamps)
                .with_specialist_metadata(SpecialistMetadataRequirements::new(
                    self.ownership,
                    self.access_control_lists,
                    self.extended_attributes,
                )),
            partial_transfer_policy: self.partial_transfer_policy,
            retry_policy: RetryPolicy::new(
                retry_attempts,
                Duration::from_millis(retry_delay_millis),
            ),
        };
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

    fn build_schedule(&self) -> Result<ScheduleDefinition, UiValidationError> {
        let interval_minutes = self
            .schedule_interval_minutes
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|interval| (1..=10_080).contains(interval))
            .ok_or(UiValidationError::InvalidScheduleInterval)?;
        let timezone = self.schedule_timezone.trim();
        if timezone.is_empty() || timezone.len() > 128 || timezone.contains('\0') {
            return Err(UiValidationError::InvalidScheduleTimezone);
        }
        ScheduleDefinition::new(interval_minutes, timezone, self.schedule_enabled)
            .map_err(|error| UiValidationError::Core(error.to_string()))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingReportAction {
    RemoveCompletedReport(RunId),
    DiscardUnresolvedRun(RunId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    GettingStarted,
    Modes,
    OneWaySync,
    SafeDelete,
    MirrorSync,
    ConflictReview,
    Exclusions,
    SshAuthentication,
    Recovery,
    RunReports,
    DestructiveActions,
    PlanAndConfirmation,
    ProgressAndCancellation,
    Diagnostics,
    PrecheckBlockers,
    ExecutionFailures,
    CloneProfile,
}

impl HelpTopic {
    pub fn label(self) -> &'static str {
        help_entry(self).title
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelpEntry {
    pub topic: HelpTopic,
    pub title: &'static str,
    pub what: &'static str,
    pub why: &'static str,
    pub how: &'static str,
    pub when: &'static str,
    pub consequences: &'static str,
    pub limitations: &'static str,
    pub next_action: &'static str,
}

const HELP_TOPICS: &[HelpTopic] = &[
    HelpTopic::GettingStarted,
    HelpTopic::Modes,
    HelpTopic::OneWaySync,
    HelpTopic::SafeDelete,
    HelpTopic::MirrorSync,
    HelpTopic::ConflictReview,
    HelpTopic::Exclusions,
    HelpTopic::SshAuthentication,
    HelpTopic::Recovery,
    HelpTopic::RunReports,
    HelpTopic::DestructiveActions,
    HelpTopic::PlanAndConfirmation,
    HelpTopic::ProgressAndCancellation,
    HelpTopic::Diagnostics,
    HelpTopic::PrecheckBlockers,
    HelpTopic::ExecutionFailures,
    HelpTopic::CloneProfile,
];

const HELP_GROUPS: &[(&str, &[HelpTopic])] = &[
    (
        "Start here",
        &[
            HelpTopic::GettingStarted,
            HelpTopic::Modes,
            HelpTopic::PlanAndConfirmation,
        ],
    ),
    (
        "Sync modes",
        &[
            HelpTopic::OneWaySync,
            HelpTopic::SafeDelete,
            HelpTopic::MirrorSync,
            HelpTopic::ConflictReview,
            HelpTopic::Exclusions,
        ],
    ),
    (
        "Safety & recovery",
        &[
            HelpTopic::DestructiveActions,
            HelpTopic::Recovery,
            HelpTopic::ProgressAndCancellation,
            HelpTopic::RunReports,
        ],
    ),
    (
        "Troubleshooting",
        &[
            HelpTopic::Diagnostics,
            HelpTopic::PrecheckBlockers,
            HelpTopic::ExecutionFailures,
            HelpTopic::SshAuthentication,
        ],
    ),
    ("Profiles & advanced", &[HelpTopic::CloneProfile]),
];

pub fn help_topics() -> &'static [HelpTopic] {
    HELP_TOPICS
}

pub fn help_entry(topic: HelpTopic) -> HelpEntry {
    match topic {
        HelpTopic::GettingStarted => HelpEntry {
            topic,
            title: "Getting started",
            what: "SyncPlus moves files through a named Sync Profile with a visible source, destination, reviewable plan, and explicit confirmation step.",
            why: "The first run should teach you what will happen before it changes anything. Saving a profile never starts a Sync Run.",
            how: "Create a profile, choose the sync type, select the source and destination folders, review the saved profile, then open the Sync workspace for Fresh Analysis and confirmation.",
            when: "Start here when SyncPlus is new to you or when you want a quick reminder of the safe workflow.",
            consequences: "A new profile defaults to Simple Mode and non-destructive One-Way Sync. Nothing changes until the exact reviewed plan is explicitly confirmed.",
            limitations: "SyncPlus does not accept arbitrary shell or rsync commands, silently resolve conflicts, or treat transfer counts as proof of completion.",
            next_action: "Create your first Sync Profile, then follow the four-step wizard through sync method, source, destination, and review.",
        },
        HelpTopic::Modes => HelpEntry {
            topic,
            title: "Simple and Advanced Mode",
            what: "Simple Mode provides the calm default workflow. Advanced Mode reveals named safety, recovery, metadata, retry, and unattended controls.",
            why: "The default should make safe, non-destructive choices easy while keeping higher-risk decisions deliberate.",
            how: "Choose the mode in the top bar. Both modes use the same validated core workflow and never accept arbitrary rsync or shell arguments.",
            when: "Use Simple Mode for ordinary One-Way Sync. Use Advanced Mode when you understand and need Safe Delete, Mirror review, metadata, or unattended authorization.",
            consequences: "Advanced controls can change more data or run without you present, so they add explicit authorization and review requirements.",
            limitations: "Advanced Mode does not bypass prechecks, Fresh Analysis, verification, host-identity review, confirmation, or Recovery Review.",
            next_action: "Start in Simple Mode, create a Sync Profile, and open the related topic before enabling any destructive option.",
        },
        HelpTopic::OneWaySync => HelpEntry {
            topic,
            title: "One-Way Sync",
            what: "One-Way Sync copies the selected source into the selected destination; the source is authoritative for differing paths.",
            why: "A single authority makes ordinary backup-style synchronization understandable and avoids inventing a winner for two changed peers.",
            how: "Select named source and destination endpoints, review the Fresh Analysis, then confirm the exact mapping and actions.",
            when: "Use it when one peer is the intended source of truth and the destination should follow it.",
            consequences: "The destination may receive copies or verified replacements. Safe Delete and Destination Cleanup are separate opt-in actions.",
            limitations: "A stale plan, changed source, failed verification, excluded item, or unresolved item keeps the affected work from being treated as complete.",
            next_action: "Review the mapping and approved scope, then run Fresh Analysis immediately before confirmation.",
        },
        HelpTopic::SafeDelete => HelpEntry {
            topic,
            title: "One-Way Safe-Delete Sync",
            what: "Safe Delete removes an approved source item only after independent SHA-256 and size checks, source-stability checks, destination verification, and a durable journal boundary.",
            why: "A successful transfer alone cannot prove that the exact source item was safely installed and recoverable.",
            how: "Choose a recoverable Trash method where possible, inspect each planned removal, and confirm only after the fresh precheck and analysis pass.",
            when: "Use it only when the source should be drained and you have reviewed the recovery method and expected consequences.",
            consequences: "A verified source item is moved to recovery or removed at the proof boundary. Any uncertainty preserves the source and requires review.",
            limitations: "There is no silent fallback from Trash to Permanent Removal. Excluded, changed, unavailable, or ambiguous items remain at the source.",
            next_action: "Keep Safe Delete off unless the source authority, recovery method, and final Run Report are understood.",
        },
        HelpTopic::MirrorSync => HelpEntry {
            topic,
            title: "Mirror Sync",
            what: "Mirror Sync compares two peers and proposes an approved result without assuming either peer is authoritative.",
            why: "Two peers can both contain unique or changed data, so absence is not deletion evidence and no implicit winner is safe.",
            how: "Run Fresh Analysis for both peers, inspect Conflict Review and baseline evidence, choose whole-file decisions, and confirm the reviewed scope.",
            when: "Use it when both peers matter and you want explicit reconciliation rather than source-to-destination copying.",
            consequences: "Keep, preserve, rename, or defer decisions remain visible in the Run Report; deferred or unresolved work keeps the run open.",
            limitations: "SyncPlus does not merge file contents, infer deletion from first-run absence, or silently choose a winner.",
            next_action: "Open Conflict Review for every proposed conflict and defer the run if the evidence is not clear.",
        },
        HelpTopic::ConflictReview => HelpEntry {
            topic,
            title: "Conflict Review",
            what: "Conflict Review is a read-only, whole-file comparison showing safe metadata, classifications, and available hashes for competing peers.",
            why: "Review keeps both versions protected until you make an explicit decision.",
            how: "Choose Keep Peer A, Keep Peer B, Preserve Both, Rename/Preserve for Review, or Defer for each entry, then start a fresh Resolution Run.",
            when: "Use it whenever Mirror Sync finds same-path differences, naming conflicts, or possible duplicate/rename candidates.",
            consequences: "Keep decisions create reviewed whole-file actions. Preserve Both, rename, and defer choices retain data and keep review open.",
            limitations: "File contents are not edited or automatically merged; equal hashes at different paths do not authorize a move or deletion.",
            next_action: "Review the peer evidence and choose one typed whole-file decision, or choose Defer when evidence is insufficient.",
        },
        HelpTopic::Exclusions => HelpEntry {
            topic,
            title: "Exclusions",
            what: "Exclusion rules keep matching items outside the Approved Sync Scope.",
            why: "An excluded item must not be synchronized or deleted accidentally.",
            how: "Enter one validated pattern per line and inspect the excluded inventory in Fresh Analysis.",
            when: "Use exclusions for caches, generated data, or other content that must remain outside this Sync Run.",
            consequences: "Excluded items remain where they are and are listed as outside scope; they do not count as successfully synchronized.",
            limitations: "Excluded Item Cleanup is a separate reviewed action. Exclusions do not authorize any deletion.",
            next_action: "Check the excluded inventory and make sure every excluded path is intentionally outside this run.",
        },
        HelpTopic::SshAuthentication => HelpEntry {
            topic,
            title: "SSH authentication",
            what: "SSH peers use structured server, account, port, path, and selected key, agent, interactive password, or Saved Secret authentication fields.",
            why: "Typed authentication keeps remote commands controlled and prevents hidden prompts or credential fallback.",
            how: "Choose the approved authentication method, review host identity and remote capability prechecks, and keep saved passwords in the desktop keyring.",
            when: "Use SSH for one local-to-SSH or SSH-to-local peer in V1; unattended runs require a noninteractive credential.",
            consequences: "Missing credentials, changed fingerprints, unavailable remote hashing, permissions, or recovery block the affected run and preserve source data.",
            limitations: "SSH-to-SSH and arbitrary remote commands are outside V1. Passwords, passphrases, private keys, and file contents are never report data.",
            next_action: "Approve a new fingerprint only after independent review; reject changed identity and fix the reported precheck blocker.",
        },
        HelpTopic::Recovery => HelpEntry {
            topic,
            title: "Recovery Review",
            what: "Recovery Review preserves source or destination state after interruption, failed verification, disconnect, crash, or an ambiguous filesystem boundary.",
            why: "SQLite records evidence but cannot make a database commit and filesystem mutation one atomic transaction.",
            how: "Open the Run Report, perform Fresh Analysis where the workflow provides it, and inspect Recovery Review and provenance before taking any explicit metadata action.",
            when: "Use it whenever a run is Interrupted, Recovery Review, pending review, or a recovery item needs restoration.",
            consequences: "Uncertainty keeps the run open and preserves user files; no uncertain deletion or replacement is treated as complete.",
            limitations: "Recovery evidence may prove only what was observed. SyncPlus never guesses completion or repeats uncertain deletion, and this surface does not provide an automatic recovery action.",
            next_action: "Read the preserved-state evidence, keep unresolved metadata available for review, and use only the explicit metadata action currently shown when appropriate.",
        },
        HelpTopic::RunReports => HelpEntry {
            topic,
            title: "Run Reports",
            what: "A Run Report retains the Profile Snapshot, plan, action outcomes, warnings, reconciliation, verification, and recovery evidence for one Sync Run.",
            why: "History must remain inspectable so a completed or unresolved result can be understood after restart.",
            how: "Select a report to inspect its status and explainable actions. Remove completed metadata or discard unresolved metadata only through the separate explicit actions.",
            when: "Review reports after every manual or unattended run, especially when the status is failed, cancelled, interrupted, blocked, or pending review.",
            consequences: "Removing metadata does not touch source or destination files. Discarding unresolved metadata loses the report's recovery evidence.",
            limitations: "Reports contain operational metadata and safe evidence, never passwords, private-key material, or file contents.",
            next_action: "Resolve every review item before marking Review Cleared; retain unresolved reports until their evidence is no longer needed.",
        },
        HelpTopic::DestructiveActions => HelpEntry {
            topic,
            title: "Destructive actions",
            what: "Safe Delete, Destination Cleanup, and Permanent Removal are named, separately reviewed actions that can remove user data.",
            why: "Deletion needs stronger intent and proof than copying, and Permanent Removal is irreversible.",
            how: "Enable destructive options only in Advanced Mode, select the recovery method, review the exact scope, and provide the required authorization and confirmation.",
            when: "Use destructive actions only after checking the source authority, recovery capacity, path warnings, and Run Report consequences.",
            consequences: "Trash is recoverable only when verified. Permanent Removal cannot be undone and requires separate explicit authorization for unattended use.",
            limitations: "No safety gate can be bypassed. Unavailable Trash never falls back silently, and uncertain or changed items remain preserved.",
            next_action: "Prefer recoverable Trash and leave destructive options disabled until the complete plan and proof boundary are understood.",
        },
        HelpTopic::PlanAndConfirmation => HelpEntry {
            topic,
            title: "Plan and confirmation",
            what: "Fresh Analysis and Execution Confirmation show the exact typed mapping, approved scope, actions, warnings, and consequences before mutation.",
            why: "A user should know what will change and why immediately before SyncPlus changes data.",
            how: "Analyze, inspect the plan and precheck, resolve conflicts or blockers, then confirm the same fresh reviewed scope.",
            when: "Run it before every file-changing action and again after profile, endpoint, filesystem, or review evidence changes.",
            consequences: "A stale analysis, required review, failed verification, or precheck blocker disables confirmation and preserves data.",
            limitations: "The technical preview is diagnostic evidence generated from typed options; it is not an editable command interface.",
            next_action: "Fix every blocker, inspect the consequences, and confirm only the exact scope that was freshly analyzed.",
        },
        HelpTopic::ProgressAndCancellation => HelpEntry {
            topic,
            title: "Progress and cancellation",
            what: "Progress shows the current Explainable Action, phase, bytes, warnings, and cancellation state for an active Sync Run.",
            why: "A stopped or partial action must not look like a completed transfer.",
            how: "Watch the active report, cancel to stop launching new actions, and inspect the durable journal before resuming.",
            when: "Use it during a long run or whenever a disconnect, drive removal, process stop, or cancellation occurs.",
            consequences: "Cancellation preserves the source and records a Cancelled Action; an unsettled boundary may require Recovery Review.",
            limitations: "Progress counts are not proof of completion. Only verified journal evidence and Completion Reconciliation can settle a run.",
            next_action: "Read the latest durable phase and open Recovery Review instead of retrying an uncertain action blindly.",
        },
        HelpTopic::Diagnostics => HelpEntry {
            topic,
            title: "Technical diagnostics",
            what: "Diagnostics identify the Sync Profile, peer, account when remote, exact scope, safety requirement, reason, and next safe action.",
            why: "A useful failure explanation should tell you what to inspect or fix without exposing sensitive material.",
            how: "Read the structured blocker or warning and follow its remediation; inspect the linked Help topic for the underlying safety rule.",
            when: "Use diagnostics for precheck blockers, identity or credential failures, permissions, capability failures, naming conflicts, and review states.",
            consequences: "A diagnostic is evidence of why execution is blocked or review-required; it is never permission to bypass the gate.",
            limitations: "Diagnostics omit passwords, passphrases, private keys, secret values, and file contents. Paths and safe metadata may still be shown.",
            next_action: "Correct the named requirement or open Recovery Review; do not paste diagnostic text into an arbitrary command.",
        },
        HelpTopic::PrecheckBlockers => HelpEntry {
            topic,
            title: "Precheck blockers and review states",
            what: "A blocker or review state explains why a Sync Run cannot safely continue or be treated as complete.",
            why: "Prechecks protect user data by stopping before mutation when a required peer, permission, identity, capability, scope, or recovery condition is not proven.",
            how: "Read the named peer, account when remote, exact scope, requirement, reason, and next action; fix the requirement and run Fresh Analysis again.",
            when: "Use this guidance for unavailable peers, unreadable sources, unwritable destinations, permission failures, identity changes, naming conflicts, stale reviews, and unresolved items.",
            consequences: "Confirmation remains unavailable and affected source data stays preserved until the blocker or review item is resolved.",
            limitations: "A blocker is not permission to bypass verification, host-identity review, confirmation, or Recovery Review. Progress or transfer counts do not override it.",
            next_action: "Follow the displayed remediation, re-run the fresh precheck and analysis, or leave the run open for Recovery Review when the state is uncertain.",
        },
        HelpTopic::ExecutionFailures => HelpEntry {
            topic,
            title: "Execution failures and verification review",
            what: "An execution failure records the action boundary, reason, and preserved state when a transfer, replacement, verification, process, or recovery step does not settle safely.",
            why: "A failed action must remain distinguishable from a completed action so SyncPlus never claims that an unverified destination or removal is safe.",
            how: "Inspect the Run Report, the affected peer and scope, the durable phase, and any reconciliation or recovery evidence before deciding what to do next.",
            when: "Use this guidance for failed transfers, verification mismatches, disconnects, unavailable peers, process errors, and actions that remain unresolved after cancellation.",
            consequences: "The affected source is preserved whenever proof is incomplete, and the run remains open for review rather than being silently retried or cleared.",
            limitations: "Progress, rsync exit status, transfer counts, size, mtime, or a single hash do not prove Safe Delete or completion. Uncertain filesystem boundaries require Recovery Review.",
            next_action: "Keep the affected item preserved, inspect its evidence and exact scope, then perform Fresh Analysis or the explicit review action supported by the report.",
        },
        HelpTopic::CloneProfile => HelpEntry {
            topic,
            title: "Clone Profile safeguards",
            what: "Clone Profile creates an editable configuration copy while clearing saved credentials and requiring an endpoint change.",
            why: "A clone must not accidentally share secrets, identity, or unattended deletion authority with its source profile.",
            how: "Review both endpoint forms, configure authentication intentionally, choose whether eligible unattended authorization is copied, and confirm that choice.",
            when: "Use cloning when a new profile is related to an existing one but should be independently reviewed and persisted.",
            consequences: "Permanent Removal authorization is never copied. Changing the clone affects future runs only; active runs keep their Profile Snapshot.",
            limitations: "Cloning does not bypass validation, Advanced Mode, authorization, precheck, Fresh Analysis, or Execution Confirmation.",
            next_action: "Change at least one endpoint, reconfigure the intended credential, and review the clone's authorization warning before saving.",
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelpSurface {
    Profile,
    Plan,
    ConflictReview,
    Progress,
    Report,
    Recovery,
    Clone,
}

fn help_topic_for_surface(surface: HelpSurface) -> HelpTopic {
    match surface {
        HelpSurface::Profile => HelpTopic::Modes,
        HelpSurface::Plan => HelpTopic::PlanAndConfirmation,
        HelpSurface::ConflictReview => HelpTopic::ConflictReview,
        HelpSurface::Progress => HelpTopic::ProgressAndCancellation,
        HelpSurface::Report => HelpTopic::RunReports,
        HelpSurface::Recovery => HelpTopic::Recovery,
        HelpSurface::Clone => HelpTopic::CloneProfile,
    }
}

fn help_topic_for_report_status(status: RunReportStatus) -> HelpTopic {
    match status {
        RunReportStatus::InProgress => HelpTopic::ProgressAndCancellation,
        RunReportStatus::Failed => HelpTopic::ExecutionFailures,
        RunReportStatus::Blocked => HelpTopic::PrecheckBlockers,
        RunReportStatus::Cancelled
        | RunReportStatus::Interrupted
        | RunReportStatus::RecoveryReview
        | RunReportStatus::CompletedWithReviewRequired => {
            help_topic_for_surface(HelpSurface::Recovery)
        }
        RunReportStatus::Completed | RunReportStatus::ReviewCleared => {
            help_topic_for_surface(HelpSurface::Report)
        }
    }
}

fn help_topic_for_error(error: &str) -> HelpTopic {
    let error = error.to_ascii_lowercase();
    if error.contains("ssh") {
        HelpTopic::SshAuthentication
    } else if error.contains("resolution") || error.contains("conflict") {
        HelpTopic::ConflictReview
    } else if error.contains("stale") || error.contains("changed") || error.contains("analysis") {
        HelpTopic::PlanAndConfirmation
    } else if error.contains("precheck") || error.contains("blocker") {
        HelpTopic::PrecheckBlockers
    } else {
        HelpTopic::Diagnostics
    }
}

fn next_action_for_help_topic(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::ConflictReview => {
            "Review every whole-file conflict decision and start a fresh Resolution Run."
        }
        HelpTopic::PlanAndConfirmation => {
            "Run Fresh Analysis again, inspect the exact scope, and confirm only after it is current."
        }
        HelpTopic::SshAuthentication => {
            "Review the selected SSH method, host identity, account, and remote capabilities before confirmation."
        }
        HelpTopic::PrecheckBlockers => {
            "Follow the displayed remediation and run the fresh precheck again; do not bypass the blocker."
        }
        HelpTopic::ExecutionFailures | HelpTopic::Recovery => {
            "Keep the affected state preserved and inspect the Run Report and Recovery Review evidence."
        }
        _ => "Read the linked Help guidance and follow its safe next action.",
    }
}

fn single_line(value: impl AsRef<str>) -> String {
    value.as_ref().replace(['\r', '\n'], " ")
}

fn peer_for_path<'a>(profile: &'a SyncProfile, path: &std::path::Path) -> &'a Peer {
    if path == profile.peer_b().root() || path.starts_with(profile.peer_b().root()) {
        profile.peer_b()
    } else {
        profile.peer_a()
    }
}

fn peer_diagnostic_label(peer: &Peer) -> String {
    match peer.endpoint() {
        syncplus_core::PeerEndpoint::Local { .. } => {
            format!("{} (local)", single_line(peer.name()))
        }
        syncplus_core::PeerEndpoint::Ssh(ssh) => format!(
            "{} (account {}@{}:{})",
            single_line(peer.name()),
            single_line(ssh.username()),
            single_line(ssh.server()),
            ssh.port()
        ),
    }
}

fn diagnostic_peer<'a>(profile: &'a SyncProfile, path: Option<&std::path::Path>) -> &'a Peer {
    if let Some(path) = path {
        return peer_for_path(profile, path);
    }
    [profile.peer_a(), profile.peer_b()]
        .into_iter()
        .find(|peer| peer.is_ssh())
        .unwrap_or_else(|| mapped_peers(profile).0)
}

fn profile_scope(profile: &SyncProfile) -> String {
    let (source, destination) = mapped_peers(profile);
    if profile.mode() == SyncMode::OneWay {
        format!(
            "{} -> {}",
            source.root().display(),
            destination.root().display()
        )
    } else {
        format!(
            "Peer A {} <-> Peer B {}",
            profile.peer_a().root().display(),
            profile.peer_b().root().display()
        )
    }
}

fn format_profile_diagnostic(
    profile: &SyncProfile,
    path: Option<&std::path::Path>,
    reason: impl AsRef<str>,
    next_action: impl AsRef<str>,
) -> String {
    let peer = diagnostic_peer(profile, path);
    let account = peer
        .ssh_peer()
        .map(|ssh| single_line(ssh.username()))
        .unwrap_or_else(|| "not applicable (local peer)".to_owned());
    let scope = path.map_or_else(|| profile_scope(profile), |path| path.display().to_string());
    format!(
        "Profile: {} | Peer: {} | Account: {} | Scope: {} | Reason: {} | Next action: {}",
        single_line(profile.name()),
        peer_diagnostic_label(peer),
        account,
        single_line(scope),
        single_line(reason),
        single_line(next_action)
    )
}

fn format_form_validation_diagnostic(form: &ProfileForm, error: &UiValidationError) -> String {
    let (peer, endpoint) = match error {
        UiValidationError::EmptyPeerName { peer } | UiValidationError::EmptyLocalPath { peer } => {
            if *peer == "Source" {
                ("Source", &form.peer_a)
            } else {
                ("Destination", &form.peer_b)
            }
        }
        _ if form.peer_a.kind == EndpointKind::Ssh => ("Source", &form.peer_a),
        _ if form.peer_b.kind == EndpointKind::Ssh => ("Destination", &form.peer_b),
        _ => ("Source and destination", &form.peer_a),
    };
    let account = if endpoint.kind == EndpointKind::Ssh {
        if endpoint.username.trim().is_empty() {
            "not configured".to_owned()
        } else {
            single_line(endpoint.username.trim())
        }
    } else {
        "not applicable (local peer)".to_owned()
    };
    let scope = if endpoint.kind == EndpointKind::Ssh {
        endpoint.remote_path.trim().to_owned()
    } else {
        endpoint.local_path.trim().to_owned()
    };
    let scope = if scope.is_empty() {
        format!(
            "{} -> {}",
            form.peer_a.local_path.trim(),
            form.peer_b.local_path.trim()
        )
    } else {
        scope
    };
    format!(
        "Profile: {} | Peer: {} | Account: {} | Scope: {} | Reason: {} | Next action: correct the named typed field and validate the profile again.",
        single_line(if form.name.trim().is_empty() {
            "(unsaved profile)"
        } else {
            form.name.trim()
        }),
        peer,
        account,
        single_line(scope),
        single_line(error.to_string())
    )
}

fn format_precheck_diagnostic(
    profile: &SyncProfile,
    blocker: &syncplus_core::PrecheckBlocker,
) -> String {
    format_profile_diagnostic(
        profile,
        Some(blocker.path()),
        format!(
            "{} (requirement: {})",
            blocker.reason(),
            blocker.requirement()
        ),
        blocker.remediation(),
    )
}

fn format_precheck_error(profile: &SyncProfile, error: &PrecheckErrorKind) -> String {
    match error {
        PrecheckErrorKind::InvalidSpecification(error) => format_profile_diagnostic(
            profile,
            None,
            format!("invalid profile: {error}"),
            "Correct the typed profile fields and run Fresh Analysis again.",
        ),
        PrecheckErrorKind::Probe(error) => format_profile_diagnostic(
            profile,
            Some(error.path()),
            format!("{}: {}", error.operation(), error.detail()),
            "Correct the named precheck requirement and run Fresh Analysis again.",
        ),
    }
}

fn format_ssh_precheck_boundary_diagnostic(profile: &SyncProfile) -> String {
    let (remote, request) = match RemotePrecheckRequest::from_profile(profile) {
        Ok(value) => value,
        Err(error) => {
            return format_profile_diagnostic(
                profile,
                None,
                format!("SSH precheck profile could not be derived: {error}"),
                "Correct the typed SSH profile fields and run Fresh Analysis again.",
            );
        }
    };
    let access = request.access();
    format_profile_diagnostic(
        profile,
        Some(remote.remote_path()),
        format!(
            "SSH remote precheck is not available at this desktop workflow boundary; host identity, the selected credential, account access, remote rsync, SHA-256, and recovery capability are not proven (requested read={}, write={}, remove={}, recovery={})",
            access.read(),
            access.write(),
            access.remove(),
            request.require_recovery()
        ),
        "Keep execution blocked and source data preserved until the typed SSH remote precheck returns a reviewed result for this peer.",
    )
}

const PATH_RISK_WARNING_LABEL: &str = "Path Risk Warning";
const QUIT_ACTIVE_RUN_COPY: &str = "Stop and Quit requests cancellation. The core workflow records the cancellation boundary, preserves affected source data, and may leave the Run Report in Recovery Review.";
const QUIT_STOPPING_COPY: &str = "SyncPlus will quit only after the durable cancellation boundary is recorded. The Run Report remains available for Recovery Review.";

fn format_warning_diagnostic(
    profile: &SyncProfile,
    warning: &syncplus_core::PathRiskWarning,
) -> String {
    format_profile_diagnostic(
        profile,
        Some(warning.source()),
        warning.explanation(),
        "Type the exact displayed source path as stronger confirmation, or disable Safe Delete.",
    )
}

fn format_naming_conflict_diagnostic(
    profile: &SyncProfile,
    conflict: &syncplus_core::NamingConflict,
) -> String {
    format_profile_diagnostic(
        profile,
        Some(conflict.destination_path()),
        format!(
            "destination naming rule {:?} prevents a safe mapping",
            conflict.rule()
        ),
        "Rename or exclude the item, or choose compatible destination storage, then run Fresh Analysis again.",
    )
}

pub struct SyncPlusApp {
    store: RunEvidenceStore,
    secret_store: Box<dyn SecretStore>,
    settings: ApplicationSettings,
    profiles: Vec<PersistedSyncProfile>,
    view: AppView,
    wizard_step: Option<ProfileWizardStep>,
    form: ProfileForm,
    status: String,
    review: Option<PlanReviewState>,
    run_reports: Vec<RunReport>,
    missed_schedule_notices: Vec<MissedScheduleNotice>,
    scheduler_events: Vec<SchedulerEvent>,
    selected_run_report: Option<RunId>,
    pending_report_action: Option<PendingReportAction>,
    help_topic: HelpTopic,
    tray: Option<TrayRuntime>,
    tray_attempted: bool,
    window_hidden_to_tray: bool,
    quit_flow: QuitFlow,
    exit_requested: bool,
    active_analysis: Option<ActiveAnalysis>,
    active_manual_run: Option<ActiveManualRun>,
    notifications: Vec<UiNotification>,
    known_scheduler_event_ids: BTreeSet<u64>,
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
        let run_reports = store.list_run_reports()?;
        let missed_schedule_notices = store.list_missed_schedule_notices()?;
        let scheduler_events = store.list_scheduler_events()?;
        let selected_run_report = run_reports.first().map(RunReport::run_id);
        let known_scheduler_event_ids = scheduler_events
            .iter()
            .map(SchedulerEvent::event_id)
            .collect();
        let (view, form, status) = if let Some(profile) = profiles.first() {
            (
                AppView::Sync,
                ProfileForm::from_persisted(profile),
                format!("Ready to review {}.", profile.profile().name()),
            )
        } else {
            (
                AppView::Welcome,
                ProfileForm::default(),
                "Ready. Create a Sync Profile to begin.".to_owned(),
            )
        };
        Ok(Self {
            store,
            secret_store: Box::new(secret_store),
            settings,
            profiles,
            view,
            wizard_step: None,
            form,
            status,
            review: None,
            run_reports,
            missed_schedule_notices,
            scheduler_events,
            selected_run_report,
            pending_report_action: None,
            help_topic: HelpTopic::GettingStarted,
            tray: None,
            tray_attempted: false,
            window_hidden_to_tray: false,
            quit_flow: QuitFlow::None,
            exit_requested: false,
            active_analysis: None,
            active_manual_run: None,
            notifications: Vec::new(),
            known_scheduler_event_ids,
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

    pub fn run_reports(&self) -> &[RunReport] {
        &self.run_reports
    }

    pub fn missed_schedule_notices(&self) -> &[MissedScheduleNotice] {
        &self.missed_schedule_notices
    }

    pub fn scheduler_events(&self) -> &[SchedulerEvent] {
        &self.scheduler_events
    }

    pub fn notifications(&self) -> &[UiNotification] {
        &self.notifications
    }

    pub const fn window_hidden_to_tray(&self) -> bool {
        self.window_hidden_to_tray
    }

    pub fn active_manual_run_id(&self) -> Option<RunId> {
        self.active_manual_run.as_ref().map(|run| run.run_id)
    }

    pub fn selected_run_report(&self) -> Option<&RunReport> {
        self.selected_run_report.and_then(|run_id| {
            self.run_reports
                .iter()
                .find(|report| report.run_id() == run_id)
        })
    }

    pub fn help_topic(&self) -> HelpTopic {
        self.help_topic
    }

    pub fn selected_help_entry(&self) -> HelpEntry {
        help_entry(self.help_topic)
    }

    pub fn select_help_topic(&mut self, topic: HelpTopic) {
        self.help_topic = topic;
    }

    fn show_welcome(&mut self) {
        self.view = AppView::Welcome;
        self.wizard_step = None;
    }

    fn show_profiles(&mut self) {
        self.view = AppView::Profiles;
        self.wizard_step = None;
    }

    fn show_settings(&mut self) {
        self.view = AppView::Settings;
        self.wizard_step = None;
    }

    fn show_sync_workspace(&mut self) {
        self.view = AppView::Sync;
        self.wizard_step = None;
    }

    fn open_sync_workspace(&mut self) {
        if self.form.id.is_some() {
            self.show_sync_workspace();
        } else {
            self.start_new_profile();
        }
    }

    fn show_reports(&mut self) {
        self.view = AppView::Reports;
        self.wizard_step = None;
    }

    fn show_help(&mut self, topic: HelpTopic) {
        self.help_topic = topic;
        self.view = AppView::Help;
        self.wizard_step = None;
    }

    fn chrome_surface(&self) -> ChromeSurface {
        match self.view {
            AppView::Welcome => ChromeSurface::Overview,
            AppView::Profiles => ChromeSurface::Profiles,
            AppView::Settings => ChromeSurface::Settings,
            AppView::Wizard | AppView::Sync => ChromeSurface::SyncWorkspace,
            AppView::Reports => ChromeSurface::Reports,
            AppView::Help => ChromeSurface::Help,
        }
    }

    fn recovery_review_pending(&self) -> bool {
        chrome::recovery_review_is_pending(self.run_reports.iter().map(RunReport::status))
    }

    fn report_review_pending(&self) -> bool {
        chrome::report_review_is_pending(self.run_reports.iter().map(RunReport::status))
    }

    fn last_run_status_for_active_profile(&self) -> Option<RunReportStatus> {
        self.run_reports.iter().find_map(|report| {
            (report.snapshot().profile().name() == self.form.name).then_some(report.status())
        })
    }

    fn recovery_review_pending_for_active_profile(&self) -> bool {
        chrome::recovery_review_is_pending(self.run_reports.iter().filter_map(|report| {
            (report.snapshot().profile().name() == self.form.name).then_some(report.status())
        }))
    }

    fn open_recovery_review(&mut self) {
        self.show_reports();
        self.help_topic = HelpTopic::Recovery;
    }

    pub fn refresh_run_reports(&mut self) -> Result<(), UiValidationError> {
        let reports = self
            .store
            .list_run_reports()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        let selected = self
            .selected_run_report
            .filter(|run_id| reports.iter().any(|report| report.run_id() == *run_id))
            .or_else(|| reports.first().map(RunReport::run_id));
        self.run_reports = reports;
        self.missed_schedule_notices = self
            .store
            .list_missed_schedule_notices()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        let scheduler_events = self
            .store
            .list_scheduler_events()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        self.record_new_scheduler_notifications(&scheduler_events);
        self.scheduler_events = scheduler_events;
        self.selected_run_report = selected;
        if self
            .pending_report_action
            .is_some_and(|action| match action {
                PendingReportAction::RemoveCompletedReport(run_id)
                | PendingReportAction::DiscardUnresolvedRun(run_id) => self
                    .run_reports
                    .iter()
                    .all(|report| report.run_id() != run_id),
            })
        {
            self.pending_report_action = None;
        }
        Ok(())
    }

    fn record_new_scheduler_notifications(&mut self, events: &[SchedulerEvent]) {
        for event in events {
            if !self.known_scheduler_event_ids.insert(event.event_id()) {
                continue;
            }
            let message = notification_for_scheduler_event(event);
            let mut sink = DesktopNotificationSink;
            let _ = self
                .store
                .deliver_scheduler_notification(event.event_id(), &mut sink);
            self.remember_notification(message);
        }
    }

    fn push_notification(&mut self, notification: UiNotification) {
        let _ = deliver_desktop_notification(
            &notification.title,
            &notification.reason,
            &notification.next_action,
        );
        self.remember_notification(notification);
    }

    fn remember_notification(&mut self, notification: UiNotification) {
        self.notifications.insert(0, notification);
        self.notifications.truncate(20);
    }

    pub fn start_manual_run(&mut self) -> Result<(), UiValidationError> {
        if self.active_manual_run.is_some() {
            return Err(UiValidationError::Core(
                "a manual Sync Run is already active".to_owned(),
            ));
        }
        let (profile, expected) = {
            let review = self
                .review
                .as_ref()
                .ok_or(UiValidationError::ReviewNotReady)?;
            if !review.confirmed {
                return Err(UiValidationError::ReviewNotReady);
            }
            let profile = review.profile.clone();
            let expected = review
                .analysis
                .as_ref()
                .ok_or(UiValidationError::ReviewNotReady)?
                .confirm(&profile)
                .map_err(|error| UiValidationError::Analysis(error.to_string()))?;
            (profile, expected)
        };
        let run_id = self
            .store
            .next_run_id()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::channel();
        thread::Builder::new()
            .name(format!("syncplus-manual-run-{}", run_id.value()))
            .spawn(move || {
                let result = execute_manual_run(run_id, profile, expected, worker_cancel);
                let _ = sender.send(ManualRunCompletion { run_id, result });
            })
            .map_err(|error| {
                UiValidationError::Core(format!("could not start Sync Run: {error}"))
            })?;
        self.active_manual_run = Some(ActiveManualRun {
            run_id,
            cancel,
            receiver,
        });
        self.status = format!(
            "Manual Sync Run {} is active. Closing the window hides SyncPlus and leaves this run active.",
            run_id.value()
        );
        Ok(())
    }

    fn request_synchronise(&mut self) {
        if self.active_manual_run.is_some() {
            self.status =
                "A Manual Sync Run is already active. Review its Run Report for progress."
                    .to_owned();
            return;
        }

        match self.review.as_ref() {
            Some(review) if review.confirmed => {
                if let Err(error) = self.start_manual_run() {
                    self.status = format!("Synchronise was not started: {error}");
                }
            }
            Some(_) => {
                self.status = "Review the current read-only plan and complete Execution Confirmation before Synchronise can change files.".to_owned();
            }
            None => {
                if let Err(error) = self.analyze_profile() {
                    self.status = format_form_validation_diagnostic(&self.form, &error);
                } else {
                    self.status = "Fresh Analysis completed. Review the plan, pass Run Precheck, and confirm the exact scope before Synchronise can change files.".to_owned();
                }
            }
        }
    }

    fn request_synchronise_async(&mut self, context: &egui::Context) {
        if self.review.is_none() {
            if let Err(error) = self.start_analysis(context) {
                self.status = format_form_validation_diagnostic(&self.form, &error);
            }
        } else {
            self.request_synchronise();
        }
    }

    fn request_manual_cancel(&mut self, run_id: RunId) {
        if let Some(active) = self
            .active_manual_run
            .as_ref()
            .filter(|active| active.run_id == run_id)
        {
            active.cancel.store(true, Ordering::Release);
            self.status = format!(
                "Cancellation requested for Manual Sync Run {}. The core workflow is settling its durable boundary; source data remains protected until verification.",
                run_id.value()
            );
        }
    }

    fn poll_manual_run(&mut self, context: &egui::Context) {
        let completion = match self
            .active_manual_run
            .as_ref()
            .map(|active| active.receiver.try_recv())
        {
            Some(Ok(completion)) => completion,
            Some(Err(TryRecvError::Empty)) => return,
            Some(Err(TryRecvError::Disconnected)) => {
                let run_id = self
                    .active_manual_run
                    .take()
                    .expect("active run checked")
                    .run_id;
                self.quit_flow = QuitFlow::None;
                self.status = format!(
                    "Manual Sync Run {} ended without a completion message. Keep the source preserved and inspect any available Run Report or Recovery Review evidence.",
                    run_id.value()
                );
                return;
            }
            None => return,
        };
        let waiting_to_quit = self.quit_flow == QuitFlow::Stopping(completion.run_id);
        self.active_manual_run = None;
        let error_message = match completion.result {
            Ok(report) => {
                self.status = format!(
                    "Manual Sync Run {} settled as {}.",
                    completion.run_id.value(),
                    run_report_status_label(report.status())
                );
                None
            }
            Err(error) => {
                self.status = format!(
                    "Manual Sync Run {} did not settle normally: {error}",
                    completion.run_id.value()
                );
                Some(error)
            }
        };
        if let Err(error) = self.refresh_run_reports() {
            self.status = format!("Run Reports are unavailable: {error}");
        }
        let durable_terminal_report = self
            .run_reports
            .iter()
            .find(|report| report.run_id() == completion.run_id)
            .is_some_and(|report| report.status() != RunReportStatus::InProgress);
        if let Some(report) = self
            .run_reports
            .iter()
            .find(|report| report.run_id() == completion.run_id)
        {
            self.push_notification(notification_for_report(report));
        } else if error_message.is_some() {
            self.push_notification(UiNotification {
                title: "Sync Run did not settle".to_owned(),
                reason: "The workflow ended before a settled Run Report was available.".to_owned(),
                next_action: "Open Run Reports and inspect any available recovery evidence."
                    .to_owned(),
                run_id: Some(completion.run_id),
            });
        }
        if waiting_to_quit && durable_terminal_report {
            self.quit_flow = QuitFlow::None;
            self.exit_requested = true;
            context.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if waiting_to_quit {
            self.quit_flow = QuitFlow::None;
            self.status = format!(
                "Cancellation for Manual Sync Run {} could not be confirmed in a durable terminal Run Report; SyncPlus remains open for Recovery Review.",
                completion.run_id.value()
            );
        }
    }

    fn ensure_tray(&mut self, context: &egui::Context) {
        if let Some(tray) = self.tray.as_ref() {
            if let Ok(mut repaint_context) = tray.repaint_context.lock() {
                *repaint_context = Some(context.clone());
            }
            return;
        }
        if self.tray_attempted {
            return;
        }
        self.tray_attempted = true;
        match TrayRuntime::start() {
            Ok(tray) => {
                if let Ok(mut repaint_context) = tray.repaint_context.lock() {
                    *repaint_context = Some(context.clone());
                }
                self.tray = Some(tray);
            }
            Err(error) => {
                self.status = format!(
                    "System tray is unavailable ({error}); the window will remain visible so SyncPlus stays reachable."
                );
            }
        }
    }

    fn process_tray_commands(&mut self, context: &egui::Context) {
        let commands = self
            .tray
            .as_ref()
            .map(|tray| tray.receiver.try_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        for command in commands {
            match command {
                TrayCommand::ShowWindow => self.show_window(context),
                TrayCommand::Quit => self.request_quit(context),
            }
        }
    }

    fn show_window(&mut self, context: &egui::Context) {
        self.window_hidden_to_tray = false;
        context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        context.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn hide_to_tray(&mut self, context: &egui::Context) {
        if window_close_decision(self.tray.is_some()) == WindowCloseDecision::KeepVisible {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.status = "The system tray is unavailable, so SyncPlus remains visible and the run was not stopped.".to_owned();
            return;
        }
        self.window_hidden_to_tray = true;
        context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        context.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.status = if let Some(active) = self.active_manual_run.as_ref() {
            format!(
                "SyncPlus is hidden in the system tray. Manual Sync Run {} continues; use the tray menu to show the window.",
                active.run_id.value()
            )
        } else {
            "SyncPlus is hidden in the system tray. Scheduled work remains owned by the per-user background scheduler.".to_owned()
        };
    }

    fn request_quit(&mut self, context: &egui::Context) {
        match quit_decision(self.active_manual_run.is_some()) {
            QuitDecision::Exit => {
                self.exit_requested = true;
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            QuitDecision::AskBeforeStopping => {
                let run_id = self
                    .active_manual_run
                    .as_ref()
                    .expect("active run checked")
                    .run_id;
                self.quit_flow = QuitFlow::ConfirmActive(run_id);
                self.show_window(context);
            }
        }
    }

    fn handle_close_request(&mut self, context: &egui::Context) {
        if !self.exit_requested && self.settings.hide_to_tray_on_window_close() {
            self.hide_to_tray(context);
        } else if !self.exit_requested {
            self.request_quit(context);
        }
    }

    fn draw_sidebar_actions(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
        ui.separator();
        ui.add_space(8.0);
        if sidebar_exit_button(ui, "Exit").clicked() {
            self.request_quit(context);
        }
        ui.add_space(12.0);
        if context.input(|input| input.modifiers.command && input.key_pressed(egui::Key::Q)) {
            self.request_quit(context);
        }
    }

    fn draw_quit_dialog(&mut self, context: &egui::Context) {
        let mut keep_running = false;
        let mut stop_and_quit = false;
        let mut cancel = false;
        match self.quit_flow {
            QuitFlow::None => return,
            QuitFlow::ConfirmActive(run_id) => {
                egui::Window::new("Quit SyncPlus")
                    .collapsible(false)
                    .resizable(false)
                    .show(context, |ui| {
                        ui.heading("A manual Sync Run is active");
                        ui.label(format!("Manual Sync Run {} is still running.", run_id.value()));
                        ui.label("Keep running and hide leaves the run active and moves SyncPlus to the tray.");
                        ui.label(QUIT_ACTIVE_RUN_COPY);
                        ui.horizontal(|ui| {
                            if ui.button("Keep running and hide").clicked() {
                                keep_running = true;
                            }
                            if ui.button("Stop and Quit").clicked() {
                                stop_and_quit = true;
                            }
                            if ui.button("Cancel").clicked() {
                                cancel = true;
                            }
                        });
                    });
            }
            QuitFlow::Stopping(run_id) => {
                egui::Window::new("Stopping SyncPlus")
                    .collapsible(false)
                    .resizable(false)
                    .show(context, |ui| {
                        ui.heading("Waiting for the active Sync Run to settle");
                        ui.label(format!(
                            "Cancellation is settling for Manual Sync Run {}.",
                            run_id.value()
                        ));
                        ui.label(QUIT_STOPPING_COPY);
                    });
            }
        }
        if cancel {
            self.quit_flow = QuitFlow::None;
        } else if keep_running {
            self.quit_flow = QuitFlow::None;
            self.hide_to_tray(context);
        } else if stop_and_quit && let QuitFlow::ConfirmActive(run_id) = self.quit_flow {
            self.request_manual_cancel(run_id);
            self.quit_flow = QuitFlow::Stopping(run_id);
        }
    }

    pub fn request_missed_schedule_run_now(
        &mut self,
        notice_id: u64,
    ) -> Result<(), UiValidationError> {
        let notice = self
            .store
            .load_missed_schedule_notice(notice_id)
            .map_err(map_storage_error)?
            .ok_or_else(|| {
                UiValidationError::Core(format!("missed schedule notice {notice_id} was not found"))
            })?;
        if notice.decision() != MissedScheduleDecision::Pending {
            return Err(UiValidationError::Core(format!(
                "missed schedule notice {notice_id} already has a decision"
            )));
        }
        let profile_id = notice.profile_id();
        self.store
            .mark_missed_schedule_decision(notice_id, MissedScheduleDecision::RunNow)
            .map_err(map_storage_error)?;
        self.profiles = self
            .store
            .list_profiles()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        self.select_profile(profile_id);
        let result = self.analyze_profile();
        self.refresh_run_reports()?;
        if result.is_ok() {
            self.status = "Run Now selected. Fresh Analysis and Run Precheck completed; review and request normal Execution Confirmation before any filesystem mutation.".to_owned();
        }
        result
    }

    pub fn record_missed_schedule_not_now(
        &mut self,
        notice_id: u64,
    ) -> Result<(), UiValidationError> {
        self.store
            .mark_missed_schedule_decision(notice_id, MissedScheduleDecision::NotNow)
            .map_err(map_storage_error)?;
        self.refresh_run_reports()?;
        self.status = "No, Not Now recorded. Synchronization did not succeed; the missed schedule remains visible in the durable notice history.".to_owned();
        Ok(())
    }

    pub fn select_run_report(&mut self, run_id: RunId) -> Result<(), UiValidationError> {
        if self
            .run_reports
            .iter()
            .any(|report| report.run_id() == run_id)
        {
            self.selected_run_report = Some(run_id);
            self.pending_report_action = None;
            self.status = format!("Viewing durable report for Sync Run {}.", run_id.value());
            Ok(())
        } else {
            Err(UiValidationError::Core(format!(
                "Sync Run report {} was not found",
                run_id.value()
            )))
        }
    }

    pub fn remove_completed_report(&mut self, run_id: RunId) -> Result<(), UiValidationError> {
        self.store
            .remove_completed_report(run_id)
            .map_err(map_storage_error)?;
        self.refresh_run_reports()?;
        self.status = format!(
            "Removed completed report metadata for Sync Run {}. Source and destination files were not changed.",
            run_id.value()
        );
        Ok(())
    }

    pub fn discard_unresolved_run(&mut self, run_id: RunId) -> Result<(), UiValidationError> {
        self.store
            .discard_unresolved_run(run_id)
            .map_err(map_storage_error)?;
        self.refresh_run_reports()?;
        self.status = format!(
            "Discarded unresolved report metadata for Sync Run {}. Source and destination files were not changed; Recovery Review evidence is no longer available in this report.",
            run_id.value()
        );
        Ok(())
    }

    pub fn mark_review_cleared(&mut self, run_id: RunId) -> Result<(), UiValidationError> {
        self.store
            .mark_review_cleared(run_id)
            .map_err(map_storage_error)?;
        self.refresh_run_reports()?;
        if let Some(report) = self
            .run_reports
            .iter()
            .find(|report| report.run_id() == run_id)
            .cloned()
        {
            self.push_notification(notification_for_report(&report));
        }
        self.status = format!(
            "Marked Sync Run {} as Review Cleared. No source or destination files were changed.",
            run_id.value()
        );
        Ok(())
    }

    pub fn start_new_profile(&mut self) {
        self.form = ProfileForm::default();
        self.review = None;
        self.view = AppView::Wizard;
        self.wizard_step = Some(ProfileWizardStep::SyncMethod);
        self.status =
            "New profile: One-Way Sync is selected and destructive actions are off.".to_owned();
    }

    pub fn clone_profile(&mut self, id: SyncProfileId) -> Result<(), UiValidationError> {
        let persisted = self
            .profiles
            .iter()
            .find(|profile| profile.id() == id)
            .cloned()
            .ok_or_else(|| UiValidationError::Core(format!("Sync Profile {id:?} was not found")))?;
        let source = persisted.profile();
        let has_unattended_authorization =
            persisted.authorizations().allow_unattended_destructive()
                || persisted
                    .authorizations()
                    .allow_unattended_permanent_removal();
        let mut form = ProfileForm::from_persisted(&persisted);
        form.id = None;
        form.profile_revision = None;
        form.name = self.next_clone_name(source.name());
        form.peer_a = form.peer_a.without_saved_credentials();
        form.peer_b = form.peer_b.without_saved_credentials();
        form.deletion_method = form.safe_delete.then_some(DeletionMethod::Trash);
        form.clone_source = Some(id);
        form.clone_source_endpoints = Some((source.peer_a().clone(), source.peer_b().clone()));
        form.clone_source_authorizations = persisted.authorizations();
        form.profile_authorizations = AuthorizationSnapshot::default();
        form.clone_authorization_choice = CloneAuthorizationChoice::Reset;
        form.clone_authorization_confirmed = !has_unattended_authorization;
        self.form = form;
        self.review = None;
        self.status = format!(
            "Cloned {} as an editable copy. Review both endpoints; saved credentials and Permanent Removal authorization are not copied.",
            source.name()
        );
        Ok(())
    }

    pub fn set_mode(&mut self, mode: ApplicationMode) {
        self.settings = ApplicationSettings::new(mode, self.settings.theme())
            .with_hide_to_tray_on_window_close(self.settings.hide_to_tray_on_window_close());
        if let Err(error) = self.store.save_settings(&self.settings) {
            self.status = format!("Could not save mode preference: {error}");
        } else {
            self.status = format!("{} Mode enabled.", mode_label(mode));
        }
    }

    pub fn set_theme(&mut self, theme: ThemePreference) {
        self.settings = ApplicationSettings::new(self.settings.mode(), theme)
            .with_hide_to_tray_on_window_close(self.settings.hide_to_tray_on_window_close());
        if let Err(error) = self.store.save_settings(&self.settings) {
            self.status = format!("Could not save theme preference: {error}");
        }
    }

    fn set_hide_to_tray_on_window_close(&mut self, enabled: bool) {
        self.settings = self.settings.with_hide_to_tray_on_window_close(enabled);
        if let Err(error) = self.store.save_settings(&self.settings) {
            self.status = format!("Could not save window-close preference: {error}");
        }
    }

    pub fn validate_profile(&mut self) -> Result<(), UiValidationError> {
        self.validated_profile()?;
        self.status = "Profile is valid. No run has been started.".to_owned();
        Ok(())
    }

    pub fn save_profile(&mut self) -> Result<SyncProfileId, UiValidationError> {
        let profile = self.validated_profile()?;
        let authorizations = self.validate_clone(&profile)?;
        let schedule = (self.settings.mode() == ApplicationMode::Advanced)
            .then(|| self.form.build_schedule())
            .transpose()?;
        if profile.options().deletion_method == Some(DeletionMethod::PermanentRemoval)
            && self.settings.mode() != ApplicationMode::Advanced
        {
            return Err(UiValidationError::PermanentRemovalRequiresAdvanced);
        }
        if profile.options().deletion_method == Some(DeletionMethod::PermanentRemoval)
            && !authorizations.allow_unattended_permanent_removal()
        {
            return Err(UiValidationError::PermanentRemovalAuthorizationRequired);
        }
        let persisted = match self.form.id {
            Some(id) => self
                .store
                .update_profile_with_authorizations_if_revision(
                    id,
                    &profile,
                    authorizations,
                    self.form.profile_revision.ok_or_else(|| {
                        UiValidationError::Core(
                            "the selected profile has no revision; reload it before saving"
                                .to_owned(),
                        )
                    })?,
                )
                .map_err(map_storage_error)?,
            None => self
                .store
                .create_profile_with_authorizations(&profile, authorizations)
                .map_err(map_storage_error)?,
        };
        let id = persisted.id();
        let persisted = if let Some(schedule) = schedule {
            self.store
                .update_schedule(id, Some(schedule), self.settings.mode())
                .map_err(map_storage_error)?
        } else {
            persisted
        };
        self.form = ProfileForm::from_persisted(&persisted);
        self.review = None;
        self.profiles = self
            .store
            .list_profiles()
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        self.status = "Profile saved. Changes apply to future runs; an active run keeps its Profile Snapshot.".to_owned();
        Ok(id)
    }

    fn validate_clone(
        &self,
        profile: &SyncProfile,
    ) -> Result<AuthorizationSnapshot, UiValidationError> {
        let Some(_source_id) = self.form.clone_source else {
            return Ok(self.form.profile_authorizations);
        };
        let Some((source_a, source_b)) = &self.form.clone_source_endpoints else {
            return Err(UiValidationError::Core(
                "clone source endpoints are unavailable; start the clone again".to_owned(),
            ));
        };
        if profile.peer_a().same_endpoint(source_a) && profile.peer_b().same_endpoint(source_b) {
            return Err(UiValidationError::CloneEndpointsUnchanged);
        }
        let source_authorizations = self.form.clone_source_authorizations;
        let has_unattended_authorization = source_authorizations.allow_unattended_destructive()
            || source_authorizations.allow_unattended_permanent_removal();
        if has_unattended_authorization && !self.form.clone_authorization_confirmed {
            return Err(UiValidationError::CloneAuthorizationConfirmationRequired);
        }
        if self.form.clone_authorization_choice
            == CloneAuthorizationChoice::CopyUnattendedDestructive
            && self.settings.mode() != ApplicationMode::Advanced
        {
            return Err(UiValidationError::CloneAuthorizationConfirmationRequired);
        }
        let copy_destructive = self.form.clone_authorization_choice
            == CloneAuthorizationChoice::CopyUnattendedDestructive;
        Ok(AuthorizationSnapshot::new(
            copy_destructive && source_authorizations.allow_unattended_destructive(),
            self.form
                .profile_authorizations
                .allow_unattended_permanent_removal(),
        ))
    }

    fn next_clone_name(&self, source_name: &str) -> String {
        let base = format!("{source_name} copy");
        if !self
            .profiles
            .iter()
            .any(|profile| profile.profile().name() == base)
        {
            return base;
        }
        for number in 2..=u32::MAX {
            let candidate = format!("{base} {number}");
            if !self
                .profiles
                .iter()
                .any(|profile| profile.profile().name() == candidate)
            {
                return candidate;
            }
        }
        base
    }

    fn validated_profile(&self) -> Result<SyncProfile, UiValidationError> {
        let profile = self.form.build()?;
        syncplus_core::ProcessSpecification::from_profile(&profile)
            .map_err(|error| UiValidationError::Core(error.to_string()))?;
        for peer in [profile.peer_a(), profile.peer_b()] {
            if let Some(ssh) = peer.ssh_peer()
                && let SshAuthentication::SavedPassword(reference) = ssh.authentication()
            {
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
        Ok(profile)
    }

    fn analyze_profile_snapshot(profile: SyncProfile) -> ProfileAnalysisResult {
        let precheck = Self::fresh_local_precheck(&profile);
        let analysis = match &precheck {
            Ok(_) => Some(FreshAnalysis::analyze(&profile).map_err(|error| error.to_string())),
            Err(_) => None,
        };
        ProfileAnalysisResult {
            profile,
            precheck,
            analysis,
        }
    }

    fn apply_analysis_result(
        &mut self,
        result: ProfileAnalysisResult,
    ) -> Result<(), UiValidationError> {
        let ProfileAnalysisResult {
            profile,
            precheck,
            analysis,
        } = result;
        let precheck = match precheck {
            Ok(precheck) => precheck,
            Err(message) => {
                self.store_review_failure(profile, None, message.clone());
                self.status = format!("Fresh precheck could not complete: {message}");
                return Err(UiValidationError::Core(message));
            }
        };

        if !precheck.can_execute() {
            let analysis = analysis.and_then(Result::ok);
            let conflicts = analysis.as_ref().and_then(|analysis| {
                (profile.mode() == SyncMode::Mirror)
                    .then(|| ConflictReviewState::from_analysis(analysis))
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

        let analysis = match analysis {
            Some(Ok(analysis)) => analysis,
            Some(Err(message)) => {
                self.store_review_failure(profile, Some(precheck), message.clone());
                self.status = format!("Fresh Analysis could not complete: {message}");
                return Err(UiValidationError::Analysis(message));
            }
            None => {
                let message = "Fresh Analysis did not return a result.".to_owned();
                self.store_review_failure(profile, Some(precheck), message.clone());
                self.status = message.clone();
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
        self.status = "Fresh Analysis ready. Review the plan and consequences before confirmation."
            .to_owned();
        Ok(())
    }

    fn start_analysis(&mut self, context: &egui::Context) -> Result<(), UiValidationError> {
        if self.active_analysis.is_some() {
            return Err(UiValidationError::Core(
                "Fresh Analysis is already running.".to_owned(),
            ));
        }
        let profile = self.validated_profile()?;
        let profile_name = profile.name().to_owned();
        let (sender, receiver) = mpsc::channel();
        let repaint_context = context.clone();
        thread::Builder::new()
            .name("syncplus-fresh-analysis".to_owned())
            .spawn(move || {
                let result = SyncPlusApp::analyze_profile_snapshot(profile);
                let _ = sender.send(AnalysisCompletion { result });
                repaint_context.request_repaint();
            })
            .map_err(|error| {
                UiValidationError::Core(format!("could not start Fresh Analysis: {error}"))
            })?;
        self.clear_review();
        self.active_analysis = Some(ActiveAnalysis { receiver });
        self.status =
            format!("Fresh Analysis is running for {profile_name}. No files are being changed.");
        Ok(())
    }

    fn poll_analysis(&mut self) {
        let completion = {
            let Some(active) = self.active_analysis.as_ref() else {
                return;
            };
            match active.receiver.try_recv() {
                Ok(completion) => completion,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.active_analysis = None;
                    self.status = "Fresh Analysis stopped before returning a result. Run it again."
                        .to_owned();
                    return;
                }
            }
        };
        self.active_analysis = None;

        let current_profile = self.form.build().ok();
        if current_profile.as_ref() != Some(&completion.result.profile) {
            self.status = "Fresh Analysis finished for an older profile state; run it again to review the current fields.".to_owned();
            return;
        }
        let _ = self.apply_analysis_result(completion.result);
    }

    pub fn analyze_profile(&mut self) -> Result<(), UiValidationError> {
        let profile = self.validated_profile()?;
        let result = Self::analyze_profile_snapshot(profile);
        self.apply_analysis_result(result)
    }

    pub fn conflict_entries(&self) -> Option<&[ConflictEntry]> {
        self.review
            .as_ref()
            .and_then(|review| review.conflicts.as_ref())
            .map(|conflicts| conflicts.review.entries())
    }

    pub fn conflict_resolution(
        &self,
        relative_path: impl Into<PathBuf>,
    ) -> Option<ConflictResolution> {
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

    pub fn conflict_entry_resolution(&self, key: &ConflictEntryKey) -> Option<ConflictResolution> {
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
            let entry = entries.next().ok_or_else(|| {
                UiValidationError::Resolution(format!(
                    "no reviewed conflict exists for {}",
                    relative_path.display()
                ))
            })?;
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
            self.status =
                "Fresh precheck found blockers; Resolution Run remains unavailable.".to_owned();
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
                    "the profile changed; run Fresh Analysis again before reviewing conflicts"
                        .to_owned(),
                ));
            }
            if !conflicts.has_all_decisions() {
                return Err(UiValidationError::UnresolvedItems);
            }
            let decisions = conflicts
                .review
                .entries()
                .iter()
                .map(|entry| ConflictDecision::for_entry(entry, conflicts.decisions[&entry.key()]))
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
            if let Some(review) = self.review.as_mut()
                && let Some(conflicts) = review.conflicts.as_mut()
            {
                conflicts.confirmed = false;
                conflicts.error = Some(message.clone());
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
            self.status =
                "Fresh precheck found blockers; Resolution Run confirmation remains unavailable."
                    .to_owned();
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
                if let Some(review) = self.review.as_mut()
                    && let Some(conflicts) = review.conflicts.as_mut()
                {
                    conflicts.confirmed = false;
                    conflicts.error = Some(error.to_string());
                }
                UiValidationError::Resolution(error.to_string())
            })?;
        if let Some(review) = self.review.as_mut()
            && let Some(conflicts) = review.conflicts.as_mut()
        {
            conflicts.confirmed = true;
            conflicts.error = None;
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
            self.status =
                "Fresh precheck found blockers; execution remains unavailable.".to_owned();
            return Err(UiValidationError::PrecheckBlocked);
        }

        let unresolved = self
            .review
            .as_ref()
            .and_then(|review| review.analysis.as_ref())
            .is_some_and(analysis_has_unresolved_items);
        if unresolved {
            self.status =
                "Unresolved or unsupported items remain; execution is unavailable.".to_owned();
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
            return Err(format_ssh_precheck_boundary_diagnostic(profile));
        }
        RunPrecheck::check(profile, &LocalPrecheckProbe::default())
            .map_err(|error| format_precheck_error(profile, &error))
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

    fn wizard_step_validation(&self, step: ProfileWizardStep) -> Result<(), UiValidationError> {
        match step {
            ProfileWizardStep::SyncMethod => {
                if self.form.name.trim().is_empty() {
                    return Err(UiValidationError::EmptyProfileName);
                }
            }
            ProfileWizardStep::SourceEndpoint => {
                self.form.peer_a.build("Source")?;
            }
            ProfileWizardStep::DestinationEndpoint => {
                self.form.peer_b.build("Destination")?;
            }
            ProfileWizardStep::ReviewAndSave => {
                let profile = self.form.build()?;
                let authorizations = self.validate_clone(&profile)?;
                if self.settings.mode() == ApplicationMode::Advanced && self.form.schedule_enabled {
                    self.form.build_schedule()?;
                }
                if profile.options().deletion_method == Some(DeletionMethod::PermanentRemoval)
                    && self.settings.mode() != ApplicationMode::Advanced
                {
                    return Err(UiValidationError::PermanentRemovalRequiresAdvanced);
                }
                if profile.options().deletion_method == Some(DeletionMethod::PermanentRemoval)
                    && !authorizations.allow_unattended_permanent_removal()
                {
                    return Err(UiValidationError::PermanentRemovalAuthorizationRequired);
                }
            }
        }
        Ok(())
    }

    fn advance_wizard_step(&mut self, step: ProfileWizardStep) -> Result<(), UiValidationError> {
        self.wizard_step_validation(step)?;
        if let Some(next) = step.next() {
            self.wizard_step = Some(next);
            self.clear_review();
        }
        Ok(())
    }

    fn retreat_wizard_step(&mut self, step: ProfileWizardStep) {
        if let Some(previous) = step.previous() {
            self.wizard_step = Some(previous);
            self.clear_review();
        }
    }

    fn select_profile(&mut self, id: SyncProfileId) {
        if let Some(profile) = self.profiles.iter().find(|profile| profile.id() == id) {
            self.form = ProfileForm::from_persisted(profile);
            self.review = None;
            let name = profile.profile().name().to_owned();
            self.show_sync_workspace();
            self.status = format!("Editing {name}. Changes apply to future runs.");
        }
    }

    fn apply_theme(&self, context: &egui::Context) {
        let preference = match self.settings.theme() {
            ThemePreference::System => egui::ThemePreference::System,
            ThemePreference::Light => egui::ThemePreference::Light,
            ThemePreference::Dark => egui::ThemePreference::Dark,
        };
        context.set_theme(preference);
        context.all_styles_mut(|style| {
            match self.settings.theme() {
                ThemePreference::Light => style.visuals.dark_mode = false,
                ThemePreference::Dark => style.visuals.dark_mode = true,
                ThemePreference::System => {}
            }
            BrandTheme::for_dark_mode(style.visuals.dark_mode).apply_to_style(style);
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(14.0, 8.0);
            style.spacing.interact_size = egui::vec2(44.0, 36.0);
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
            style
                .text_styles
                .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
            style
                .text_styles
                .insert(egui::TextStyle::Heading, egui::FontId::proportional(20.0));
        });
    }

    fn draw_sidebar(&mut self, ui: &mut egui::Ui) {
        let palette = ui_palette(ui);
        let pending = self.recovery_review_pending();
        let review_pending = self.report_review_pending();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            Self::draw_brand_mark_sized(ui, 34.0);
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("SyncPlus").strong().size(17.0));
                ui.label(
                    egui::RichText::new("SAFETY-FIRST FILE SYNC")
                        .small()
                        .color(palette.muted),
                );
            });
        });
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(14.0);
        let mut opened = None;
        let mut open_recovery = false;
        for item in chrome::sidebar_items(self.chrome_surface()) {
            let icon = match item.surface {
                ChromeSurface::Overview => SidebarIcon::Overview,
                ChromeSurface::Profiles => SidebarIcon::Profiles,
                ChromeSurface::SyncWorkspace => SidebarIcon::SyncWorkspace,
                ChromeSurface::Reports => SidebarIcon::Reports,
                ChromeSurface::Settings => SidebarIcon::Settings,
                ChromeSurface::Help => SidebarIcon::Help,
            };
            let icon_color = match item.accent {
                ChromeAccent::Copper => palette.copper,
                ChromeAccent::Muted => palette.muted,
            };
            let label = if item.surface == ChromeSurface::Reports {
                match chrome::reports_badge(review_pending) {
                    Some(badge) => format!("{} · {badge}", item.label),
                    None => item.label.to_owned(),
                }
            } else {
                item.label.to_owned()
            };
            if sidebar_nav_button(ui, &label, item.selected, icon, icon_color).clicked() {
                opened = Some(item.surface);
            }
        }
        if let Some(notice) = chrome::recovery_review_notice(pending) {
            if recovery_review_notice_button(ui, notice).clicked() {
                open_recovery = true;
            }
        }
        if let Some(surface) = opened {
            match surface {
                ChromeSurface::Overview => self.show_welcome(),
                ChromeSurface::Profiles => self.show_profiles(),
                ChromeSurface::SyncWorkspace => self.open_sync_workspace(),
                ChromeSurface::Reports => self.show_reports(),
                ChromeSurface::Settings => self.show_settings(),
                ChromeSurface::Help => self.show_help(self.help_topic),
            }
        } else if open_recovery {
            self.open_recovery_review();
        }
    }

    fn draw_profiles_page(&mut self, ui: &mut egui::Ui) {
        let mut create_profile = false;
        let mut open_profile = None;
        let palette = ui_palette(ui);
        let profile_entries = self
            .profiles
            .iter()
            .map(|profile| {
                let persisted = profile.profile();
                let source = EndpointForm::from_peer(persisted.peer_a());
                let destination = EndpointForm::from_peer(persisted.peer_b());
                (
                    profile.id(),
                    persisted.name().to_owned(),
                    sync_mode_label(persisted.mode()),
                    endpoint_summary(&source),
                    endpoint_summary(&destination),
                )
            })
            .collect::<Vec<_>>();

        egui::ScrollArea::vertical()
            .id_salt("profiles-content")
            .show(ui, |ui| {
                let available_width = ui.available_width();
                let content_width = available_width.min(1040.0);
                ui.horizontal(|ui| {
                    ui.add_space(((available_width - content_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(content_width);
                        ui.add_space(28.0);
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                section_intro(
                                    ui,
                                    "Workspace",
                                    "Profiles",
                                    "Choose a saved Sync Profile to continue where you left off.",
                                );
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Min),
                                |ui| {
                                    if primary_button(ui, "New Sync Profile").clicked() {
                                        create_profile = true;
                                    }
                                },
                            );
                        });
                        ui.add_space(20.0);

                        if profile_entries.is_empty() {
                            card_frame(ui).show(ui, |ui| {
                                ui.vertical_centered(|ui| {
                                    Self::draw_brand_mark_sized(ui, 54.0);
                                    ui.add_space(10.0);
                                    ui.heading("No Sync Profiles yet");
                                    ui.label(
                                        egui::RichText::new(
                                            "Create a named profile to define its sync method, source, destination, and safety settings.",
                                        )
                                        .color(palette.muted),
                                    );
                                    ui.add_space(14.0);
                                    if primary_button(ui, "Create your first profile").clicked() {
                                        create_profile = true;
                                    }
                                });
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{} saved {}",
                                        profile_entries.len(),
                                        if profile_entries.len() == 1 {
                                            "profile"
                                        } else {
                                            "profiles"
                                        }
                                    ))
                                    .small()
                                    .strong()
                                    .color(palette.copper),
                                );
                                ui.label(
                                    egui::RichText::new("Select one to open its Sync workspace.")
                                        .small()
                                        .color(palette.muted),
                                );
                            });
                            ui.add_space(8.0);
                            for (id, name, mode, source, destination) in profile_entries {
                                let selected = self.form.id == Some(id);
                                card_frame(ui).show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.horizontal(|ui| {
                                                status_dot(
                                                    ui,
                                                    if selected {
                                                        palette.copper
                                                    } else {
                                                        palette.steel
                                                    },
                                                );
                                                ui.label(
                                                    egui::RichText::new(&name)
                                                        .size(17.0)
                                                        .strong(),
                                                );
                                                if selected {
                                                    status_badge(ui, "Active", true);
                                                }
                                            });
                                            ui.label(
                                                egui::RichText::new(mode)
                                                    .small()
                                                    .color(palette.muted),
                                            );
                                            ui.add_space(8.0);
                                            ui.columns(2, |columns| {
                                                columns[0].vertical(|ui| {
                                                    ui.label(
                                                        egui::RichText::new("SOURCE")
                                                            .small()
                                                            .strong()
                                                            .color(palette.copper),
                                                    );
                                                    ui.label(egui::RichText::new(source).monospace());
                                                });
                                                columns[1].vertical(|ui| {
                                                    ui.label(
                                                        egui::RichText::new("DESTINATION")
                                                            .small()
                                                            .strong()
                                                            .color(palette.steel),
                                                    );
                                                    ui.label(
                                                        egui::RichText::new(destination).monospace(),
                                                    );
                                                });
                                            });
                                        });
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if secondary_button(ui, "Open workspace").clicked() {
                                                    open_profile = Some(id);
                                                }
                                            },
                                        );
                                    });
                                });
                            }
                        }

                        ui.add_space(16.0);
                        egui::Frame::new()
                            .fill(palette.field)
                            .stroke(egui::Stroke::new(1.0, palette.border_subtle))
                            .corner_radius(egui::CornerRadius::same(12))
                            .inner_margin(egui::Margin::symmetric(16, 13))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    status_dot(ui, palette.copper);
                                    ui.label(egui::RichText::new("Safe by default").strong());
                                    ui.label(
                                        egui::RichText::new(
                                            "Selecting a profile only opens its configuration; every run still requires Fresh Analysis, precheck, and explicit confirmation.",
                                        )
                                        .color(palette.muted),
                                    );
                                });
                            });
                        ui.add_space(20.0);
                    });
                });
            });

        if create_profile {
            self.start_new_profile();
        } else if let Some(id) = open_profile {
            self.select_profile(id);
        }
    }

    fn draw_settings_page(&mut self, ui: &mut egui::Ui) {
        let mut mode_change = None;
        let mut theme_change = None;
        let mut tray_change = None;
        let palette = ui_palette(ui);

        egui::ScrollArea::vertical()
            .id_salt("settings-content")
            .show(ui, |ui| {
                let available_width = ui.available_width();
                let content_width = available_width.min(900.0);
                ui.horizontal(|ui| {
                    ui.add_space(((available_width - content_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(content_width);
                        ui.add_space(28.0);
                        section_intro(
                            ui,
                            "Preferences",
                            "Settings",
                            "Control how SyncPlus presents the workflow. Safety gates remain enforced in every mode.",
                        );
                        ui.add_space(20.0);

                        card_frame(ui).show(ui, |ui| {
                            ui.heading("Workflow mode");
                            ui.label(
                                egui::RichText::new(
                                    "Simple Mode keeps the safe path visible. Advanced Mode reveals additional reviewed controls; it never bypasses prechecks or confirmation.",
                                )
                                .color(palette.muted),
                            );
                            ui.add_space(12.0);
                            ui.columns(2, |columns| {
                                for (column, mode, title, description) in [
                                    (
                                        0,
                                        ApplicationMode::Simple,
                                        "Simple",
                                        "Recommended for ordinary, non-destructive syncs.",
                                    ),
                                    (
                                        1,
                                        ApplicationMode::Advanced,
                                        "Advanced",
                                        "Shows reviewed options such as scheduling and recovery choices.",
                                    ),
                                ] {
                                    let selected = self.settings.mode() == mode;
                                    let width = columns[column].available_width();
                                    columns[column].vertical(|ui| {
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    egui::RichText::new(title)
                                                        .strong()
                                                        .color(if selected {
                                                            palette.text
                                                        } else {
                                                            palette.muted
                                                        }),
                                                )
                                                .fill(if selected {
                                                    palette.copper_soft
                                                } else {
                                                    palette.elevated
                                                })
                                                .stroke(egui::Stroke::new(
                                                    1.0,
                                                    if selected {
                                                        palette.copper
                                                    } else {
                                                        palette.border_subtle
                                                    },
                                                ))
                                                .corner_radius(egui::CornerRadius::same(9))
                                                .min_size(egui::vec2(width, 44.0)),
                                            )
                                            .clicked()
                                        {
                                            mode_change = Some(mode);
                                        }
                                        ui.label(
                                            egui::RichText::new(description)
                                                .small()
                                                .color(palette.muted),
                                        );
                                    });
                                }
                            });
                        });

                        ui.add_space(12.0);
                        card_frame(ui).show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.heading("Window behavior");
                            ui.label(
                                egui::RichText::new(
                                    "Choose what the window close control does. The sidebar Exit button always quits SyncPlus.",
                                )
                                .color(palette.muted),
                            );
                            ui.add_space(10.0);
                            let mut hide_to_tray = self.settings.hide_to_tray_on_window_close();
                            if ui
                                .checkbox(
                                    &mut hide_to_tray,
                                    "Hide to system tray when the window is closed",
                                )
                                .changed()
                            {
                                tray_change = Some(hide_to_tray);
                            }
                            ui.label(
                                egui::RichText::new(if hide_to_tray {
                                    "Window close hides SyncPlus and leaves scheduled work running in the background."
                                } else {
                                    "Window close exits SyncPlus when no run is active; an active run still requires a quit decision."
                                })
                                .small()
                                .color(palette.muted),
                            );
                        });

                        ui.add_space(12.0);
                        card_frame(ui).show(ui, |ui| {
                            ui.heading("Appearance");
                            ui.label(
                                egui::RichText::new(
                                    "Choose the canvas treatment that best suits your environment. Changes apply immediately and are remembered.",
                                )
                                .color(palette.muted),
                            );
                            ui.add_space(12.0);
                            ui.columns(3, |columns| {
                                for (column, theme, title, description) in [
                                    (0, ThemePreference::System, "System", "Follow the desktop Dark Appearance or Light Appearance."),
                                    (1, ThemePreference::Light, "Light", "Use the warm paper Light Appearance."),
                                    (2, ThemePreference::Dark, "Dark", "Use the warm ink Dark Appearance."),
                                ] {
                                    let selected = self.settings.theme() == theme;
                                    let width = columns[column].available_width();
                                    columns[column].vertical(|ui| {
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    egui::RichText::new(title)
                                                        .strong()
                                                        .color(if selected {
                                                            palette.text
                                                        } else {
                                                            palette.muted
                                                        }),
                                                )
                                                .fill(if selected {
                                                    palette.copper_soft
                                                } else {
                                                    palette.elevated
                                                })
                                                .stroke(egui::Stroke::new(
                                                    1.0,
                                                    if selected {
                                                        palette.copper
                                                    } else {
                                                        palette.border_subtle
                                                    },
                                                ))
                                                .corner_radius(egui::CornerRadius::same(9))
                                                .min_size(egui::vec2(width, 44.0)),
                                            )
                                            .clicked()
                                        {
                                            theme_change = Some(theme);
                                        }
                                        ui.label(
                                            egui::RichText::new(description)
                                                .small()
                                                .color(palette.muted),
                                        );
                                    });
                                }
                            });
                        });

                        ui.add_space(12.0);
                        card_frame(ui).show(ui, |ui| {
                            ui.heading("Safety guarantees");
                            ui.label(
                                egui::RichText::new(
                                    "These protections are deliberately enforced rather than optional toggles. They keep the product predictable when data is unavailable, changed, or ambiguous.",
                                )
                                .color(palette.muted),
                            );
                            ui.add_space(12.0);
                            for (title, description, color) in [
                                (
                                    "Fresh Analysis before every run",
                                    "The current filesystem state is reviewed before a plan can be confirmed.",
                                    palette.copper,
                                ),
                                (
                                    "Explicit confirmation before mutation",
                                    "No copy, overwrite, or removal begins from navigation or a stale plan.",
                                    palette.steel,
                                ),
                                (
                                    "Preserve data when verification is uncertain",
                                    "Failures and unexplained changes stay open for Recovery Review.",
                                    palette.warning,
                                ),
                            ] {
                                inset_frame(ui).show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        status_dot(ui, color);
                                        ui.vertical(|ui| {
                                            ui.label(egui::RichText::new(title).strong());
                                            ui.label(
                                                egui::RichText::new(description)
                                                    .small()
                                                    .color(palette.muted),
                                            );
                                        });
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| status_badge(ui, "Enforced", true),
                                        );
                                    });
                                });
                            }
                        });
                        ui.add_space(20.0);
                    });
                });
            });

        if let Some(mode) = mode_change {
            self.set_mode(mode);
        }
        if let Some(theme) = theme_change {
            self.set_theme(theme);
        }
        if let Some(enabled) = tray_change {
            self.set_hide_to_tray_on_window_close(enabled);
        }
    }

    fn draw_brand_mark_sized(ui: &mut egui::Ui, size: f32) {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        let painter = ui.painter();
        let palette = ui_palette(ui);
        let radius = (size * 0.22).round().clamp(6.0, 20.0) as u8;
        painter.rect_filled(rect, egui::CornerRadius::same(radius), palette.canvas);
        let margin = size * 0.2;
        let left = rect.left() + margin;
        let right = rect.right() - margin;
        let upper = rect.center().y - size * 0.13;
        let lower = rect.center().y + size * 0.13;
        let stroke = (size * 0.055).max(2.0);
        painter.line_segment(
            [
                egui::pos2(left, upper),
                egui::pos2(right - size * 0.045, upper),
            ],
            egui::Stroke::new(stroke, palette.copper),
        );
        painter.line_segment(
            [
                egui::pos2(right - size * 0.045, upper),
                egui::pos2(right - size * 0.155, upper - size * 0.09),
            ],
            egui::Stroke::new(stroke, palette.copper),
        );
        painter.line_segment(
            [
                egui::pos2(right - size * 0.045, upper),
                egui::pos2(right - size * 0.155, upper + size * 0.09),
            ],
            egui::Stroke::new(stroke, palette.copper),
        );
        painter.line_segment(
            [
                egui::pos2(right, lower),
                egui::pos2(left + size * 0.045, lower),
            ],
            egui::Stroke::new(stroke, palette.steel),
        );
        painter.line_segment(
            [
                egui::pos2(left + size * 0.045, lower),
                egui::pos2(left + size * 0.155, lower - size * 0.09),
            ],
            egui::Stroke::new(stroke, palette.steel),
        );
        painter.line_segment(
            [
                egui::pos2(left + size * 0.045, lower),
                egui::pos2(left + size * 0.155, lower + size * 0.09),
            ],
            egui::Stroke::new(stroke, palette.steel),
        );
    }

    fn draw_empty_welcome(&mut self, ui: &mut egui::Ui) {
        let mut open_wizard = false;
        let overview = chrome::empty_overview();
        egui::ScrollArea::vertical()
            .id_salt("empty-welcome-content")
            .show(ui, |ui| {
                let available_width = ui.available_width();
                let content_width = available_width.min(720.0);
                ui.horizontal(|ui| {
                    ui.add_space(((available_width - content_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(content_width);
                        ui.add_space(28.0);
                        card_frame(ui).show(ui, |ui| {
                            section_intro(ui, overview.eyebrow, &overview.title, &overview.body);
                            ui.add_space(8.0);
                            active_mode_badge(ui, self.settings.mode());
                            ui.add_space(16.0);
                            if primary_button(ui, overview.primary_action.label()).clicked() {
                                open_wizard = true;
                            }
                        });
                        ui.add_space(20.0);
                    });
                });
            });
        if open_wizard {
            self.start_new_profile();
        }
    }

    fn draw_welcome(&mut self, ui: &mut egui::Ui) {
        let mut open_sync = false;
        let mut request_sync = false;
        let mut open_recovery = false;
        if self.form.id.is_none() {
            self.draw_empty_welcome(ui);
            return;
        }
        let pending = self.recovery_review_pending_for_active_profile();
        let overview = chrome::populated_overview(
            &self.form.name,
            sync_mode_label(self.form.mode),
            self.last_run_status_for_active_profile(),
            pending,
        );
        let source = endpoint_summary(&self.form.peer_a);
        let destination = endpoint_summary(&self.form.peer_b);
        egui::ScrollArea::vertical()
            .id_salt("welcome-content")
            .show(ui, |ui| {
                ui.add_space(28.0);
                card_frame(ui).show(ui, |ui| {
                    section_intro(ui, overview.eyebrow, &overview.title, &overview.body);
                    ui.add_space(8.0);
                    active_mode_badge(ui, self.settings.mode());
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new(&source).monospace());
                    ui.label(egui::RichText::new(&destination).monospace());
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new(&overview.last_run).color(ui_palette(ui).text));
                    ui.label(
                        egui::RichText::new(format!(
                            "Next safe action · {}",
                            overview.next_safe_action
                        ))
                        .color(ui_palette(ui).muted),
                    );
                    if let Some(notice) = overview.recovery_notice {
                        ui.add_space(10.0);
                        let palette = ui_palette(ui);
                        egui::Frame::new()
                            .fill(palette.danger_soft)
                            .stroke(egui::Stroke::new(1.0, palette.danger))
                            .corner_radius(egui::CornerRadius::same(8))
                            .inner_margin(egui::Margin::symmetric(12, 8))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(notice)
                                        .strong()
                                        .color(palette.on_danger_soft),
                                );
                            });
                    }
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if primary_button(ui, overview.primary_action.label()).clicked() {
                            match overview.primary_action {
                                OverviewAction::OpenRecoveryReview => open_recovery = true,
                                OverviewAction::Synchronise | OverviewAction::CreateProfile => {
                                    request_sync = true
                                }
                            }
                        }
                        if secondary_button(ui, "Edit profile").clicked() {
                            open_sync = true;
                        }
                    });
                });
                ui.add_space(16.0);
            });
        if open_sync {
            self.show_sync_workspace();
        } else if open_recovery {
            self.open_recovery_review();
        } else if request_sync {
            self.show_sync_workspace();
            self.request_synchronise_async(ui.ctx());
        }
    }

    fn draw_wizard_stepper(&self, ui: &mut egui::Ui, current: ProfileWizardStep) {
        let palette = ui_palette(ui);
        ui.columns(4, |columns| {
            for (index, step) in ProfileWizardStep::ALL.into_iter().enumerate() {
                let completed = step.number() < current.number();
                let selected = step == current;
                let color = if selected || completed {
                    palette.copper
                } else {
                    palette.muted
                };
                egui::Frame::new()
                    .fill(if selected || completed {
                        palette.copper_soft
                    } else {
                        palette.elevated
                    })
                    .stroke(egui::Stroke::new(
                        1.0,
                        if selected || completed {
                            palette.copper
                        } else {
                            palette.border
                        },
                    ))
                    .corner_radius(egui::CornerRadius::same(9))
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(&mut columns[index], |ui| {
                        ui.horizontal(|ui| {
                            egui::Frame::new()
                                .fill(if selected || completed {
                                    palette.copper
                                } else {
                                    palette.field
                                })
                                .stroke(egui::Stroke::new(1.0, color))
                                .corner_radius(egui::CornerRadius::same(7))
                                .inner_margin(egui::Margin::symmetric(7, 4))
                                .show(ui, |ui| {
                                    ui.label(
                                        egui::RichText::new(step.number().to_string())
                                            .strong()
                                            .color(if selected || completed {
                                                palette.on_copper
                                            } else {
                                                palette.text
                                            }),
                                    );
                                });
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(step.title()).strong().color(color));
                                ui.label(
                                    egui::RichText::new(if selected {
                                        "Current step"
                                    } else if completed {
                                        "Complete"
                                    } else {
                                        "Required"
                                    })
                                    .small()
                                    .color(palette.muted),
                                );
                            });
                        });
                    });
            }
        });
    }

    fn draw_wizard(&mut self, ui: &mut egui::Ui) {
        let step = self.wizard_step.unwrap_or(ProfileWizardStep::SyncMethod);
        let step_ready = self.wizard_step_validation(step).is_ok();
        let form_before_draw = self.form.clone();
        let palette = ui_palette(ui);
        let mut cancel = false;
        let mut previous = false;
        let mut next = false;
        let mut save = false;
        let mut profile_saved = false;
        egui::ScrollArea::vertical()
            .id_salt("profile-wizard")
            .show(ui, |ui| {
                let available_width = ui.available_width();
                let content_width = available_width.min(1040.0);
                ui.horizontal(|ui| {
                    ui.add_space(((available_width - content_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(content_width);
                        ui.add_space(24.0);
                        card_frame(ui).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    section_intro(
                                        ui,
                                        "New profile",
                                        "Create a Sync Profile",
                                        "Set up the safe path once, then fine-tune it from the Sync workspace.",
                                    );
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                    if secondary_button(ui, "Cancel").clicked() {
                                        cancel = true;
                                    }
                                });
                            });
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new("Saving only stores the profile; it never starts a Sync Run.").color(palette.muted));
                        });
                        egui::Frame::new()
                            .fill(palette.surface)
                            .stroke(egui::Stroke::new(1.0, palette.border_subtle))
                            .corner_radius(egui::CornerRadius::same(12))
                            .inner_margin(egui::Margin::symmetric(12, 10))
                            .outer_margin(egui::Margin::symmetric(0, 6))
                            .show(ui, |ui| self.draw_wizard_stepper(ui, step));
                        card_frame(ui).show(ui, |ui| match step {
                            ProfileWizardStep::SyncMethod => {
                                section_intro(
                                    ui,
                                    "Step 1 · Sync method",
                                    "Choose the sync type",
                                    "Start with the safe default, then name the profile so its future runs are easy to identify.",
                                );
                                ui.add_space(14.0);
                                ui.label(egui::RichText::new("Profile name").strong());
                                ui.label(egui::RichText::new("A short name such as “Home archive” or “Work files”.").small().color(palette.muted));
                                ui.add_space(6.0);
                                ui.add_sized(
                                    egui::vec2(ui.available_width(), 42.0),
                                    egui::TextEdit::singleline(&mut self.form.name),
                                );
                                ui.add_space(18.0);
                                ui.label(egui::RichText::new("Sync method").strong());
                                ui.label(egui::RichText::new("Choose the direction model for this profile.").small().color(palette.muted));
                                ui.add_space(6.0);
                                egui::ComboBox::from_id_salt("wizard-sync-method")
                                    .selected_text(sync_mode_label(self.form.mode))
                                    .width(ui.available_width())
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(
                                            &mut self.form.mode,
                                            SyncMode::OneWay,
                                            "One-Way Sync (recommended)",
                                        );
                                        ui.selectable_value(
                                            &mut self.form.mode,
                                            SyncMode::Mirror,
                                            "Mirror Sync (review required)",
                                        );
                                    });
                                ui.add_space(16.0);
                                ui.label(egui::RichText::new(match self.form.mode {
                                    SyncMode::OneWay => "One-Way Sync copies from the authoritative source endpoint to the other endpoint.",
                                    SyncMode::Mirror => "Mirror Sync keeps both endpoints populated and requires explicit conflict review.",
                                }).color(palette.muted));
                                if self.form.mode == SyncMode::OneWay {
                                    ui.add_space(8.0);
                                    egui::Frame::new()
                                        .fill(palette.field)
                                        .stroke(egui::Stroke::new(1.0, palette.border_subtle))
                                        .corner_radius(egui::CornerRadius::same(10))
                                        .inner_margin(egui::Margin::symmetric(12, 10))
                                        .show(ui, |ui| {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(egui::RichText::new("Authoritative source").strong());
                                                ui.radio_value(&mut self.form.source, OneWaySource::PeerA, "Source endpoint");
                                                ui.radio_value(&mut self.form.source, OneWaySource::PeerB, "Destination endpoint");
                                            });
                                        });
                                }
                            }
                            ProfileWizardStep::SourceEndpoint => {
                                section_intro(
                                    ui,
                                    "Step 2 · Source",
                                    "Select the source folder for this sync",
                                    "Choose the folder whose contents should be copied. The selected path is kept as a validated endpoint, not a shell command.",
                                );
                                ui.add_space(12.0);
                                draw_endpoint(ui, "Source endpoint", &mut self.form.peer_a);
                                inset_frame(ui).show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        status_dot(ui, palette.steel);
                                        ui.label(egui::RichText::new("Next").strong());
                                    });
                                    ui.label(egui::RichText::new("When the source folder is selected, continue to choose the destination folder.").color(palette.muted));
                                });
                            }
                            ProfileWizardStep::DestinationEndpoint => {
                                section_intro(
                                    ui,
                                    "Step 3 · Destination",
                                    "Select the destination folder for this sync",
                                    "Choose where the selected source should be synchronized. SyncPlus verifies the destination before any Safe Delete or overwrite action can proceed.",
                                );
                                ui.add_space(12.0);
                                inset_frame(ui).show(ui, |ui| {
                                    ui.label(egui::RichText::new("Source selected").strong());
                                    ui.label(egui::RichText::new(endpoint_summary(&self.form.peer_a)).monospace().color(palette.muted));
                                });
                                draw_endpoint(ui, "Destination endpoint", &mut self.form.peer_b);
                            }
                            ProfileWizardStep::ReviewAndSave => {
                                section_intro(
                                    ui,
                                    "Step 4 · Review",
                                    "Review your Sync Profile",
                                    "Check the summary, then save. Additional options remain available from the Sync workspace.",
                                );
                                ui.add_space(12.0);
                                ui.columns(2, |columns| {
                                    columns[0].vertical(|ui| {
                                        inset_frame(ui).show(ui, |ui| {
                                            ui.label(egui::RichText::new("Profile summary").strong());
                                            ui.add_space(8.0);
                                            ui.label(format!("Name: {}", if self.form.name.trim().is_empty() { "Not entered" } else { self.form.name.trim() }));
                                            ui.label(format!("Sync type: {}", sync_mode_label(self.form.mode)));
                                            if self.form.mode == SyncMode::OneWay {
                                                ui.label(format!("Authoritative source: {}", match self.form.source {
                                                    OneWaySource::PeerA => "Source endpoint",
                                                    OneWaySource::PeerB => "Destination endpoint",
                                                }));
                                            }
                                            ui.label(format!("Source: {}", endpoint_summary(&self.form.peer_a)));
                                            ui.label(format!("Destination: {}", endpoint_summary(&self.form.peer_b)));
                                        });
                                    });
                                    columns[1].vertical(|ui| {
                                        inset_frame(ui).show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                status_dot(ui, palette.copper);
                                                ui.label(egui::RichText::new("What happens next").strong());
                                            });
                                            ui.add_space(8.0);
                                            ui.label(egui::RichText::new("After saving, the Sync workspace opens with this profile populated. Choose any additional options there, then press Synchronise to begin the required review flow.").color(palette.muted));
                                            ui.add_space(8.0);
                                            ui.label(egui::RichText::new("Synchronise will not change files until Fresh Analysis, Run Precheck, and explicit Execution Confirmation are complete.").color(palette.muted));
                                        });
                                    });
                                });
                            }
                        });
                        if step == ProfileWizardStep::SyncMethod {
                            full_width_inset_frame(ui, |ui| {
                                let one_way = self.form.mode == SyncMode::OneWay;
                                ui.horizontal_wrapped(|ui| {
                                    status_dot(ui, if one_way { palette.copper } else { palette.warning });
                                    ui.label(egui::RichText::new(if one_way {
                                        "Simple default:"
                                    } else {
                                        "Review required:"
                                    }).strong());
                                    ui.label(egui::RichText::new(match self.form.mode {
                                        SyncMode::OneWay => "One-Way Sync copies from one authoritative folder to the other endpoint.",
                                        SyncMode::Mirror => "Mirror Sync keeps both endpoints in view and requires Conflict Review.",
                                    }).color(palette.muted));
                                });
                                ui.add_space(2.0);
                                ui.horizontal_wrapped(|ui| {
                                    status_dot(ui, palette.copper);
                                    ui.label(egui::RichText::new("No changes yet:").strong());
                                    ui.label(egui::RichText::new("SyncPlus will first run Fresh Analysis and a precheck. You confirm the exact reviewed work immediately before mutation.").color(palette.muted));
                                });
                            });
                        }
                        egui::Frame::new()
                            .fill(palette.surface)
                            .stroke(egui::Stroke::new(1.0, palette.border_subtle))
                            .corner_radius(egui::CornerRadius::same(12))
                            .inner_margin(egui::Margin::symmetric(14, 10))
                            .outer_margin(egui::Margin::symmetric(0, 6))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(format!("Step {} of 4", step.number())).color(palette.muted));
                                    if !step_ready {
                                        ui.label(
                                            egui::RichText::new("Complete the required fields to continue.")
                                                .small()
                                                .color(palette.warning),
                                        );
                                    }
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if step.next().is_some() {
                                            let next_label = match step {
                                                ProfileWizardStep::SyncMethod => "Next: choose source folder",
                                                ProfileWizardStep::SourceEndpoint => "Next: choose destination folder",
                                                ProfileWizardStep::DestinationEndpoint => "Next: review and save",
                                                ProfileWizardStep::ReviewAndSave => unreachable!(),
                                            };
                                            if primary_button_enabled(ui, next_label, step_ready).clicked() {
                                                next = true;
                                            }
                                        } else if primary_button_enabled(
                                            ui,
                                            "Save profile & open Sync workspace",
                                            step_ready,
                                        )
                                        .clicked()
                                        {
                                            save = true;
                                        }
                                        if step.previous().is_some() && secondary_button(ui, "Back").clicked() {
                                            previous = true;
                                        }
                                    });
                                });
                            });
                        ui.add_space(20.0);
                    });
                });
            });
        if cancel {
            self.show_welcome();
        } else if next {
            if let Err(error) = self.advance_wizard_step(step) {
                self.status = format_form_validation_diagnostic(&self.form, &error);
            }
        } else if save {
            match self.save_profile() {
                Ok(_) => {
                    profile_saved = true;
                    self.show_sync_workspace();
                    self.status = "Profile saved. Run Fresh Analysis to review the intended work before confirmation.".to_owned();
                }
                Err(error) => {
                    self.status = format_form_validation_diagnostic(&self.form, &error);
                }
            }
        } else if previous {
            self.retreat_wizard_step(step);
        }
        if !profile_saved && self.form != form_before_draw {
            self.clear_review();
            self.status = "Profile changed. Complete the wizard, then run Fresh Analysis before confirmation.".to_owned();
        }
    }

    fn draw_profile_form(&mut self, ui: &mut egui::Ui) {
        let form_before_draw = self.form.clone();
        let mut request_analyze = false;
        let mut request_validate = false;
        let mut request_save = false;
        let mut request_synchronise = false;
        let mut profile_to_select = None;
        let profile_options = self
            .profiles
            .iter()
            .map(|profile| (profile.id(), profile.profile().name().to_owned()))
            .collect::<Vec<_>>();
        let selected_profile_name = self
            .form
            .id
            .and_then(|id| {
                profile_options
                    .iter()
                    .find(|(profile_id, _)| *profile_id == id)
                    .map(|(_, name)| name.as_str())
            })
            .unwrap_or("Unsaved profile draft");
        let review_confirmed = self.review.as_ref().is_some_and(|review| review.confirmed);
        let review_exists = self.review.is_some();
        let review_blocked = self
            .review
            .as_ref()
            .is_some_and(|review| review.error.is_some());
        let analysis_active = self.active_analysis.is_some();
        let synchronise_enabled =
            review_confirmed && self.active_manual_run.is_none() && !analysis_active;
        let (phase_label, phase_description, phase_positive) = if analysis_active {
            (
                "Analysis in progress",
                "Fresh Analysis is hashing the selected scope in the background. The workspace remains available.",
                false,
            )
        } else if self.active_manual_run.is_some() {
            (
                "Sync Run active",
                "The reviewed Sync Run is executing. Progress and durable evidence are shown below.",
                true,
            )
        } else if review_confirmed {
            (
                "Ready to synchronise",
                "Execution Confirmation is recorded for this exact reviewed scope.",
                true,
            )
        } else if review_blocked {
            (
                "Review blocked",
                "Correct the named profile or endpoint problem, then run the dry run again.",
                false,
            )
        } else if review_exists {
            (
                "Review required",
                "The read-only plan is ready. Inspect it, resolve any blockers, and confirm the exact scope.",
                false,
            )
        } else {
            (
                "Ready for dry run",
                "Dry run performs Fresh Analysis and Run Precheck. It does not change files.",
                false,
            )
        };
        let palette = ui_palette(ui);
        card_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    section_intro(
                        ui,
                        "Active Sync Profile",
                        "Sync workspace",
                        "Run a read-only dry run, review the exact plan, then confirm before anything changes.",
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    status_badge(ui, phase_label, phase_positive);
                });
            });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Active profile").strong());
                egui::ComboBox::from_id_salt("workspace-profile-selector")
                    .selected_text(selected_profile_name)
                    .width(280.0)
                    .show_ui(ui, |ui| {
                        for (id, name) in &profile_options {
                            ui.selectable_value(
                                &mut profile_to_select,
                                Some(*id),
                                name,
                            );
                        }
                    });
                ui.label(egui::RichText::new(phase_description).color(palette.muted));
            });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if primary_button_enabled(
                    ui,
                    if review_exists { "Run dry run again" } else { "Dry run · Analyze" },
                    !analysis_active,
                )
                .clicked()
                {
                    request_analyze = true;
                }
                if secondary_button(ui, "Validate profile").clicked() {
                    request_validate = true;
                }
                if secondary_button(ui, "Save profile").clicked() {
                    request_save = true;
                }
                if primary_button_enabled(ui, "Synchronise", synchronise_enabled).clicked() {
                    request_synchronise = true;
                }
            });
            ui.add_space(10.0);
            egui::Frame::new()
                .fill(palette.field)
                .stroke(egui::Stroke::new(1.0, palette.border_subtle))
                .corner_radius(egui::CornerRadius::same(9))
                .inner_margin(egui::Margin::symmetric(12, 9))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        status_dot(ui, palette.steel);
                        ui.label(egui::RichText::new("No arbitrary commands").strong());
                        ui.label(egui::RichText::new("SyncPlus uses validated profile fields and the same reviewed process specification for analysis and execution.").color(palette.muted));
                    });
                });
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                status_dot(
                    ui,
                    if review_blocked {
                        palette.danger
                    } else if review_confirmed {
                        palette.copper
                    } else {
                        palette.warning
                    },
                );
                ui.label(egui::RichText::new("Latest status").strong());
                ui.label(egui::RichText::new(&self.status).color(palette.muted));
            });
            draw_contextual_help_link(
                ui,
                "Profile guidance",
                help_topic_for_surface(HelpSurface::Profile),
                &mut self.help_topic,
            );
        });
        if let Some(source_id) = self.form.clone_source {
            let clone_authorization_choice_before = self.form.clone_authorization_choice;
            card_frame(ui).show(ui, |ui| {
                section_intro(
                    ui,
                    "Clone review",
                    "Clone Profile safeguards",
                    "Review the copied endpoints and authorization choices before saving this separate profile.",
                );
                draw_contextual_help_link(
                    ui,
                    "Clone safeguards",
                    help_topic_for_surface(HelpSurface::Clone),
                    &mut self.help_topic,
                );
                ui.label(format!(
                    "This is an editable copy of Sync Profile {source_id:?}. Both endpoint forms below are pre-filled for review. Change at least one endpoint before saving."
                ));
                ui.label("Saving this clone changes future Sync Runs only; an active run continues using its frozen Profile Snapshot.");
                ui.label("Saved passwords, passphrases, and keyring references were cleared from the clone. Configure authentication intentionally through the approved SSH/keyring controls.");
                let source_authorizations = self.form.clone_source_authorizations;
                if source_authorizations.allow_unattended_destructive()
                    || source_authorizations.allow_unattended_permanent_removal()
                {
                    ui.label("Authorization warning: this clone does not silently inherit unattended destructive authorization.");
                    ui.radio_value(
                        &mut self.form.clone_authorization_choice,
                        CloneAuthorizationChoice::Reset,
                        "Reset unattended destructive authorization (recommended)",
                    );
                    if source_authorizations.allow_unattended_destructive() {
                        let copy_enabled = self.settings.mode() == ApplicationMode::Advanced;
                        ui.add_enabled_ui(copy_enabled, |ui| {
                            ui.radio_value(
                                &mut self.form.clone_authorization_choice,
                                CloneAuthorizationChoice::CopyUnattendedDestructive,
                                "Copy unattended destructive authorization (Advanced only)",
                            );
                        });
                    }
                    if source_authorizations.allow_unattended_permanent_removal() {
                        ui.label("Permanent Removal authorization is never copied by cloning. It requires separate Advanced Mode authorization.");
                    }
                    ui.checkbox(
                        &mut self.form.clone_authorization_confirmed,
                        "I understand and confirm this clone's explicit authorization choice.",
                    );
                }
            });
            if self.form.clone_authorization_choice != clone_authorization_choice_before {
                self.form.clone_authorization_confirmed = false;
                self.form.profile_authorizations = AuthorizationSnapshot::new(
                    self.form.clone_authorization_choice
                        == CloneAuthorizationChoice::CopyUnattendedDestructive
                        && self
                            .form
                            .clone_source_authorizations
                            .allow_unattended_destructive(),
                    self.form
                        .profile_authorizations
                        .allow_unattended_permanent_removal(),
                );
            }
        }
        card_frame(ui).show(ui, |ui| {
            ui.label(egui::RichText::new("PROFILE IDENTITY").small().strong().color(palette.copper));
            ui.heading("Name this Sync Profile");
            ui.label(egui::RichText::new("A clear name makes schedules, Run Reports, and recovery decisions easier to identify.").color(palette.muted));
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Profile name").strong());
            ui.add_sized(
                egui::vec2(ui.available_width(), 38.0),
                egui::TextEdit::singleline(&mut self.form.name)
                    .vertical_align(egui::Align::Center),
            );
        });
        card_frame(ui).show(ui, |ui| {
            ui.label(egui::RichText::new("SYNC POLICY").small().strong().color(palette.steel));
            ui.heading("Choose how files move");
            ui.label(egui::RichText::new("One-Way Sync has an explicit authority. Mirror Sync never assumes a winner and requires Conflict Review.").color(palette.muted));
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Sync method").strong());
            egui::ComboBox::from_id_salt("sync-method")
                .selected_text(sync_mode_label(self.form.mode))
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.form.mode,
                        SyncMode::OneWay,
                        "One-Way Sync (recommended)",
                    );
                    ui.selectable_value(
                        &mut self.form.mode,
                        SyncMode::Mirror,
                        "Mirror Sync (review required)",
                    );
                });
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(10.0);
            ui.label(match self.form.mode {
                SyncMode::OneWay => "One-Way Sync copies from the authoritative source endpoint to the other endpoint.",
                SyncMode::Mirror => "Mirror Sync keeps both endpoints populated and requires explicit conflict review.",
            });
            if self.form.mode == SyncMode::OneWay {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("Authoritative source").strong());
                    ui.radio_value(&mut self.form.source, OneWaySource::PeerA, "Source endpoint");
                    ui.radio_value(&mut self.form.source, OneWaySource::PeerB, "Destination endpoint");
                });
            }
        });
        card_frame(ui).show(ui, |ui| {
            section_intro(
                ui,
                "Connections",
                "Source and destination",
                "Both endpoints remain visible so the direction and scope are always clear.",
            );
            ui.add_space(4.0);
            draw_endpoint(ui, "Source endpoint", &mut self.form.peer_a);
            ui.add_space(12.0);
            draw_endpoint(ui, "Destination endpoint", &mut self.form.peer_b);
        });
        card_frame(ui).show(ui, |ui| {
            ui.collapsing("Exclusion Rules", |ui| {
                ui.label(egui::RichText::new("One pattern per line. Excluded items are neither synchronized nor deleted.").color(ui_palette(ui).muted));
                ui.add(egui::TextEdit::multiline(&mut self.form.exclusions).desired_rows(3));
            });
        });
        if self.settings.mode() == ApplicationMode::Advanced {
            card_frame(ui).show(ui, |ui| {
                ui.collapsing("Advanced safety options", |ui| {
                    let safe_delete_changed = ui
                        .checkbox(&mut self.form.safe_delete, "One-Way Safe-Delete Sync")
                        .changed();
                    if !self.form.safe_delete {
                        self.form.deletion_method = None;
                    } else if safe_delete_changed && self.form.deletion_method.is_none() {
                        self.form.deletion_method = Some(DeletionMethod::Trash);
                    }
                    if self.form.safe_delete {
                        ui.label("Recovery method (Permanent Removal is separately authorized and irreversible):");
                        ui.radio_value(
                            &mut self.form.deletion_method,
                            Some(DeletionMethod::Trash),
                            "Move verified removals to Trash",
                        );
                        ui.radio_value(
                            &mut self.form.deletion_method,
                            Some(DeletionMethod::PermanentRemoval),
                            "Permanent Removal (separate Advanced authorization)",
                        );
                    }
                    ui.checkbox(&mut self.form.destination_cleanup, "Destination Cleanup");
                    ui.separator();
                    ui.label("Unattended authorization (explicit and profile-specific)");
                    let destructive_actions_enabled = self.form.safe_delete || self.form.destination_cleanup;
                    if self.form.clone_source.is_none() && destructive_actions_enabled {
                        let mut allow_destructive = self
                            .form
                            .profile_authorizations
                            .allow_unattended_destructive();
                        ui.checkbox(
                            &mut allow_destructive,
                            "Authorize unattended Safe Delete or Destination Cleanup",
                        );
                        self.form.profile_authorizations = AuthorizationSnapshot::new(
                            allow_destructive,
                            self.form.profile_authorizations.allow_unattended_permanent_removal(),
                        );
                    } else if !destructive_actions_enabled {
                        self.form.profile_authorizations = AuthorizationSnapshot::new(
                            false,
                            self.form.profile_authorizations.allow_unattended_permanent_removal(),
                        );
                        ui.label("Enable Safe Delete or Destination Cleanup before authorizing unattended destructive actions.");
                    } else {
                        ui.label(if self
                            .form
                            .profile_authorizations
                            .allow_unattended_destructive()
                        {
                            "This clone explicitly authorizes unattended destructive actions."
                        } else {
                            "This clone does not authorize unattended destructive actions."
                        });
                    }
                    if self.form.deletion_method == Some(DeletionMethod::PermanentRemoval) {
                        let mut allow_permanent = self
                            .form
                            .profile_authorizations
                            .allow_unattended_permanent_removal();
                        ui.checkbox(
                            &mut allow_permanent,
                            "Authorize unattended Permanent Removal (irreversible; Advanced only)",
                        );
                        self.form.profile_authorizations = AuthorizationSnapshot::new(
                            self.form.profile_authorizations.allow_unattended_destructive(),
                            allow_permanent,
                        );
                        ui.label("Permanent Removal requires this separate authorization before saving.");
                    } else {
                        if self
                            .form
                            .profile_authorizations
                            .allow_unattended_permanent_removal()
                        {
                            self.form.profile_authorizations = AuthorizationSnapshot::new(
                                self.form.profile_authorizations.allow_unattended_destructive(),
                                false,
                            );
                        }
                        ui.label("Unattended Permanent Removal remains disabled unless Permanent Removal is selected.");
                    }
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
                    ui.separator();
                    ui.label("Background Scheduler (Advanced Mode only)");
                    ui.checkbox(
                        &mut self.form.schedule_enabled,
                        "Enable recurring Unattended Run for this Sync Profile",
                    );
                    ui.horizontal(|ui| {
                        ui.label("Every (minutes)");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.form.schedule_interval_minutes)
                                .desired_width(70.0),
                        );
                        ui.label("Timezone");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.form.schedule_timezone)
                                .desired_width(150.0),
                        );
                    });
                    ui.label("Scheduled launches run as this OS user through the same safety workflow; no root service or hidden credential prompt is used.");
                    ui.label("The next run is persisted by the Background Scheduler. Editing or disabling this schedule never changes an active Run's frozen Profile Snapshot.");
                    ui.label("Transport is selected through the typed Local or SSH endpoint fields. Command editing is not available.");
                    ui.label("These options remain subject to Fresh Analysis, verification, and explicit Execution Confirmation.");
                });
            });
        } else {
            full_width_inset_frame(ui, |ui| {
                ui.label(egui::RichText::new("Simple Mode").strong());
                ui.label("Destructive options stay hidden. Switch to Advanced Mode only when you need to review them.");
            });
        }
        card_frame(ui).show(ui, |ui| {
            ui.collapsing("Help & safety", |ui| {
                ui.label("What: Simple Mode provides a calm, non-destructive One-Way Sync profile editor.");
                ui.label("Why: new profiles start with source-authoritative copying and no deletion, cleanup, schedules, or unattended destructive authorization.");
                ui.label("How: choose named local folders or one SSH peer, validate the fields, then save. The core creates the same typed Process Specification used later for execution.");
                ui.label("When: Fresh Analysis, precheck, and one final Execution Confirmation are required before a file-changing run.");
                ui.label("Limits: Mirror Sync has no implicit winner; excluded, unavailable, changed, or ambiguous items remain visible for review. Passwords stay in the desktop keyring and only an opaque reference is kept in the profile.");
            });
        });
        if self.form != form_before_draw {
            self.clear_review();
            self.status =
                "Profile changed. Fresh Analysis and confirmation are required again.".to_owned();
        }
        if let Some(id) = profile_to_select {
            self.select_profile(id);
        }
        if request_analyze && let Err(error) = self.start_analysis(ui.ctx()) {
            self.status = format_form_validation_diagnostic(&self.form, &error);
        }
        if request_validate && let Err(error) = self.validate_profile() {
            self.status = format_form_validation_diagnostic(&self.form, &error);
        }
        if request_save && let Err(error) = self.save_profile() {
            self.status = format_form_validation_diagnostic(&self.form, &error);
        }
        if request_synchronise {
            self.request_synchronise_async(ui.ctx());
        }
    }

    fn draw_review(&mut self, ui: &mut egui::Ui) {
        let mut request_confirmation = false;
        let mut request_start = false;
        let mut request_resolution_start = false;
        let mut request_resolution_confirmation = false;
        section_intro(
            ui,
            "Safety gate",
            "Plan review and Execution Confirmation",
            "Read the exact scope, resolve every blocker, then confirm this plan before any file-changing action.",
        );
        draw_contextual_help_link(
            ui,
            "Plan and confirmation",
            help_topic_for_surface(HelpSurface::Plan),
            &mut self.help_topic,
        );

        if let Some(review) = self.review.as_mut() {
            ui.label(egui::RichText::new("This is a read-only review of the current profile. No filesystem mutation starts from this view.").color(ui_palette(ui).muted));
            card_frame(ui).show(ui, |ui| {
                section_intro(
                    ui,
                    "Scope",
                    "Folder mapping",
                    "These exact roots define the reviewed action. A trailing separator does not widen the scope.",
                );
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
                ui.label("The reviewed typed Process Specification below is authoritative for execution.");
            });

            if let Some(error) = &review.error {
                inset_frame(ui).show(ui, |ui| {
                    status_badge(ui, "Blocked · review not ready", false);
                    let topic = help_topic_for_error(error);
                    draw_contextual_help_link(
                        ui,
                        "Blocked-state guidance",
                        topic,
                        &mut self.help_topic,
                    );
                    ui.label(format_profile_diagnostic(
                        &review.profile,
                        None,
                        error,
                        next_action_for_help_topic(topic),
                    ));
                });
            }

            if let Some(precheck) = &review.precheck {
                card_frame(ui).show(ui, |ui| {
                    status_badge(
                        ui,
                        if precheck.can_execute() {
                            "Precheck passed"
                        } else {
                            "Precheck blocked"
                        },
                        precheck.can_execute(),
                    );
                    draw_contextual_help_link(
                        ui,
                        "Precheck blocker guidance",
                        HelpTopic::PrecheckBlockers,
                        &mut self.help_topic,
                    );
                    ui.label(if precheck.can_execute() {
                        "Fresh precheck: passed (no blockers)"
                    } else {
                        "Fresh precheck: blocked"
                    });
                    for blocker in precheck.blockers() {
                        ui.label(format!("BLOCKER [{:?}]", blocker.kind()));
                        ui.label(format_precheck_diagnostic(&review.profile, blocker));
                        ui.label(format!("Requirement: {}", blocker.requirement()));
                    }
                    for warning in precheck.warnings() {
                        ui.label(format!(
                            "{PATH_RISK_WARNING_LABEL}: {}",
                            format_warning_diagnostic(&review.profile, warning)
                        ));
                    }
                    if precheck.blockers().is_empty() && precheck.warnings().is_empty() {
                        ui.label("No precheck warnings or blockers were reported.");
                    }
                    draw_compatibility_review(ui, &review.profile, precheck);
                });
            }

            if let Some(analysis) = review.analysis.clone() {
                draw_analysis_review(ui, review, &analysis, &mut self.help_topic);
                if review.profile.mode() == SyncMode::Mirror {
                    match draw_conflict_review(ui, review, &mut self.help_topic) {
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
                card_frame(ui).show(ui, |ui| {
                    section_intro(
                        ui,
                        "Final gate",
                        "Execution Confirmation",
                        "Confirm only after the plan, precheck, and any high-risk scope requirements are understood.",
                    );
                    if review.confirmed {
                        status_badge(ui, "Confirmation recorded", true);
                    }
                    draw_confirmation_summary(ui, review, &analysis);
                    if stronger_required {
                        ui.label("This high-risk source scope requires stronger confirmation. Type the exact source path shown in the mapping above:");
                        ui.text_edit_singleline(&mut review.stronger_confirmation_path);
                    }
                    if review.confirmed {
                        ui.label("Execution Confirmation recorded. No filesystem mutation has started.");
                        if self.active_manual_run.is_some() {
                            ui.label("A Manual Sync Run is active. Closing the window hides SyncPlus and leaves it running.");
                        } else if primary_button(ui, "Synchronise").clicked() {
                            request_start = true;
                        }
                    } else if primary_button_enabled(
                        ui,
                        "Confirm this exact reviewed scope",
                        can_confirm,
                    )
                    .clicked() {
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
                ui.label(
                    "No explainable plan is available until the precheck and Fresh Analysis pass.",
                );
            }
        } else {
            ui.label("No plan has been analyzed. Select Analyze current state to review the intended work.");
        }

        if request_resolution_start && let Err(error) = self.start_resolution_run() {
            self.status = format!("Resolution Run was not started: {error}");
        }
        if request_resolution_confirmation && let Err(error) = self.confirm_resolution_run() {
            self.status = format!("Resolution Run confirmation was not recorded: {error}");
        }
        if request_confirmation && let Err(error) = self.confirm_review() {
            self.status = format!("Execution Confirmation was not recorded: {error}");
        }
        if request_start && let Err(error) = self.start_manual_run() {
            self.status = format!("Manual Sync Run was not started: {error}");
        }
    }

    fn draw_run_reports(&mut self, ui: &mut egui::Ui) {
        let mut action_to_run = None;
        let mut cancel_pending = false;
        let mut manual_cancel = None;
        let mut review_to_clear = None;
        let mut requested_help = None;
        section_intro(
            ui,
            "Evidence",
            "Sync Runs and Recovery Review",
            "Durable Run Reports explain progress, outcomes, and recovery facts without storing passwords or file contents.",
        );
        if self.run_reports.is_empty() {
            inset_frame(ui).show(ui, |ui| {
                ui.label(
                    egui::RichText::new("No durable Sync Run reports are available.").strong(),
                );
                ui.label("Reports will appear here after a reviewed Sync Run starts.");
            });
            return;
        }

        let reports = self.run_reports.clone();
        ui.columns(2, |columns| {
            columns[0].heading("Run Reports");
            for report in &reports {
                let selected = self.selected_run_report == Some(report.run_id());
                let label = format!(
                    "Run {} — {} — {}",
                    report.run_id().value(),
                    report.snapshot().profile().name(),
                    run_report_status_label(report.status())
                );
                if columns[0]
                    .selectable_label(selected, label)
                    .on_hover_text("Select this durable report")
                    .clicked()
                {
                    self.selected_run_report = Some(report.run_id());
                    self.pending_report_action = None;
                }
            }

            let selected = self
                .selected_run_report
                .and_then(|run_id| reports.iter().find(|report| report.run_id() == run_id));
            let Some(report) = selected else {
                columns[1].label(egui::RichText::new("Select a Run Report").strong());
                columns[1].label("Inspect its lifecycle, evidence, and any Recovery Review requirements here.");
                return;
            };
            draw_run_report_detail(&mut columns[1], report, &mut requested_help);

            let pending = self
                .pending_report_action
                .filter(|action| match action {
                    PendingReportAction::RemoveCompletedReport(run_id)
                    | PendingReportAction::DiscardUnresolvedRun(run_id) => *run_id == report.run_id(),
                });
            if let Some(action) = pending {
                card_frame(&columns[1]).show(&mut columns[1], |ui| {
                    ui.label("Confirm metadata action");
                    match action {
                        PendingReportAction::RemoveCompletedReport(_) => {
                            ui.label("This removes only the completed report metadata. It does not remove synchronized source or destination files.");
                            if ui.button("Confirm Remove Completed Report").clicked() {
                                action_to_run = Some(action);
                            }
                        }
                        PendingReportAction::DiscardUnresolvedRun(_) => {
                            ui.label("This discards unresolved report and Recovery Review metadata. It does not undo or remove synchronized source or destination files; review evidence will no longer be available here.");
                            if ui.button("Confirm Discard Unresolved Run").clicked() {
                                action_to_run = Some(action);
                            }
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        cancel_pending = true;
                    }
                });
            } else {
                if report.can_mark_review_cleared()
                    && columns[1].button("Mark Review Cleared").clicked()
                {
                    review_to_clear = Some(report.run_id());
                }
                match report.status() {
                    RunReportStatus::Completed | RunReportStatus::ReviewCleared => {
                        if columns[1].button("Remove Completed Report").clicked() {
                            self.pending_report_action = Some(
                                PendingReportAction::RemoveCompletedReport(report.run_id()),
                            );
                        }
                    }
                    RunReportStatus::InProgress => {
                        if self.active_manual_run_id() == Some(report.run_id()) {
                            if columns[1].button("Request cancellation").clicked() {
                                manual_cancel = Some(report.run_id());
                            }
                            columns[1].label("Cancellation stops new actions and preserves the durable boundary for Recovery Review.");
                        } else {
                            columns[1].label("This active Scheduled Run is owned by the per-user background scheduler and is not cancelled when the visible UI is hidden or closed.");
                        }
                    }
                    _ => {
                        if columns[1].button("Discard Unresolved Run").clicked() {
                            self.pending_report_action = Some(
                                PendingReportAction::DiscardUnresolvedRun(report.run_id()),
                            );
                        }
                    }
                }
            }
        });

        if let Some(topic) = requested_help {
            self.help_topic = topic;
        }

        if cancel_pending {
            self.pending_report_action = None;
        }
        if let Some(run_id) = manual_cancel {
            self.request_manual_cancel(run_id);
        }
        if let Some(action) = action_to_run {
            self.pending_report_action = None;
            let result = match action {
                PendingReportAction::RemoveCompletedReport(run_id) => {
                    self.remove_completed_report(run_id)
                }
                PendingReportAction::DiscardUnresolvedRun(run_id) => {
                    self.discard_unresolved_run(run_id)
                }
            };
            if let Err(error) = result {
                self.status = format!("Run Report action was not completed: {error}");
            }
        } else if let Some(run_id) = review_to_clear
            && let Err(error) = self.mark_review_cleared(run_id)
        {
            self.status = format!("Review could not be cleared: {error}");
        }
    }

    fn draw_missed_schedule_notices(&mut self, ui: &mut egui::Ui) {
        if self.missed_schedule_notices.is_empty() {
            return;
        }
        let notices = self.missed_schedule_notices.clone();
        let mut run_now = None;
        let mut not_now = None;
        section_intro(
            ui,
            "Attention",
            "Missed Schedule Notices",
            "A missed occurrence is never replayed blindly. Run Now starts a fresh interactive review.",
        );
        for notice in notices {
            inset_frame(ui).show(ui, |ui| {
                ui.label(format!(
                    "Sync Profile {} — {} missed occurrence{}",
                    notice.profile_id().value(),
                    notice.missed_count(),
                    if notice.missed_count() == 1 { "" } else { "s" }
                ));
                ui.label(notice.reason());
                match notice.decision() {
                    MissedScheduleDecision::Pending => {
                        ui.horizontal(|ui| {
                            if ui.button(MISSED_SCHEDULE_RUN_NOW_LABEL).clicked() {
                                run_now = Some(notice.notice_id());
                            }
                            if ui.button(MISSED_SCHEDULE_NOT_NOW_LABEL).clicked() {
                                not_now = Some(notice.notice_id());
                            }
                        });
                    }
                    MissedScheduleDecision::RunNow => {
                        ui.label("Decision recorded: Run Now selected; the interactive review must still be completed.");
                    }
                    MissedScheduleDecision::NotNow => {
                        ui.label("Decision recorded: Not Now. Synchronization did not succeed.");
                    }
                }
            });
        }
        if let Some(notice_id) = run_now {
            if let Err(error) = self.request_missed_schedule_run_now(notice_id) {
                self.status = format!("Run Now was not started: {error}");
            }
        } else if let Some(notice_id) = not_now
            && let Err(error) = self.record_missed_schedule_not_now(notice_id)
        {
            self.status = format!("Not Now was not recorded: {error}");
        }
    }

    fn draw_scheduler_events(&self, ui: &mut egui::Ui) {
        if self.scheduler_events.is_empty() {
            return;
        }
        section_intro(
            ui,
            "Background activity",
            "Scheduler Events and Notifications",
            "These notices preserve the reason and safe next action for unattended work.",
        );
        for event in &self.scheduler_events {
            let notification = event.notification();
            inset_frame(ui).show(ui, |ui| {
                ui.label(format!(
                    "{} — Sync Profile {} — Sync Run {}",
                    notification.title(),
                    notification.profile_id().value(),
                    notification.run_id().value()
                ));
                ui.label(format!("Reason: {}", notification.reason()));
                ui.label(format!("Next action: {}", notification.next_action()));
                match notification.action() {
                    SchedulerNotificationAction::OpenReport(run_id) => {
                        ui.label(format!("Safe action: open Run Report {}.", run_id.value()));
                    }
                    SchedulerNotificationAction::StartInteractiveCatchUp(notice_id) => {
                        ui.label(format!(
                            "Safe action: start interactive catch-up from missed notice {}.",
                            notice_id
                        ));
                    }
                }
            });
        }
    }

    fn draw_notifications(&self, ui: &mut egui::Ui) {
        if self.notifications.is_empty() {
            return;
        }
        section_intro(
            ui,
            "Updates",
            "Notifications",
            "Safe status and next-action text. Open the Run Report for paths and evidence.",
        );
        for notification in &self.notifications {
            inset_frame(ui).show(ui, |ui| {
                let run = notification
                    .run_id
                    .map(|run_id| format!(" — Sync Run {}", run_id.value()))
                    .unwrap_or_default();
                ui.label(format!("{}{}", notification.title, run));
                ui.label(format!("Reason: {}", notification.reason));
                ui.label(format!("Next action: {}", notification.next_action));
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictReviewAction {
    None,
    StartResolutionRun,
    ConfirmResolutionRun,
}

fn draw_conflict_review(
    ui: &mut egui::Ui,
    review: &mut PlanReviewState,
    help_topic: &mut HelpTopic,
) -> ConflictReviewAction {
    let Some(conflicts) = review.conflicts.as_mut() else {
        return ConflictReviewAction::None;
    };
    let entries = conflicts.review.entries().to_vec();
    let mut decisions_changed = false;
    let mut action = ConflictReviewAction::None;

    card_frame(ui).show(ui, |ui| {
        section_intro(
            ui,
            "Mirror Sync",
            "Conflict Review (read-only)",
            "Mirror Sync has no implicit winner. Choose one explicit whole-file decision for every entry.",
        );
        draw_contextual_help_link(
            ui,
            "Conflict Review guidance",
            help_topic_for_surface(HelpSurface::ConflictReview),
            help_topic,
        );
        ui.label("This review never edits file content. Preserve Both, Rename/Preserve for Review, and Defer keep the run open for later review.");
        if entries.is_empty() {
            ui.label("No Mirror conflicts require a whole-file decision in this Fresh Analysis.");
        }

        for entry in &entries {
            let path = entry.relative_path().to_path_buf();
            let key = entry.key();
            ui.push_id(format!("{:?}:{:?}", entry.kind(), key), |ui| {
                inset_frame(ui).show(ui, |ui| {
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
            draw_contextual_help_link(
                ui,
                "Resolution failure guidance",
                HelpTopic::ConflictReview,
                help_topic,
            );
            ui.label(format!(
                "Resolution status: blocked — {}",
                format_profile_diagnostic(
                    &review.profile,
                    None,
                    error,
                    "Review the whole-file conflict decisions, run Fresh Analysis again, and start a fresh Resolution Run.",
                )
            ));
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
            } else if primary_button(ui, "Confirm this exact Resolution Run").clicked() {
                action = ConflictReviewAction::ConfirmResolutionRun;
            }
        } else if entries.is_empty() {
            ui.label("Resolution Run is not needed because Fresh Analysis found no conflicts.");
        } else if primary_button_enabled(
            ui,
            "Start Resolution Run review (fresh-check decisions)",
            all_decisions && precheck_ready,
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

fn draw_compatibility_review(ui: &mut egui::Ui, profile: &SyncProfile, precheck: &PrecheckResult) {
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
            ui.label(format_naming_conflict_diagnostic(profile, conflict));
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
        ConflictResolution::KeepPeerA => {
            "copy Peer A's verified whole file to Peer B; Peer A is preserved"
        }
        ConflictResolution::KeepPeerB => {
            "copy Peer B's verified whole file to Peer A; Peer B is preserved"
        }
        ConflictResolution::PreserveBoth => {
            "keep both existing peer versions without an implicit winner"
        }
        ConflictResolution::RenamePreserveForReview => {
            "preserve both versions for a later explicit review"
        }
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

fn draw_analysis_review(
    ui: &mut egui::Ui,
    review: &PlanReviewState,
    analysis: &FreshAnalysis,
    help_topic: &mut HelpTopic,
) {
    let summary = analysis.plan().summary();
    let unsupported_count = analysis
        .source_inventory()
        .items()
        .iter()
        .chain(analysis.destination_inventory().items())
        .filter(|item| item.outcome() == AnalysisOutcome::Unsupported)
        .count();
    let excluded_count = analysis.source_inventory().excluded_items().count()
        + analysis.destination_inventory().excluded_items().count();

    card_frame(ui).show(ui, |ui| {
        section_intro(
            ui,
            "Fresh Analysis",
            "Explainable Actions",
            "A read-only plan generated from the current profile and endpoint inventories.",
        );
        draw_contextual_help_link(
            ui,
            "Plan guidance",
            help_topic_for_surface(HelpSurface::Plan),
            help_topic,
        );
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
        status_badge(
            ui,
            if unsupported_count == 0 {
                "Scope ready for confirmation"
            } else {
                "Scope has unresolved items"
            },
            unsupported_count == 0,
        );
    });

    ui.collapsing(
        format!("Explainable Actions ({})", analysis.plan().action_count()),
        |ui| {
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
        },
    );

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
                for inventory in [
                    analysis.source_inventory(),
                    analysis.destination_inventory(),
                ] {
                    for item in inventory
                        .items()
                        .iter()
                        .filter(|item| item.outcome() == AnalysisOutcome::Unsupported)
                    {
                        let path = inventory.root().join(item.relative_path());
                        ui.label(format!(
                            "Unresolved unsupported item: {}",
                            format_profile_diagnostic(
                                &review.profile,
                                Some(&path),
                                format!(
                                    "{} ({:?}); execution must remain blocked",
                                    item.relative_path().display(),
                                    item.item_type()
                                ),
                                "Inspect the item and peer capability, then correct, exclude, or preserve it before running Fresh Analysis again.",
                            )
                        ));
                    }
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

fn stronger_confirmation_satisfied(review: &PlanReviewState, precheck: &PrecheckResult) -> bool {
    let typed_path = review.stronger_confirmation_path.trim();
    precheck
        .warnings()
        .iter()
        .filter(|warning| warning.requires_stronger_confirmation())
        .all(|warning| warning.source().display().to_string() == typed_path)
}

fn draw_confirmation_summary(
    ui: &mut egui::Ui,
    review: &PlanReviewState,
    analysis: &FreshAnalysis,
) {
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

fn map_storage_error(error: syncplus_core::StorageError) -> UiValidationError {
    match error {
        syncplus_core::StorageError::DuplicateEndpointPair => {
            UiValidationError::DuplicateEndpointPair
        }
        syncplus_core::StorageError::ConcurrentProfileUpdate => {
            UiValidationError::ProfileChangedDuringEdit
        }
        other => UiValidationError::Core(other.to_string()),
    }
}

fn execute_manual_run(
    run_id: RunId,
    profile: SyncProfile,
    expected: ConfirmedPlan,
    cancel: Arc<AtomicBool>,
) -> Result<RunReport, String> {
    let database_path = RunEvidenceStore::canonical_path().map_err(|error| error.to_string())?;
    let data_home = database_path
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| "canonical database has no XDG data parent".to_owned())?
        .to_path_buf();
    let recovery_method =
        if profile.options().deletion_method == Some(DeletionMethod::PermanentRemoval) {
            RecoveryMethod::permanent_removal()
        } else {
            RecoveryMethod::native_trash(data_home)
        };
    let workflow = syncplus_core::RunWorkflow::new(recovery_method);
    let mut store = RunEvidenceStore::open_canonical().map_err(|error| error.to_string())?;
    workflow
        .execute(
            run_id,
            &profile,
            &LocalPrecheckProbe::default(),
            move |fresh| fresh == &expected,
            &mut store,
            move || cancel.load(Ordering::Acquire),
        )
        .map_err(|error| error.to_string())
}

impl eframe::App for SyncPlusApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.ensure_tray(&context);
        self.process_tray_commands(&context);
        self.poll_analysis();
        self.poll_manual_run(&context);
        if !self.exit_requested && context.input(|input| input.viewport().close_requested()) {
            self.handle_close_request(&context);
        }
        if self.exit_requested {
            context.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        context.request_repaint_after(Duration::from_millis(if self.active_manual_run.is_some() {
            200
        } else {
            1_000
        }));
        self.apply_theme(ui.ctx());
        if let Err(error) = self.refresh_run_reports() {
            self.status = format!("Run Reports are unavailable: {error}");
        }
        let palette = ui_palette(ui);
        egui::Panel::left("workspace-sidebar")
            .resizable(true)
            .default_size(250.0)
            .min_size(220.0)
            .max_size(300.0)
            .frame(
                egui::Frame::new()
                    .fill(palette.canvas)
                    .inner_margin(egui::Margin::symmetric(14, 8)),
            )
            .show(ui, |ui| {
                let sidebar_actions_height = 78.0;
                let sidebar_content_height =
                    (ui.available_height() - sidebar_actions_height).max(1.0);
                egui::ScrollArea::vertical()
                    .id_salt("workspace-sidebar-content")
                    .auto_shrink([false, false])
                    .max_height(sidebar_content_height)
                    .show(ui, |ui| {
                        ui.set_min_height(sidebar_content_height);
                        self.draw_sidebar(ui);
                    });
                ui.add_space(6.0);
                self.draw_sidebar_actions(ui, &context);
            });
        egui::CentralPanel::default().show(ui, |ui| self.draw_central_content(ui));
        self.draw_quit_dialog(&context);
    }
}

impl SyncPlusApp {
    fn draw_central_content(&mut self, ui: &mut egui::Ui) {
        match self.view {
            AppView::Welcome => self.draw_welcome(ui),
            AppView::Profiles => self.draw_profiles_page(ui),
            AppView::Settings => self.draw_settings_page(ui),
            AppView::Wizard => self.draw_wizard(ui),
            AppView::Help => self.draw_help_page(ui),
            AppView::Reports => {
                egui::ScrollArea::vertical()
                    .id_salt("reports-content")
                    .show(ui, |ui| self.draw_run_reports(ui));
            }
            AppView::Sync => {
                egui::ScrollArea::vertical()
                    .id_salt("central-content")
                    .show(ui, |ui| {
                        self.draw_notifications(ui);
                        self.draw_missed_schedule_notices(ui);
                        self.draw_scheduler_events(ui);
                        self.draw_profile_form(ui);
                        self.draw_review(ui);
                        self.draw_run_reports(ui);
                    });
            }
        }
    }

    fn draw_help_page(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("help-support")
            .show(ui, |ui| {
                let available_width = ui.available_width();
                let content_width = available_width.min(1120.0);
                ui.horizontal(|ui| {
                    ui.add_space(((available_width - content_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(content_width);
                        ui.add_space(28.0);
                        card_frame(ui).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    section_intro(
                                        ui,
                                        "Support centre",
                                        "Help & Support",
                                        "A clear route through setup, synchronization, and recovery.",
                                    );
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Min),
                                    |ui| {
                                        info_badge(ui, &format!("{} guides", help_topics().len()));
                                    },
                                );
                            });
                            ui.add_space(14.0);
                            inset_frame(ui).show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    status_dot(ui, ui_palette(ui).copper);
                                    ui.label(egui::RichText::new("Safety promise").strong());
                                    ui.label(egui::RichText::new(
                                        "Every guide explains the next safe action. Help informs decisions; it never bypasses a safety gate.",
                                    ).color(ui_palette(ui).muted));
                                });
                            });
                        });
                        ui.add_space(8.0);
                        draw_help(ui, &mut self.help_topic);
                        ui.add_space(16.0);
                    });
                });
            });
    }
}

fn draw_run_report_detail(
    ui: &mut egui::Ui,
    report: &RunReport,
    requested_help: &mut Option<HelpTopic>,
) {
    section_intro(
        ui,
        "Selected report",
        &format!("Sync Run {}", report.run_id().value()),
        "A durable record of the frozen Profile Snapshot, actions, outcomes, and review state.",
    );
    status_badge(
        ui,
        run_report_status_label(report.status()),
        matches!(
            report.status(),
            RunReportStatus::Completed | RunReportStatus::ReviewCleared
        ),
    );
    draw_contextual_help_request(
        ui,
        "Run Report guidance",
        help_topic_for_report_status(report.status()),
        requested_help,
    );
    ui.label(format!(
        "Profile: {} | Mode: {} | Snapshot: {}",
        report.snapshot().profile().name(),
        sync_mode_label(report.snapshot().profile().mode()),
        report.snapshot().snapshot_id().value()
    ));
    ui.label(format!(
        "Status: {} | Execution: {} | Lifecycle: {}",
        run_report_status_label(report.status()),
        run_execution_result_label_for_report(report),
        run_lifecycle_label(report.lifecycle())
    ));
    ui.label(format!(
        "Recorded actions: {} | Reports are retained until an explicit metadata action.",
        report.items().len()
    ));

    if report.status() == RunReportStatus::InProgress {
        inset_frame(ui).show(ui, |ui| {
            section_intro(
                ui,
                "Live progress",
                "Active Sync Run",
                "The latest durable action boundary remains visible while the run is active.",
            );
            draw_contextual_help_request(
                ui,
                "Progress and cancellation",
                help_topic_for_surface(HelpSurface::Progress),
                requested_help,
            );
            if let Some(item) = report
                .items()
                .iter()
                .rev()
                .find(|item| matches!(item.outcome(), ActionOutcome::InProgress))
            {
                draw_explainable_action(ui, item);
            } else {
                ui.label("The run is active, but no current action boundary has been recorded yet.");
                ui.label("The source remains protected until the next durable action boundary is written.");
            }
            ui.label("Cancellation is stateful: the latest durable phase and progress remain available while the run is cancelled, interrupted, or awaiting review.");
        });
    }

    if matches!(
        report.status(),
        RunReportStatus::Cancelled
            | RunReportStatus::Interrupted
            | RunReportStatus::RecoveryReview
            | RunReportStatus::CompletedWithReviewRequired
            | RunReportStatus::Failed
            | RunReportStatus::Blocked
    ) {
        card_frame(ui).show(ui, |ui| {
            let report_help_topic = help_topic_for_report_status(report.status());
            let review_heading = match report.status() {
                RunReportStatus::Failed => "Execution Failure Review",
                RunReportStatus::Blocked => "Precheck Blocked Review",
                _ => "Recovery Review",
            };
            let review_help_label = match report_help_topic {
                HelpTopic::ExecutionFailures => "Execution failure guidance",
                HelpTopic::PrecheckBlockers => "Precheck blocker guidance",
                _ => "Recovery guidance",
            };
            section_intro(ui, "Review required", review_heading, run_recovery_message(report.status()));
            draw_contextual_help_request(
                ui,
                review_help_label,
                report_help_topic,
                requested_help,
            );
            if let Some(reason) = report.blocked_reason() {
                let topic = help_topic_for_report_status(report.status());
                ui.label(format!(
                    "Blocker: {}",
                    format_profile_diagnostic(
                        report.snapshot().profile(),
                        None,
                        reason,
                        next_action_for_help_topic(topic),
                    )
                ));
            }
            if let Some(reconciliation) = report.reconciliation() {
                if reconciliation.findings().is_empty() {
                    ui.label("Completion Reconciliation recorded no findings.");
                } else {
                    for finding in reconciliation.findings() {
                        ui.label(format!(
                            "Reconciliation finding: {}",
                            format_profile_diagnostic(
                                report.snapshot().profile(),
                                None,
                                format!(
                                    "{}: {}",
                                    finding.relative_path().display(),
                                    finding.reason()
                                ),
                                "Keep the report open, inspect the current peer state, and run Fresh Analysis before any explicit review action.",
                            )
                        ));
                    }
                }
            }
            for item in report.items().iter().filter(|item| {
                !matches!(item.outcome(), ActionOutcome::Completed)
                    || item.journal().recovery_evidence().is_some()
            }) {
                ui.label(format!(
                    "Review item: {}",
                    format_profile_diagnostic(
                        report.snapshot().profile(),
                        Some(item.source_path()),
                        format!(
                            "{}: {}",
                            item.relative_path().display(),
                            action_outcome_label(item.outcome())
                        ),
                        "Inspect the durable action and preserved-state evidence before taking an explicit review action.",
                    )
                ));
                if let Some(evidence) = item.journal().recovery_evidence() {
                    ui.label(format!(
                        "Preserved-state evidence: source present {}, destination present {}, recovery present {}; observed sizes: source {}, destination {}.",
                        evidence.source_present(),
                        evidence.destination_present(),
                        evidence.recovery_present(),
                        evidence.source_size().map_or_else(|| "unknown".to_owned(), format_bytes),
                        evidence.destination_size().map_or_else(|| "unknown".to_owned(), format_bytes),
                    ));
                }
            }
        });
    }

    ui.collapsing(
        format!("Explainable Actions ({})", report.items().len()),
        |ui| {
            if report.items().is_empty() {
                ui.label("No action boundaries have been recorded yet.");
            }
            for item in report.items() {
                ui.group(|ui| draw_explainable_action(ui, item));
            }
        },
    );
    if !report.mirror_resolutions().is_empty() {
        ui.collapsing("Mirror resolution evidence", |ui| {
            for resolution in report.mirror_resolutions() {
                ui.label(format!(
                    "{} — {:?} — {:?} — review state {:?}",
                    resolution.relative_path().display(),
                    resolution.operation(),
                    resolution.outcome(),
                    resolution.review_state()
                ));
            }
        });
    }
}

fn draw_explainable_action(ui: &mut egui::Ui, item: &syncplus_core::RunReportItem) {
    ui.label(format!(
        "{} — {} — {}",
        item.relative_path().display(),
        plan_action_label(item.operation()),
        action_outcome_label(item.outcome())
    ));
    let planned = item.journal().plan().planned_bytes();
    let progress = item.progress_bytes();
    let progress_text = planned.map_or_else(
        || format_bytes(progress),
        |planned| format!("{} of {}", format_bytes(progress), format_bytes(planned)),
    );
    ui.label(format!(
        "Phase: {} | Progress: {} | Consequence: {}",
        item.journal().last_phase(),
        progress_text,
        item.consequence()
    ));
    ui.label(format!(
        "Source path: {} | Destination path: {}",
        item.source_path().display(),
        item.destination_path().display()
    ));
}

fn run_report_status_label(status: RunReportStatus) -> &'static str {
    chrome::run_report_status_phrase(status)
}

fn run_execution_result_label(result: RunExecutionResult) -> &'static str {
    match result {
        RunExecutionResult::NotStarted => "Not started",
        RunExecutionResult::InProgress => "In progress",
        RunExecutionResult::Succeeded => "Succeeded",
        RunExecutionResult::Failed => "Failed",
        RunExecutionResult::Cancelled => "Cancelled",
        RunExecutionResult::Interrupted => "Interrupted",
        RunExecutionResult::Blocked => "Blocked",
        RunExecutionResult::RecoveryReview => "Recovery Review",
    }
}

fn run_execution_result_label_for_report(report: &RunReport) -> &'static str {
    if report.status() == RunReportStatus::CompletedWithReviewRequired {
        "Pending review"
    } else {
        run_execution_result_label(report.execution_result())
    }
}

fn run_lifecycle_label(lifecycle: RunLifecycle) -> &'static str {
    match lifecycle {
        RunLifecycle::Open => "Open",
        RunLifecycle::ReviewRequired => "Review required",
        RunLifecycle::ReviewCleared => "Review cleared",
    }
}

fn sync_mode_label(mode: SyncMode) -> &'static str {
    match mode {
        SyncMode::OneWay => "One-Way Sync",
        SyncMode::Mirror => "Mirror Sync",
    }
}

fn plan_action_label(action: syncplus_core::PlanActionKind) -> &'static str {
    match action {
        syncplus_core::PlanActionKind::CopyToDestination => "Copy to destination",
        syncplus_core::PlanActionKind::OverwriteDestination => "Verified destination overwrite",
        syncplus_core::PlanActionKind::RemoveDestination => "Remove destination item",
        syncplus_core::PlanActionKind::RemoveSourceAfterVerification => "Verified source removal",
    }
}

fn action_outcome_label(outcome: &ActionOutcome) -> String {
    match outcome {
        ActionOutcome::InProgress => "In progress".to_owned(),
        ActionOutcome::Completed => "Completed".to_owned(),
        ActionOutcome::Failed(reason) => format!("Failed: {reason}"),
        ActionOutcome::Cancelled => "Cancelled; preserved for review".to_owned(),
        ActionOutcome::Interrupted => "Interrupted; preserved for review".to_owned(),
        ActionOutcome::Deferred => "Deferred for review".to_owned(),
        ActionOutcome::Unresolved(reason) => format!("Unresolved: {reason}"),
        ActionOutcome::RecoveryReview(reason) => format!("Recovery Review: {reason}"),
    }
}

fn run_recovery_message(status: RunReportStatus) -> &'static str {
    match status {
        RunReportStatus::Cancelled => {
            "Cancellation was recorded. Unfinished work remains open; affected source items remain preserved when safety cannot prove removal. Inspect the durable action evidence before taking an explicit review action."
        }
        RunReportStatus::Interrupted => {
            "The run was interrupted by a crash, disconnect, or process stop. The last durable boundary is shown below and unresolved work requires Recovery Review."
        }
        RunReportStatus::RecoveryReview => {
            "Filesystem state crossed an uncertain boundary. The recorded source, destination, and recovery observations must be reviewed before this run can be cleared."
        }
        RunReportStatus::CompletedWithReviewRequired => {
            "Actions settled, but completion is withheld because unexplained, failed, unavailable, or otherwise unverified items remain."
        }
        RunReportStatus::Failed => {
            "At least one action failed. The report remains open so the failure, verification state, and preserved data can be reviewed."
        }
        RunReportStatus::Blocked => {
            "The run did not start because a safety precheck or scope blocker prevented mutation."
        }
        _ => "This run requires review before it can be treated as cleared.",
    }
}

fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    primary_button_enabled(ui, label, true)
}

fn primary_button_enabled(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let palette = ui_palette(ui);
    let fill = if enabled {
        palette.copper
    } else {
        palette.elevated
    };
    let text_color = if enabled {
        palette.on_copper
    } else {
        palette.muted
    };
    let response = ui.add_enabled(
        enabled,
        egui::Button::new(egui::RichText::new(label).strong().color(text_color))
            .fill(fill)
            .stroke(egui::Stroke::new(
                1.0,
                if enabled {
                    palette.copper
                } else {
                    palette.border_subtle
                },
            ))
            .corner_radius(egui::CornerRadius::same(8))
            .min_size(egui::vec2(0.0, 40.0)),
    );
    paint_focus_ring(ui, &response, palette.on_copper);
    response
}

fn secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let palette = ui_palette(ui);
    let response = ui.add(
        egui::Button::new(egui::RichText::new(label).color(palette.text))
            .fill(palette.elevated)
            .stroke(egui::Stroke::new(1.0, palette.border))
            .corner_radius(egui::CornerRadius::same(8))
            .min_size(egui::vec2(0.0, 38.0)),
    );
    paint_focus_ring(ui, &response, palette.text);
    response
}

fn sidebar_nav_button(
    ui: &mut egui::Ui,
    label: &str,
    selected: bool,
    icon: SidebarIcon,
    icon_color: egui::Color32,
) -> egui::Response {
    let palette = ui_palette(ui);
    let width = ui.available_width();
    let response = ui.add(
        egui::Button::new(
            egui::RichText::new(format!("        {label}")).color(if selected {
                palette.text
            } else {
                palette.muted
            }),
        )
        .fill(if selected {
            palette.copper_soft
        } else {
            egui::Color32::TRANSPARENT
        })
        .stroke(egui::Stroke::new(
            1.0,
            if selected {
                palette.copper
            } else {
                egui::Color32::TRANSPARENT
            },
        ))
        .corner_radius(egui::CornerRadius::same(8))
        .min_size(egui::vec2(width, 40.0)),
    );
    paint_sidebar_icon(ui, response.rect, icon, icon_color);
    paint_focus_ring(ui, &response, palette.text);
    response
}

fn paint_sidebar_icon(
    ui: &egui::Ui,
    button_rect: egui::Rect,
    icon: SidebarIcon,
    color: egui::Color32,
) {
    let painter = ui.painter();
    let rect = egui::Rect::from_center_size(
        egui::pos2(button_rect.left() + 22.0, button_rect.center().y),
        egui::vec2(18.0, 18.0),
    );
    let stroke = egui::Stroke::new(1.7, color);

    match icon {
        SidebarIcon::Overview => {
            let roof = [
                egui::pos2(rect.left() + 2.0, rect.top() + 8.0),
                egui::pos2(rect.center().x, rect.top() + 2.0),
                egui::pos2(rect.right() - 2.0, rect.top() + 8.0),
            ];
            painter.line(roof.to_vec(), stroke);
            painter.rect_stroke(
                egui::Rect::from_min_max(
                    egui::pos2(rect.left() + 4.0, rect.top() + 7.0),
                    egui::pos2(rect.right() - 4.0, rect.bottom() - 2.0),
                ),
                egui::CornerRadius::same(2),
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment(
                [
                    egui::pos2(rect.center().x, rect.bottom() - 2.0),
                    egui::pos2(rect.center().x, rect.bottom() - 7.0),
                ],
                stroke,
            );
        }
        SidebarIcon::Profiles => {
            painter.circle_stroke(egui::pos2(rect.center().x, rect.top() + 5.0), 2.8, stroke);
            painter.line(
                vec![
                    egui::pos2(rect.center().x - 5.0, rect.bottom() - 2.0),
                    egui::pos2(rect.center().x - 3.5, rect.bottom() - 5.0),
                    egui::pos2(rect.center().x, rect.bottom() - 6.0),
                    egui::pos2(rect.center().x + 3.5, rect.bottom() - 5.0),
                    egui::pos2(rect.center().x + 5.0, rect.bottom() - 2.0),
                ],
                stroke,
            );
            painter.circle_stroke(egui::pos2(rect.left() + 4.0, rect.top() + 8.0), 2.0, stroke);
            painter.line_segment(
                [
                    egui::pos2(rect.left() + 1.5, rect.bottom() - 2.0),
                    egui::pos2(rect.left() + 6.5, rect.bottom() - 2.0),
                ],
                stroke,
            );
        }
        SidebarIcon::SyncWorkspace => {
            painter.line_segment(
                [
                    egui::pos2(rect.left() + 1.0, rect.top() + 6.0),
                    egui::pos2(rect.right() - 2.0, rect.top() + 6.0),
                ],
                stroke,
            );
            painter.line(
                vec![
                    egui::pos2(rect.right() - 5.0, rect.top() + 3.0),
                    egui::pos2(rect.right() - 1.0, rect.top() + 6.0),
                    egui::pos2(rect.right() - 5.0, rect.top() + 9.0),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(rect.right() - 1.0, rect.bottom() - 6.0),
                    egui::pos2(rect.left() + 2.0, rect.bottom() - 6.0),
                ],
                stroke,
            );
            painter.line(
                vec![
                    egui::pos2(rect.left() + 5.0, rect.bottom() - 9.0),
                    egui::pos2(rect.left() + 1.0, rect.bottom() - 6.0),
                    egui::pos2(rect.left() + 5.0, rect.bottom() - 3.0),
                ],
                stroke,
            );
        }
        SidebarIcon::Reports => {
            painter.rect_stroke(
                egui::Rect::from_min_max(
                    egui::pos2(rect.left() + 4.0, rect.top() + 2.0),
                    egui::pos2(rect.right() - 4.0, rect.bottom() - 2.0),
                ),
                egui::CornerRadius::same(2),
                stroke,
                egui::StrokeKind::Inside,
            );
            for offset in [6.0, 9.5, 13.0] {
                painter.line_segment(
                    [
                        egui::pos2(rect.left() + 7.0, rect.top() + offset),
                        egui::pos2(rect.right() - 7.0, rect.top() + offset),
                    ],
                    stroke,
                );
            }
        }
        SidebarIcon::Settings => {
            painter.circle_stroke(rect.center(), 4.2, stroke);
            for degrees in [0.0, 60.0, 120.0, 180.0, 240.0, 300.0] {
                let radians = degrees * std::f32::consts::PI / 180.0;
                let inner = rect.center() + egui::vec2(radians.cos() * 5.2, radians.sin() * 5.2);
                let outer = rect.center() + egui::vec2(radians.cos() * 8.0, radians.sin() * 8.0);
                painter.line_segment([inner, outer], stroke);
            }
        }
        SidebarIcon::Help => {
            painter.circle_stroke(rect.center(), 7.0, stroke);
            painter.text(
                egui::pos2(rect.center().x, rect.top() + 1.0),
                egui::Align2::CENTER_TOP,
                "?",
                egui::FontId::proportional(12.0),
                color,
            );
        }
    }
}

fn sidebar_exit_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let palette = ui_palette(ui);
    let width = ui.available_width();
    let response = ui.add(
        egui::Button::new(egui::RichText::new(label).color(palette.muted))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, palette.border_subtle))
            .corner_radius(egui::CornerRadius::same(8))
            .min_size(egui::vec2(width, 32.0)),
    );
    paint_focus_ring(ui, &response, palette.text);
    response
}

fn recovery_review_notice_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let palette = ui_palette(ui);
    let width = ui.available_width();
    ui.add_space(12.0);
    let response = ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .small()
                .color(palette.on_danger_soft),
        )
        .fill(palette.danger_soft)
        .stroke(egui::Stroke::new(1.0, palette.danger))
        .corner_radius(egui::CornerRadius::same(8))
        .min_size(egui::vec2(width, 28.0)),
    );
    paint_focus_ring(ui, &response, palette.text);
    response
}

fn status_dot(ui: &mut egui::Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.5, color);
}

fn paint_focus_ring(ui: &egui::Ui, response: &egui::Response, inner_color: egui::Color32) {
    if response.has_focus() {
        let palette = ui_palette(ui);
        ui.painter().rect_stroke(
            response.rect.expand(3.0),
            egui::CornerRadius::same(11),
            egui::Stroke::new(2.0, palette.copper),
            egui::StrokeKind::Outside,
        );
        ui.painter().rect_stroke(
            response.rect.expand(1.0),
            egui::CornerRadius::same(9),
            egui::Stroke::new(2.0, inner_color),
            egui::StrokeKind::Outside,
        );
    }
}

fn card_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = ui_palette(ui);
    egui::Frame::new()
        .fill(palette.surface)
        .stroke(egui::Stroke::new(1.0, palette.border_subtle))
        .corner_radius(egui::CornerRadius::same(12))
        .inner_margin(egui::Margin::symmetric(16, 14))
        .outer_margin(egui::Margin::symmetric(0, 6))
        .shadow(if ui.visuals().dark_mode {
            egui::Shadow {
                offset: [0, 3],
                blur: 12,
                spread: 1,
                color: egui::Color32::from_black_alpha(80),
            }
        } else {
            egui::Shadow {
                offset: [0, 2],
                blur: 8,
                spread: 0,
                color: egui::Color32::from_black_alpha(24),
            }
        })
}

fn inset_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = ui_palette(ui);
    egui::Frame::new()
        .fill(palette.elevated)
        .stroke(egui::Stroke::new(1.0, palette.border_subtle))
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::symmetric(12, 10))
        .outer_margin(egui::Margin::symmetric(0, 4))
}

fn full_width_inset_frame(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    let content_width = (ui.available_width() - 24.0).max(0.0);
    inset_frame(ui).show(ui, |ui| {
        ui.set_min_width(content_width);
        add_contents(ui);
    });
}

fn section_intro(ui: &mut egui::Ui, eyebrow: &str, title: &str, description: &str) {
    let palette = ui_palette(ui);
    ui.label(
        egui::RichText::new(eyebrow.to_uppercase())
            .small()
            .strong()
            .color(palette.copper),
    );
    ui.heading(title);
    ui.label(egui::RichText::new(description).color(palette.muted));
}

fn status_badge(ui: &mut egui::Ui, label: &str, positive: bool) {
    let palette = ui_palette(ui);
    let fill = if positive {
        palette.copper_soft
    } else {
        palette.warning_soft
    };
    let text = if positive {
        palette.copper
    } else {
        palette.warning
    };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(7))
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).small().strong().color(text));
        });
}

fn active_mode_badge(ui: &mut egui::Ui, mode: ApplicationMode) {
    let label = format!("Active mode: {}", mode_label(mode));
    status_badge(ui, &label, true);
}

fn info_badge(ui: &mut egui::Ui, label: &str) {
    let palette = ui_palette(ui);
    egui::Frame::new()
        .fill(palette.elevated)
        .stroke(egui::Stroke::new(1.0, palette.steel))
        .corner_radius(egui::CornerRadius::same(7))
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label)
                    .small()
                    .strong()
                    .color(palette.steel),
            );
        });
}

fn endpoint_summary(endpoint: &EndpointForm) -> String {
    match endpoint.kind {
        EndpointKind::Local => {
            if endpoint.local_path.trim().is_empty() {
                "Not selected".to_owned()
            } else {
                endpoint.local_path.trim().to_owned()
            }
        }
        EndpointKind::Ssh => {
            if endpoint.server.trim().is_empty()
                || endpoint.username.trim().is_empty()
                || endpoint.remote_path.trim().is_empty()
            {
                "SSH peer not fully configured".to_owned()
            } else {
                format!(
                    "{}@{}:{}{}",
                    endpoint.username.trim(),
                    endpoint.server.trim(),
                    endpoint.port.trim(),
                    endpoint.remote_path.trim()
                )
            }
        }
    }
}

fn endpoint_form_label(ui: &mut egui::Ui, label: &str) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(112.0, ui.spacing().interact_size.y),
        egui::Sense::hover(),
    );
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        label,
        egui::TextStyle::Body.resolve(ui.style()),
        ui.visuals().text_color(),
    );
}

fn draw_endpoint(ui: &mut egui::Ui, title: &str, endpoint: &mut EndpointForm) {
    inset_frame(ui).show(ui, |ui| {
        ui.label(egui::RichText::new(title).heading().strong());
        ui.label(egui::RichText::new("A named endpoint keeps the sync scope explicit and reviewable.").color(ui_palette(ui).muted));
        ui.horizontal(|ui| {
            endpoint_form_label(ui, "Display name");
            let width = ui.available_width();
            ui.add_sized(
                egui::vec2(width, 32.0),
                egui::TextEdit::singleline(&mut endpoint.name).vertical_align(egui::Align::Center),
            );
        });
        ui.horizontal(|ui| {
            endpoint_form_label(ui, "Endpoint type");
            ui.radio_value(&mut endpoint.kind, EndpointKind::Local, "Local folder");
            ui.radio_value(&mut endpoint.kind, EndpointKind::Ssh, "SSH peer");
        });
        match endpoint.kind {
            EndpointKind::Local => {
                ui.horizontal(|ui| {
                    endpoint_form_label(ui, "Folder");
                    let browse_width = 106.0;
                    let field_width = (ui.available_width()
                        - browse_width
                        - ui.spacing().item_spacing.x)
                        .max(180.0);
                    ui.add_sized(
                        egui::vec2(field_width, 32.0),
                        egui::TextEdit::singleline(&mut endpoint.local_path)
                            .vertical_align(egui::Align::Center),
                    );
                    if secondary_button(ui, "Browse…").clicked()
                        && let Some(path) = FileDialog::new()
                            .set_title(format!("Select {title} folder"))
                            .pick_folder()
                        {
                            endpoint.local_path = path.to_string_lossy().into_owned();
                        }
                });
                ui.label("The folder is passed as a validated path argument; no shell command is accepted.");
            }
            EndpointKind::Ssh => {
                ui.horizontal(|ui| {
                    endpoint_form_label(ui, "Server");
                    ui.add_sized(
                        egui::vec2(ui.available_width(), 32.0),
                        egui::TextEdit::singleline(&mut endpoint.server)
                            .vertical_align(egui::Align::Center),
                    );
                });
                ui.horizontal(|ui| {
                    endpoint_form_label(ui, "Username");
                    ui.add_sized(
                        egui::vec2(ui.available_width(), 32.0),
                        egui::TextEdit::singleline(&mut endpoint.username)
                            .vertical_align(egui::Align::Center),
                    );
                });
                ui.horizontal(|ui| {
                    endpoint_form_label(ui, "Port");
                    ui.add_sized(
                        egui::vec2(100.0, 32.0),
                        egui::TextEdit::singleline(&mut endpoint.port)
                            .vertical_align(egui::Align::Center),
                    );
                });
                ui.horizontal(|ui| {
                    endpoint_form_label(ui, "Remote folder");
                    let width = ui.available_width();
                    ui.add_sized(
                        egui::vec2(width, 32.0),
                        egui::TextEdit::singleline(&mut endpoint.remote_path)
                            .vertical_align(egui::Align::Center),
                    );
                });
                ui.label("SSH host identity is checked by the core preflight before any mutation.");
                ui.horizontal(|ui| {
                    endpoint_form_label(ui, "Authentication");
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
                            endpoint_form_label(ui, "Identity file");
                            ui.add_sized(
                                egui::vec2(ui.available_width(), 32.0),
                                egui::TextEdit::singleline(&mut endpoint.identity)
                                    .vertical_align(egui::Align::Center),
                            );
                        });
                    }
                    AuthenticationForm::SavedPassword => {
                        ui.horizontal(|ui| {
                            endpoint_form_label(ui, "Keyring reference");
                            ui.add_sized(
                                egui::vec2(ui.available_width(), 32.0),
                                egui::TextEdit::singleline(&mut endpoint.secret_reference)
                                    .vertical_align(egui::Align::Center),
                            );
                        });
                        ui.label("Only the nonsecret reference is saved. Passwords and passphrases stay in the desktop keyring.");
                    }
                    AuthenticationForm::Agent | AuthenticationForm::InteractivePassword => {}
                    AuthenticationForm::NeedsConfiguration => {
                        ui.label("Authentication was cleared from this clone. Choose an approved method before saving.");
                    }
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

fn draw_contextual_help_link(
    ui: &mut egui::Ui,
    label: &str,
    topic: HelpTopic,
    selected_topic: &mut HelpTopic,
) {
    if help_link_clicked(ui, label, topic) {
        *selected_topic = topic;
    }
}

fn draw_contextual_help_request(
    ui: &mut egui::Ui,
    label: &str,
    topic: HelpTopic,
    requested_topic: &mut Option<HelpTopic>,
) {
    if help_link_clicked(ui, label, topic) {
        *requested_topic = Some(topic);
    }
}

fn help_link_clicked(ui: &mut egui::Ui, label: &str, topic: HelpTopic) -> bool {
    secondary_button(ui, &format!("Help: {label}"))
        .on_hover_text(format!("Open {} guidance", topic.label()))
        .clicked()
}

fn draw_help(ui: &mut egui::Ui, selected_topic: &mut HelpTopic) {
    let content_width = ui.available_width();
    let navigation_width = 270.0_f32.min((content_width * 0.32).max(230.0));
    let article_width = (content_width - navigation_width - 16.0).max(0.0);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width(navigation_width);
            draw_help_navigation(ui, selected_topic);
        });
        ui.add_space(16.0);
        ui.vertical(|ui| {
            ui.set_width(article_width);
            draw_help_article(ui, *selected_topic);
        });
    });
}

fn draw_help_navigation(ui: &mut egui::Ui, selected_topic: &mut HelpTopic) {
    let palette = ui_palette(ui);
    card_frame(ui).show(ui, |ui| {
        section_intro(
            ui,
            "Browse guides",
            "Support library",
            "Choose a guide by task. Start at the top if SyncPlus is new to you.",
        );
        ui.add_space(10.0);
        for (group, topics) in HELP_GROUPS {
            ui.label(
                egui::RichText::new(group.to_uppercase())
                    .small()
                    .strong()
                    .color(palette.muted),
            );
            ui.add_space(4.0);
            for topic in *topics {
                if help_topic_button(ui, *topic, *selected_topic == *topic).clicked() {
                    *selected_topic = *topic;
                }
            }
            ui.add_space(6.0);
        }
    });
}

fn help_topic_button(ui: &mut egui::Ui, topic: HelpTopic, selected: bool) -> egui::Response {
    let palette = ui_palette(ui);
    let width = ui.available_width();
    let response = ui.add(
        egui::Button::new(egui::RichText::new(format!("   {}", topic.label())).color(
            if selected {
                palette.text
            } else {
                palette.muted
            },
        ))
        .fill(if selected {
            palette.copper_soft
        } else {
            egui::Color32::TRANSPARENT
        })
        .stroke(egui::Stroke::new(
            1.0,
            if selected {
                palette.copper
            } else {
                egui::Color32::TRANSPARENT
            },
        ))
        .corner_radius(egui::CornerRadius::same(7))
        .min_size(egui::vec2(width, 34.0)),
    );
    ui.painter().circle_filled(
        egui::pos2(response.rect.left() + 12.0, response.rect.center().y),
        3.0,
        help_topic_color(topic, palette),
    );
    paint_focus_ring(ui, &response, palette.copper);
    response
}

fn help_topic_color(topic: HelpTopic, palette: BrandTheme) -> egui::Color32 {
    match topic {
        HelpTopic::GettingStarted | HelpTopic::Modes | HelpTopic::OneWaySync => palette.copper,
        HelpTopic::SafeDelete
        | HelpTopic::Recovery
        | HelpTopic::DestructiveActions
        | HelpTopic::ExecutionFailures => palette.danger,
        HelpTopic::MirrorSync
        | HelpTopic::SshAuthentication
        | HelpTopic::ProgressAndCancellation
        | HelpTopic::Diagnostics => palette.steel,
        HelpTopic::ConflictReview | HelpTopic::CloneProfile => palette.steel,
        HelpTopic::PrecheckBlockers => palette.warning,
        HelpTopic::Exclusions | HelpTopic::RunReports => palette.muted,
        HelpTopic::PlanAndConfirmation => palette.copper,
    }
}

fn draw_help_article(ui: &mut egui::Ui, topic: HelpTopic) {
    let palette = ui_palette(ui);
    let entry = help_entry(topic);
    let topic_color = help_topic_color(topic, palette);
    card_frame(ui).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("GUIDE")
                        .small()
                        .strong()
                        .color(topic_color),
                );
                ui.heading(entry.title);
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                info_badge(ui, "SAFE GUIDANCE");
            });
        });
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        help_article_section(ui, "At a glance", entry.what, topic_color);
        help_article_section(ui, "Why it matters", entry.why, palette.steel);
        help_article_section(ui, "How to use it", entry.how, palette.copper);
        help_article_section(ui, "When to use it", entry.when, palette.muted);
        help_callout(
            ui,
            "Consequences",
            entry.consequences,
            palette.danger_soft,
            palette.danger,
            palette.on_danger_soft,
        );
        help_callout(
            ui,
            "Limitations",
            entry.limitations,
            palette.warning_soft,
            palette.warning,
            palette.text,
        );
        help_callout(
            ui,
            "Next safe action",
            entry.next_action,
            palette.copper_soft,
            palette.copper,
            palette.text,
        );
    });
}

fn help_article_section(
    ui: &mut egui::Ui,
    heading: &str,
    body: &str,
    heading_color: egui::Color32,
) {
    let palette = ui_palette(ui);
    ui.label(
        egui::RichText::new(heading.to_uppercase())
            .small()
            .strong()
            .color(heading_color),
    );
    ui.add_space(3.0);
    ui.label(egui::RichText::new(body).color(palette.text));
    ui.add_space(11.0);
}

fn help_callout(
    ui: &mut egui::Ui,
    heading: &str,
    body: &str,
    fill: egui::Color32,
    border: egui::Color32,
    text: egui::Color32,
) {
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, border))
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::symmetric(12, 10))
        .outer_margin(egui::Margin::symmetric(0, 5))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(heading.to_uppercase())
                    .small()
                    .strong()
                    .color(border),
            );
            ui.add_space(3.0);
            ui.label(egui::RichText::new(body).color(text));
        });
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    const FORBIDDEN_MAGENTA: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x00, 0x99);
    const FORBIDDEN_NEON_MINT: egui::Color32 = egui::Color32::from_rgb(0x00, 0xFF, 0x85);
    const FORBIDDEN_TEAL: egui::Color32 = egui::Color32::from_rgb(0x79, 0xD2, 0xC3);

    fn app() -> SyncPlusApp {
        SyncPlusApp::new_with_store(RunEvidenceStore::open_in_memory().expect("database"))
            .expect("app")
    }

    #[test]
    fn empty_store_opens_branded_welcome_and_new_profile_starts_wizard() {
        let mut syncplus = app();
        assert_eq!(syncplus.view, AppView::Welcome);
        assert_eq!(syncplus.wizard_step, None);

        syncplus.start_new_profile();

        assert_eq!(syncplus.view, AppView::Wizard);
        assert_eq!(syncplus.wizard_step, Some(ProfileWizardStep::SyncMethod));
    }

    #[test]
    fn wizard_requires_current_step_fields_before_advancing() {
        let mut syncplus = app();
        syncplus.start_new_profile();

        assert_eq!(
            syncplus.advance_wizard_step(ProfileWizardStep::SyncMethod),
            Err(UiValidationError::EmptyProfileName)
        );
        assert_eq!(syncplus.wizard_step, Some(ProfileWizardStep::SyncMethod));

        syncplus.form.name = "Documents backup".to_owned();
        assert!(
            syncplus
                .advance_wizard_step(ProfileWizardStep::SyncMethod)
                .is_ok()
        );
        assert_eq!(
            syncplus.wizard_step,
            Some(ProfileWizardStep::SourceEndpoint)
        );
        assert_eq!(
            syncplus.wizard_step_validation(ProfileWizardStep::SourceEndpoint),
            Err(UiValidationError::EmptyLocalPath { peer: "Source" })
        );
    }

    #[test]
    fn wizard_back_moves_to_the_previous_step_and_clears_review() {
        let mut syncplus = app();
        syncplus.start_new_profile();
        syncplus.wizard_step = Some(ProfileWizardStep::DestinationEndpoint);
        syncplus.review = Some(PlanReviewState {
            profile: SyncProfile::new(
                "Documents backup",
                Peer::new("source", PathBuf::from("/source")),
                Peer::new("destination", PathBuf::from("/destination")),
            ),
            precheck: None,
            analysis: None,
            conflicts: None,
            error: None,
            stronger_confirmation_path: String::new(),
            confirmed: false,
        });

        syncplus.retreat_wizard_step(ProfileWizardStep::DestinationEndpoint);

        assert_eq!(
            syncplus.wizard_step,
            Some(ProfileWizardStep::SourceEndpoint)
        );
        assert!(syncplus.review.is_none());
    }

    #[test]
    fn selecting_a_saved_profile_loads_it_into_the_sync_workspace() {
        let mut syncplus = app();
        let profile = SyncProfile::new(
            "Documents backup",
            Peer::new("source", PathBuf::from("/source")),
            Peer::new("destination", PathBuf::from("/destination")),
        );
        let persisted = syncplus.store.create_profile(&profile).expect("profile");
        syncplus.profiles = syncplus.store.list_profiles().expect("profiles");

        syncplus.select_profile(persisted.id());

        assert_eq!(syncplus.view, AppView::Sync);
        assert_eq!(syncplus.form.id, Some(persisted.id()));
        assert_eq!(syncplus.form.name, "Documents backup");
        assert!(syncplus.status().contains("Editing Documents backup"));
    }

    #[test]
    fn help_navigation_is_separate_from_the_sync_workspace() {
        let mut syncplus = app();
        syncplus.show_help(HelpTopic::Recovery);
        assert_eq!(syncplus.view, AppView::Help);
        assert_eq!(syncplus.help_topic, HelpTopic::Recovery);

        syncplus.show_sync_workspace();
        assert_eq!(syncplus.view, AppView::Sync);
        assert_eq!(syncplus.wizard_step, None);
    }

    #[test]
    fn settings_navigation_is_available_as_a_primary_workspace_destination() {
        let mut syncplus = app();
        syncplus.show_settings();

        assert_eq!(syncplus.view, AppView::Settings);
        assert_eq!(syncplus.wizard_step, None);
    }

    #[test]
    fn synchronise_starts_with_fresh_analysis_and_never_bypasses_confirmation() {
        let (form, _source, base) = filesystem_form();
        let mut syncplus = app();
        syncplus.form = form;

        syncplus.request_synchronise();

        assert!(syncplus.review.is_some());
        assert!(syncplus.active_manual_run.is_none());
        assert!(syncplus.status().contains("Fresh Analysis completed"));

        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[test]
    fn fresh_analysis_is_dispatched_without_blocking_the_ui_thread() {
        let (form, _source, base) = filesystem_form();
        let mut syncplus = app();
        syncplus.form = form;
        let context = egui::Context::default();

        syncplus
            .start_analysis(&context)
            .expect("analysis should be dispatched");

        assert!(syncplus.active_analysis.is_some());
        assert!(syncplus.status().contains("running"));

        for _ in 0..100 {
            syncplus.poll_analysis();
            if syncplus.active_analysis.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(syncplus.active_analysis.is_none());
        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn central_content_does_not_paint_scroll_area_id_clash_diagnostics() {
        fn collect_text(shape: &egui::Shape, texts: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => texts.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect_text(shape, texts);
                    }
                }
                _ => {}
            }
        }

        let mut syncplus = app();
        let context = egui::Context::default();
        let output = context.run_ui(Default::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| syncplus.draw_central_content(ui));
        });
        let mut texts = Vec::new();
        for clipped_shape in &output.shapes {
            collect_text(&clipped_shape.shape, &mut texts);
        }
        output.drop_without_applying_deltas();

        assert!(
            !texts.iter().any(|text| text.contains("ScrollArea ID")),
            "egui painted an internal widget diagnostic: {texts:?}"
        );
    }

    #[test]
    fn missed_schedule_notice_exposes_exactly_the_two_catch_up_choices() {
        assert_eq!(MISSED_SCHEDULE_RUN_NOW_LABEL, "Yes, Run Now");
        assert_eq!(MISSED_SCHEDULE_NOT_NOW_LABEL, "No, Not Now");
        assert_ne!(MISSED_SCHEDULE_RUN_NOW_LABEL, MISSED_SCHEDULE_NOT_NOW_LABEL);
    }

    #[test]
    fn window_close_hides_to_tray_without_stopping_work() {
        assert_eq!(window_close_decision(true), WindowCloseDecision::HideToTray);
        assert_eq!(
            window_close_decision(false),
            WindowCloseDecision::KeepVisible
        );
    }

    #[test]
    fn quit_requires_a_choice_only_for_an_active_manual_run() {
        assert_eq!(quit_decision(false), QuitDecision::Exit);
        assert_eq!(quit_decision(true), QuitDecision::AskBeforeStopping);
    }

    #[test]
    fn lifecycle_notification_copy_has_reason_and_safe_next_action() {
        for status in [
            RunReportStatus::Completed,
            RunReportStatus::Failed,
            RunReportStatus::Cancelled,
            RunReportStatus::Interrupted,
            RunReportStatus::CompletedWithReviewRequired,
            RunReportStatus::ReviewCleared,
        ] {
            let message = notification_template_for_status(status);
            assert!(!message.title.is_empty());
            assert!(!message.reason.is_empty());
            assert!(!message.next_action.is_empty());
            assert!(!message.reason.contains('/'));
            assert!(!message.next_action.contains('/'));
            assert!(!message.reason.contains("password"));
            assert!(!message.next_action.contains("password"));
        }
    }

    fn report_store() -> (RunEvidenceStore, syncplus_core::RunId, syncplus_core::RunId) {
        let mut store = RunEvidenceStore::open_in_memory().expect("database");
        let profile = SyncProfile::new(
            "report profile",
            Peer::new("source", PathBuf::from("/source")),
            Peer::new("destination", PathBuf::from("/destination")),
        );
        let action = || {
            syncplus_core::PlanRecord::new(
                1,
                PathBuf::from("file.txt"),
                syncplus_core::PlanActionKind::CopyToDestination,
                syncplus_core::PeerSide::PeerA,
                Some(42),
                syncplus_core::PreActionState::new(
                    syncplus_core::ItemType::RegularFile,
                    42,
                    None,
                    None,
                    None,
                ),
            )
        };
        let completed_run = syncplus_core::RunId::new(90);
        let completed_snapshot = syncplus_core::RunSnapshot::from_profile(
            completed_run,
            &profile,
            syncplus_core::AuthorizationSnapshot::default(),
        )
        .expect("completed snapshot");
        store.begin_run(&completed_snapshot).expect("snapshot");
        store
            .append_event(
                completed_run,
                syncplus_core::JournalEvent::Planned { action: action() },
            )
            .expect("plan");
        store
            .append_event(
                completed_run,
                syncplus_core::JournalEvent::Started { action_id: 1 },
            )
            .expect("start");
        store
            .append_event(
                completed_run,
                syncplus_core::JournalEvent::Completed { action_id: 1 },
            )
            .expect("complete");

        let unresolved_run = syncplus_core::RunId::new(91);
        let unresolved_snapshot = syncplus_core::RunSnapshot::from_profile(
            unresolved_run,
            &profile,
            syncplus_core::AuthorizationSnapshot::default(),
        )
        .expect("unresolved snapshot");
        store.begin_run(&unresolved_snapshot).expect("snapshot");
        store
            .append_event(
                unresolved_run,
                syncplus_core::JournalEvent::Planned { action: action() },
            )
            .expect("plan");
        store
            .append_event(
                unresolved_run,
                syncplus_core::JournalEvent::Started { action_id: 1 },
            )
            .expect("start");
        store
            .append_event(
                unresolved_run,
                syncplus_core::JournalEvent::Unresolved {
                    action_id: 1,
                    reason: syncplus_core::ActionReason::PermissionDenied,
                },
            )
            .expect("unresolved");
        (store, completed_run, unresolved_run)
    }

    #[test]
    fn run_report_surface_loads_status_and_guards_metadata_actions() {
        let (store, completed_run, unresolved_run) = report_store();
        let mut app = SyncPlusApp::new_with_store(store).expect("app");

        assert_eq!(app.run_reports().len(), 2);
        assert_eq!(app.run_reports()[0].run_id(), unresolved_run);
        app.select_run_report(completed_run).expect("select report");
        assert_eq!(
            app.selected_run_report().expect("selected report").run_id(),
            completed_run
        );
        assert!(
            app.remove_completed_report(unresolved_run)
                .expect_err("unresolved work has a separate discard action")
                .to_string()
                .contains("Remove Completed Report")
        );
        app.mark_review_cleared(completed_run)
            .expect("record explicit review acknowledgement");
        assert_eq!(
            app.selected_run_report()
                .expect("selected cleared report")
                .status(),
            RunReportStatus::ReviewCleared
        );
        app.remove_completed_report(completed_run)
            .expect("remove completed metadata");
        assert_eq!(app.run_reports().len(), 1);
        app.discard_unresolved_run(unresolved_run)
            .expect("discard unresolved metadata");
        assert!(app.run_reports().is_empty());
    }

    #[test]
    fn pending_review_is_not_presented_as_completed() {
        assert_eq!(
            run_report_status_label(RunReportStatus::CompletedWithReviewRequired),
            "Pending review"
        );
        assert!(run_recovery_message(RunReportStatus::Interrupted).contains("Recovery Review"));
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
        let base =
            std::env::temp_dir().join(format!("syncplus-ui-{unique}-{}", std::process::id()));
        let source = base.join("source");
        let destination = base.join("destination");
        fs::create_dir_all(&source).expect("source directory");
        fs::create_dir_all(&destination).expect("destination directory");
        fs::write(source.join("keep.txt"), b"new contents").expect("included file");
        fs::write(source.join("ignored.tmp"), b"excluded file").expect("excluded file");
        fs::write(destination.join("keep.txt"), b"old contents").expect("existing file");

        let mut form = ProfileForm {
            name: "Filesystem review".to_owned(),
            ..Default::default()
        };
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
    fn scheduling_is_advanced_only_persisted_and_keeps_snapshot_boundaries() {
        let mut app = app();
        app.set_mode(ApplicationMode::Advanced);
        app.form = valid_form();
        app.form.schedule_enabled = true;
        app.form.schedule_interval_minutes = "15".to_owned();
        app.form.schedule_timezone = "Pacific/Auckland".to_owned();
        let id = app.save_profile().expect("save scheduled profile");
        let schedule = app.profiles()[0].schedule().expect("schedule");
        assert_eq!(schedule.interval_minutes(), 15);
        assert_eq!(schedule.timezone(), "Pacific/Auckland");
        assert!(schedule.next_run_at_unix_seconds().is_some());
        assert!(app.profiles()[0].schedule_enabled());

        app.set_mode(ApplicationMode::Simple);
        app.form.name = "edited later".to_owned();
        app.save_profile().expect("edit profile in Simple Mode");
        let persisted = app
            .profiles()
            .iter()
            .find(|profile| profile.id() == id)
            .expect("profile");
        assert!(persisted.schedule_enabled());
        assert_eq!(
            persisted.schedule().expect("schedule").interval_minutes(),
            15
        );
    }

    #[test]
    fn invalid_schedule_fields_are_rejected_before_profile_save() {
        let mut app = app();
        app.set_mode(ApplicationMode::Advanced);
        app.form = valid_form();
        app.form.schedule_interval_minutes = "0".to_owned();
        assert_eq!(
            app.save_profile(),
            Err(UiValidationError::InvalidScheduleInterval)
        );
        assert!(app.profiles().is_empty());
    }

    #[test]
    fn stale_profile_form_cannot_overwrite_a_scheduler_update() {
        let mut app = app();
        app.form = valid_form();
        let id = app.save_profile().expect("create profile");

        let externally_edited = app
            .profiles()
            .iter()
            .find(|profile| profile.id() == id)
            .expect("created profile")
            .profile()
            .clone()
            .with_mode(SyncMode::Mirror);
        app.store
            .update_profile(id, &externally_edited)
            .expect("scheduler update");

        app.form.mode = SyncMode::Mirror;
        assert_eq!(
            app.save_profile(),
            Err(UiValidationError::ProfileChangedDuringEdit)
        );
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
        assert_eq!(
            error,
            UiValidationError::EmptyLocalPath {
                peer: "Destination"
            }
        );
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
        assert_eq!(
            app.profiles()[0].profile().peer_a().root(),
            PathBuf::from("/home/user/Documents")
        );
        assert!(app.status().contains("future runs"));
    }

    #[test]
    fn cloning_clears_saved_credentials_and_requires_a_real_endpoint_change() {
        let mut store = RunEvidenceStore::open_in_memory().expect("database");
        let mut source_form = valid_form();
        source_form.peer_b.kind = EndpointKind::Ssh;
        source_form.peer_b.server = "backup.example.com".to_owned();
        source_form.peer_b.username = "sync-user".to_owned();
        source_form.peer_b.remote_path = "/srv/backup".to_owned();
        source_form.peer_b.authentication = AuthenticationForm::SavedPassword;
        source_form.peer_b.secret_reference = "backup-password".to_owned();
        let source = source_form.build().expect("source profile");
        let source_id = store.create_profile(&source).expect("source profile").id();
        let mut app = SyncPlusApp::new_with_store(store).expect("app");

        app.clone_profile(source_id).expect("clone profile");
        assert_eq!(app.form.id, None);
        assert_eq!(app.form.peer_b.secret_reference, "");
        assert_eq!(
            app.form.peer_b.authentication,
            AuthenticationForm::NeedsConfiguration
        );
        app.form.peer_b.name = "renamed destination label".to_owned();
        assert_eq!(
            app.save_profile(),
            Err(UiValidationError::SshAuthenticationRequired)
        );

        app.form.peer_b.authentication = AuthenticationForm::Agent;
        assert_eq!(
            app.save_profile(),
            Err(UiValidationError::CloneEndpointsUnchanged)
        );
        app.form.peer_b.remote_path = "/srv/backup-copy".to_owned();
        let clone_id = app.save_profile().expect("changed endpoint clone");
        let clone = app
            .profiles()
            .iter()
            .find(|profile| profile.id() == clone_id)
            .expect("saved clone");
        assert_eq!(
            clone.profile().peer_b().root(),
            PathBuf::from("/srv/backup-copy")
        );
        assert!(!clone.authorizations().allow_unattended_destructive());
        assert!(!clone.authorizations().allow_unattended_permanent_removal());
    }

    #[test]
    fn cloning_requires_authorization_choice_and_never_copies_permanent_removal() {
        let mut store = RunEvidenceStore::open_in_memory().expect("database");
        let mut source_form = valid_form();
        source_form.safe_delete = true;
        source_form.deletion_method = Some(DeletionMethod::PermanentRemoval);
        let source = source_form.build().expect("source profile");
        let source_id = store
            .create_profile_with_authorizations(&source, AuthorizationSnapshot::new(true, true))
            .expect("authorized source profile")
            .id();
        let mut app = SyncPlusApp::new_with_store(store).expect("app");

        app.clone_profile(source_id).expect("clone profile");
        assert_eq!(app.form.deletion_method, Some(DeletionMethod::Trash));
        app.form.peer_a.local_path = "/home/user/other-documents".to_owned();
        assert_eq!(
            app.save_profile(),
            Err(UiValidationError::CloneAuthorizationConfirmationRequired)
        );

        app.form.clone_authorization_confirmed = true;
        let clone_id = app.save_profile().expect("explicitly confirmed clone");
        let clone = app
            .profiles()
            .iter()
            .find(|profile| profile.id() == clone_id)
            .expect("saved clone");
        assert_eq!(
            clone.profile().options().deletion_method,
            Some(DeletionMethod::Trash)
        );
        assert!(!clone.authorizations().allow_unattended_destructive());
        assert!(!clone.authorizations().allow_unattended_permanent_removal());
    }

    #[test]
    fn clone_copy_authorization_is_explicit_advanced_only_and_excludes_permanent_removal() {
        let mut store = RunEvidenceStore::open_in_memory().expect("database");
        let mut source_form = valid_form();
        source_form.safe_delete = true;
        source_form.deletion_method = Some(DeletionMethod::PermanentRemoval);
        let source = source_form.build().expect("source profile");
        let source_id = store
            .create_profile_with_authorizations(&source, AuthorizationSnapshot::new(true, true))
            .expect("authorized source profile")
            .id();
        let mut app = SyncPlusApp::new_with_store(store).expect("app");
        app.clone_profile(source_id).expect("clone profile");
        app.form.peer_b.local_path = "/home/user/other-backup".to_owned();
        app.form.clone_authorization_choice = CloneAuthorizationChoice::CopyUnattendedDestructive;
        app.form.clone_authorization_confirmed = true;
        assert_eq!(
            app.save_profile(),
            Err(UiValidationError::CloneAuthorizationConfirmationRequired)
        );

        app.set_mode(ApplicationMode::Advanced);
        let clone_id = app.save_profile().expect("advanced explicit copy");
        let clone = app
            .profiles()
            .iter()
            .find(|profile| profile.id() == clone_id)
            .expect("saved clone");
        assert!(clone.authorizations().allow_unattended_destructive());
        assert!(!clone.authorizations().allow_unattended_permanent_removal());
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
        let mut app =
            SyncPlusApp::new_with_store_and_secret_store(store, AvailableSecretStore).expect("app");
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
        assert!(
            analysis
                .source_inventory()
                .excluded_items()
                .any(|item| item.relative_path() == std::path::Path::new("ignored.tmp"))
        );
        assert!(analysis.plan().summary().overwrite_count() >= 1);
        assert!(analysis.specification().preview().contains("rsync"));
        assert!(
            !analysis
                .specification()
                .preview()
                .contains("test-only-secret")
        );
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

        assert_eq!(
            app.analyze_profile(),
            Err(UiValidationError::PrecheckBlocked)
        );
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
        assert!(
            app.start_resolution_run().is_err(),
            "missing decisions must block"
        );

        app.set_conflict_resolution("keep.txt", ConflictResolution::KeepPeerA)
            .expect("whole-file decision");
        fs::write(source.join("keep.txt"), b"changed before resolution start")
            .expect("change source");
        assert!(
            app.start_resolution_run().is_err(),
            "stale resolution must block before start"
        );

        app.analyze_profile()
            .expect("fresh mirror analysis should pass");
        app.set_conflict_resolution("keep.txt", ConflictResolution::KeepPeerA)
            .expect("whole-file decision after fresh analysis");
        app.start_resolution_run()
            .expect("selected decision starts a fresh Resolution Run");
        assert!(!app.resolution_is_confirmed());
        let source_before = fs::read(source.join("keep.txt")).expect("source contents");
        let destination_before =
            fs::read(base.join("destination/keep.txt")).expect("destination contents");
        app.confirm_resolution_run()
            .expect("fresh Resolution Run confirmation should pass");
        assert!(app.resolution_is_confirmed());
        assert_eq!(
            fs::read(source.join("keep.txt")).expect("source contents"),
            source_before
        );
        assert_eq!(
            fs::read(base.join("destination/keep.txt")).expect("destination contents"),
            destination_before
        );

        fs::write(source.join("keep.txt"), b"changed after conflict review")
            .expect("change source");
        assert!(
            app.confirm_resolution_run().is_err(),
            "stale resolution must block"
        );
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
        assert!(
            options
                .metadata
                .specialist_metadata()
                .access_control_lists()
        );
        assert!(options.metadata.specialist_metadata().extended_attributes());
        assert_eq!(
            options.partial_transfer_policy,
            PartialTransferPolicy::KeepPartialForResume
        );
        assert_eq!(options.retry_policy.max_attempts(), 5);
        assert_eq!(
            options.retry_policy.initial_delay(),
            Duration::from_millis(250)
        );
        assert!(
            !syncplus_core::ProcessSpecification::from_profile(&profile)
                .expect("validated specification")
                .preview()
                .contains("--arbitrary")
        );

        form.retry_attempts = "11".to_owned();
        assert_eq!(form.build(), Err(UiValidationError::InvalidRetryAttempts));
        form.retry_attempts = "5".to_owned();
        form.retry_delay_millis = "3600001".to_owned();
        assert_eq!(form.build(), Err(UiValidationError::InvalidRetryDelay));
    }

    #[test]
    fn help_catalog_covers_required_topics_with_complete_safe_guidance() {
        let required_topics = [
            HelpTopic::Modes,
            HelpTopic::OneWaySync,
            HelpTopic::SafeDelete,
            HelpTopic::MirrorSync,
            HelpTopic::ConflictReview,
            HelpTopic::Exclusions,
            HelpTopic::SshAuthentication,
            HelpTopic::Recovery,
            HelpTopic::RunReports,
            HelpTopic::DestructiveActions,
            HelpTopic::ExecutionFailures,
        ];

        for topic in required_topics {
            let entry = help_entry(topic);
            assert!(!entry.title.is_empty());
            assert!(!entry.what.is_empty());
            assert!(!entry.why.is_empty());
            assert!(!entry.how.is_empty());
            assert!(!entry.when.is_empty());
            assert!(!entry.consequences.is_empty());
            assert!(!entry.limitations.is_empty());
            assert!(!entry.next_action.is_empty());
            let content = format!(
                "{} {} {} {} {} {} {} {}",
                entry.title,
                entry.what,
                entry.why,
                entry.how,
                entry.when,
                entry.consequences,
                entry.limitations,
                entry.next_action
            );
            assert!(!content.contains("test-only-secret"));
            assert!(!content.contains("private-key-material"));
            assert!(!content.contains("file-content-sentinel"));
        }

        assert!(help_topics().len() >= required_topics.len());
    }

    #[test]
    fn report_statuses_select_the_matching_help_guidance() {
        assert_eq!(
            help_topic_for_report_status(RunReportStatus::InProgress),
            HelpTopic::ProgressAndCancellation
        );
        assert_eq!(
            help_topic_for_report_status(RunReportStatus::Blocked),
            HelpTopic::PrecheckBlockers
        );
        assert_eq!(
            help_topic_for_report_status(RunReportStatus::Failed),
            HelpTopic::ExecutionFailures
        );
        assert_eq!(
            help_topic_for_report_status(RunReportStatus::RecoveryReview),
            HelpTopic::Recovery
        );
        assert_eq!(
            help_topic_for_report_status(RunReportStatus::Completed),
            HelpTopic::RunReports
        );
    }

    #[test]
    fn contextual_help_maps_every_required_surface_to_text_guidance() {
        let surfaces = [
            (HelpSurface::Profile, HelpTopic::Modes),
            (HelpSurface::Plan, HelpTopic::PlanAndConfirmation),
            (HelpSurface::ConflictReview, HelpTopic::ConflictReview),
            (HelpSurface::Progress, HelpTopic::ProgressAndCancellation),
            (HelpSurface::Report, HelpTopic::RunReports),
            (HelpSurface::Recovery, HelpTopic::Recovery),
            (HelpSurface::Clone, HelpTopic::CloneProfile),
        ];

        for (surface, expected_topic) in surfaces {
            let topic = help_topic_for_surface(surface);
            assert_eq!(topic, expected_topic);
            assert!(!help_entry(topic).next_action.is_empty());
        }
    }

    #[test]
    fn help_panel_renders_text_controls_in_light_and_dark_themes() {
        for theme in [egui::ThemePreference::Light, egui::ThemePreference::Dark] {
            egui::__run_test_ui(|ui| {
                ui.ctx().set_theme(theme);
                let mut selected_topic = HelpTopic::Modes;
                draw_help(ui, &mut selected_topic);
                assert_eq!(selected_topic, HelpTopic::Modes);
            });
        }
    }

    fn collect_painted_text(shape: &egui::Shape, texts: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(text) => texts.push(text.galley.text().to_owned()),
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect_painted_text(shape, texts);
                }
            }
            _ => {}
        }
    }

    fn collect_painted_colors(shape: &egui::Shape, colors: &mut Vec<egui::Color32>) {
        match shape {
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect_painted_colors(shape, colors);
                }
            }
            egui::Shape::Circle(circle) => {
                colors.push(circle.fill);
                colors.push(circle.stroke.color);
            }
            egui::Shape::Ellipse(ellipse) => {
                colors.push(ellipse.fill);
                colors.push(ellipse.stroke.color);
            }
            egui::Shape::LineSegment { stroke, .. } => colors.push(stroke.color),
            egui::Shape::Path(path) => {
                colors.push(path.fill);
                if let egui::epaint::ColorMode::Solid(color) = path.stroke.color {
                    colors.push(color);
                }
            }
            egui::Shape::Rect(rect) => {
                colors.push(rect.fill);
                colors.push(rect.stroke.color);
            }
            egui::Shape::Text(text) => {
                colors.push(text.fallback_color);
                if let Some(color) = text.override_text_color {
                    colors.push(color);
                }
                colors.push(text.underline.color);
            }
            egui::Shape::Mesh(mesh) => {
                for vertex in &mesh.vertices {
                    colors.push(vertex.color);
                }
            }
            _ => {}
        }
    }

    fn painted_output_for(
        app: &mut SyncPlusApp,
        theme: ThemePreference,
    ) -> (Vec<String>, Vec<egui::Color32>) {
        painted_shapes_for(app, theme, false)
    }

    fn painted_window_for(
        app: &mut SyncPlusApp,
        theme: ThemePreference,
    ) -> (Vec<String>, Vec<egui::Color32>) {
        painted_shapes_for(app, theme, true)
    }

    fn painted_shapes_for(
        app: &mut SyncPlusApp,
        theme: ThemePreference,
        include_sidebar: bool,
    ) -> (Vec<String>, Vec<egui::Color32>) {
        app.set_theme(theme);
        let context = egui::Context::default();
        let output = context.run_ui(Default::default(), |context| {
            app.apply_theme(context);
            if include_sidebar {
                let ctx = context.clone();
                egui::Panel::left("workspace-sidebar").show(context, |ui| {
                    app.draw_sidebar(ui);
                    app.draw_sidebar_actions(ui, &ctx);
                });
            }
            egui::CentralPanel::default().show(context, |ui| app.draw_central_content(ui));
        });
        let mut texts = Vec::new();
        let mut colors = Vec::new();
        for clipped_shape in &output.shapes {
            collect_painted_text(&clipped_shape.shape, &mut texts);
            collect_painted_colors(&clipped_shape.shape, &mut colors);
        }
        output.drop_without_applying_deltas();
        (texts, colors)
    }

    fn app_with_saved_profile() -> SyncPlusApp {
        let mut syncplus = app();
        let profile = SyncProfile::new(
            "Documents backup",
            Peer::new("source", PathBuf::from("/source")),
            Peer::new("destination", PathBuf::from("/destination")),
        );
        let persisted = syncplus.store.create_profile(&profile).expect("profile");
        syncplus.profiles = syncplus.store.list_profiles().expect("profiles");
        syncplus.form = ProfileForm::from_persisted(&persisted);
        syncplus.show_welcome();
        syncplus
    }

    fn assert_no_forbidden_hues(colors: &[egui::Color32], screen: &str, appearance: &str) {
        for color in colors {
            let opaque = egui::Color32::from_rgb(color.r(), color.g(), color.b());
            assert_ne!(
                opaque, FORBIDDEN_MAGENTA,
                "{appearance} {screen} painted magenta"
            );
            assert_ne!(
                opaque, FORBIDDEN_NEON_MINT,
                "{appearance} {screen} painted neon mint"
            );
            assert_ne!(opaque, FORBIDDEN_TEAL, "{appearance} {screen} painted teal");
        }
    }

    #[test]
    fn theme_preference_is_persisted_in_application_database() {
        let store = RunEvidenceStore::open_in_memory().expect("database");
        let mut app = SyncPlusApp::new_with_store(store).expect("app");
        for theme in [
            ThemePreference::Light,
            ThemePreference::Dark,
            ThemePreference::System,
        ] {
            app.set_theme(theme);
            assert_eq!(app.theme(), theme);
        }
    }

    #[test]
    fn switching_appearance_restyles_window_tokens_immediately() {
        let mut app = app();
        let context = egui::Context::default();

        app.set_theme(ThemePreference::Dark);
        app.apply_theme(&context);
        context.all_styles_mut(|style| {
            assert_eq!(style.visuals.panel_fill, BrandTheme::dark().canvas);
            assert_eq!(style.visuals.window_fill, BrandTheme::dark().surface);
            assert_eq!(
                style.visuals.selection.stroke.color,
                BrandTheme::dark().copper
            );
            assert_eq!(style.visuals.hyperlink_color, BrandTheme::dark().steel);
            assert_eq!(style.visuals.error_fg_color, BrandTheme::dark().danger);
            assert_eq!(style.visuals.warn_fg_color, BrandTheme::dark().warning);
            assert_ne!(style.visuals.panel_fill, egui::Color32::BLACK);
            assert_ne!(
                style.visuals.widgets.hovered.bg_stroke.color,
                FORBIDDEN_MAGENTA
            );
        });

        app.set_theme(ThemePreference::Light);
        app.apply_theme(&context);
        context.all_styles_mut(|style| {
            assert_eq!(style.visuals.panel_fill, BrandTheme::light().canvas);
            assert_eq!(style.visuals.window_fill, BrandTheme::light().surface);
            assert_eq!(
                style.visuals.selection.stroke.color,
                BrandTheme::light().copper
            );
            assert_ne!(style.visuals.panel_fill, egui::Color32::WHITE);
            assert_ne!(style.visuals.window_fill, egui::Color32::WHITE);
        });
    }

    #[test]
    fn representative_screens_render_in_both_appearances() {
        let screens: [(&str, fn(&mut SyncPlusApp), &[&str]); 7] = [
            (
                "Overview",
                |app| app.show_welcome(),
                &[
                    crate::chrome::EMPTY_OVERVIEW_TITLE,
                    crate::chrome::EMPTY_OVERVIEW_PRIMARY,
                ],
            ),
            ("Profiles", |app| app.show_profiles(), &["Profiles"]),
            (
                "Settings",
                |app| app.show_settings(),
                &["Appearance", "System", "Light", "Dark"],
            ),
            ("wizard", |app| app.start_new_profile(), &["Sync method"]),
            (
                "Sync workspace",
                |app| app.show_sync_workspace(),
                &["Execution Confirmation"],
            ),
            (
                "Run Reports",
                |app| app.show_reports(),
                &["Recovery Review"],
            ),
            (
                "Help",
                |app| app.show_help(HelpTopic::Recovery),
                &["Recovery Review"],
            ),
        ];

        for theme in [ThemePreference::Light, ThemePreference::Dark] {
            let appearance = match theme {
                ThemePreference::Light => "light",
                ThemePreference::Dark => "dark",
                ThemePreference::System => "system",
            };
            for (screen, setup, required) in screens {
                let mut app = app();
                setup(&mut app);
                let (texts, colors) = painted_output_for(&mut app, theme);
                let joined = texts.join("\n");
                for needle in required {
                    assert!(
                        texts.iter().any(|text| text.contains(needle)),
                        "{appearance} {screen} missing {needle:?} in {joined}"
                    );
                }
                assert_no_forbidden_hues(&colors, screen, appearance);
            }
        }
    }

    #[test]
    fn empty_and_populated_overview_are_evidenced_in_both_appearances() {
        for theme in [ThemePreference::Light, ThemePreference::Dark] {
            let appearance = match theme {
                ThemePreference::Light => "light",
                ThemePreference::Dark => "dark",
                ThemePreference::System => "system",
            };
            let mut empty = app();
            empty.show_welcome();
            let (texts, colors) = painted_window_for(&mut empty, theme);
            let joined = texts.join("\n");
            assert!(
                texts
                    .iter()
                    .any(|text| text.contains(crate::chrome::EMPTY_OVERVIEW_TITLE)),
                "{appearance} empty Overview missing title in {joined}"
            );
            assert!(
                texts
                    .iter()
                    .any(|text| text.contains(crate::chrome::EMPTY_OVERVIEW_PRIMARY)),
                "{appearance} empty Overview missing primary action in {joined}"
            );
            assert!(
                texts.iter().any(|text| text.contains("Settings")),
                "{appearance} chrome missing Settings in {joined}"
            );
            assert!(
                texts.iter().any(|text| text.contains("Exit")),
                "{appearance} chrome missing quiet Exit in {joined}"
            );
            assert!(
                !texts.iter().any(|text| text.trim() == "Recovery Review"),
                "{appearance} Recovery Review remained a permanent nav item in {joined}"
            );
            assert!(
                !joined.contains("in rhythm."),
                "{appearance} empty Overview kept marketing display type"
            );
            assert_no_forbidden_hues(&colors, "empty Overview", appearance);

            let mut populated = app_with_saved_profile();
            let (texts, colors) = painted_window_for(&mut populated, theme);
            let joined = texts.join("\n");
            assert!(
                texts.iter().any(|text| text.contains("Documents backup")),
                "{appearance} populated Overview missing Sync Profile in {joined}"
            );
            assert!(
                texts
                    .iter()
                    .any(|text| text.contains(crate::chrome::NO_SYNC_RUN_YET)),
                "{appearance} populated Overview missing last Sync Run in {joined}"
            );
            assert!(
                texts
                    .iter()
                    .any(|text| text.contains(crate::chrome::NEXT_ACTION_REVIEW_PLAN)),
                "{appearance} populated Overview missing next safe action in {joined}"
            );
            assert!(
                texts
                    .iter()
                    .any(|text| text.contains(crate::chrome::PRIMARY_SYNCHRONISE)),
                "{appearance} populated Overview missing Synchronise in {joined}"
            );
            assert!(
                !joined.contains("in rhythm.") && !joined.contains("A calmer way to"),
                "{appearance} populated Overview kept marketing display type"
            );
            assert_no_forbidden_hues(&colors, "populated Overview", appearance);
        }
    }

    #[test]
    fn quit_dialog_copy_keeps_recovery_review_and_inherits_appearance_tokens() {
        assert!(QUIT_ACTIVE_RUN_COPY.contains("Recovery Review"));
        assert!(QUIT_STOPPING_COPY.contains("Recovery Review"));
        let mut app = app();
        let context = egui::Context::default();
        for (theme, expected) in [
            (ThemePreference::Dark, BrandTheme::dark()),
            (ThemePreference::Light, BrandTheme::light()),
        ] {
            app.set_theme(theme);
            app.apply_theme(&context);
            context.all_styles_mut(|style| {
                assert_eq!(style.visuals.window_fill, expected.surface);
                assert_eq!(style.visuals.panel_fill, expected.canvas);
            });
        }
    }

    #[test]
    fn safety_copy_keeps_labels_and_does_not_rely_on_colour_alone() {
        assert_eq!(
            run_report_status_label(RunReportStatus::RecoveryReview),
            "Recovery Review required"
        );
        assert_eq!(
            run_report_status_label(RunReportStatus::Completed),
            "Completed"
        );
        assert_eq!(run_report_status_label(RunReportStatus::Blocked), "Blocked");
        assert!(run_recovery_message(RunReportStatus::Interrupted).contains("Recovery Review"));
        assert!(
            help_entry(HelpTopic::PlanAndConfirmation)
                .what
                .contains("Execution Confirmation")
        );
        assert!(
            help_entry(HelpTopic::Recovery)
                .title
                .contains("Recovery Review")
        );
        assert_eq!(PATH_RISK_WARNING_LABEL, "Path Risk Warning");
    }

    #[test]
    fn precheck_diagnostic_identifies_scope_and_safe_next_action() {
        let (mut form, _source, base) = filesystem_form();
        let missing = base.join("missing-source");
        form.peer_a.local_path = missing.display().to_string();
        let profile = form.build().expect("valid profile with unavailable source");
        let precheck = RunPrecheck::check(&profile, &LocalPrecheckProbe::default())
            .expect("precheck returns blockers");
        let blocker = precheck.blockers().first().expect("source blocker");

        let diagnostic = format_precheck_diagnostic(&profile, blocker);
        assert!(diagnostic.contains("Profile: Filesystem review"));
        assert!(diagnostic.contains("Peer: Source"));
        assert!(diagnostic.contains("Account: not applicable (local peer)"));
        assert!(diagnostic.contains("Scope:"));
        assert!(diagnostic.contains("Reason:"));
        assert!(diagnostic.contains("Next action:"));
        assert!(!diagnostic.contains("test-only-secret"));
        assert!(!diagnostic.contains("file-content-sentinel"));

        fs::remove_dir_all(base).expect("test directory cleanup");
    }

    #[test]
    fn ssh_precheck_message_identifies_peer_account_scope_and_next_action() {
        let mut form = valid_form();
        form.peer_b.kind = EndpointKind::Ssh;
        form.peer_b.server = "backup.example.com".to_owned();
        form.peer_b.username = "sync-user".to_owned();
        form.peer_b.remote_path = "/srv/backup".to_owned();
        form.peer_b.authentication = AuthenticationForm::Agent;
        let profile = form.build().expect("valid SSH profile");

        let message = SyncPlusApp::fresh_local_precheck(&profile)
            .expect_err("SSH precheck requires the typed SSH workflow");
        assert!(message.contains("Profile: Documents backup"));
        assert!(message.contains("Peer: Backup disk (account sync-user@backup.example.com:22)"));
        assert!(message.contains("Account: sync-user"));
        assert!(message.contains("Scope: /srv/backup"));
        assert!(message.contains("Reason:"));
        assert!(message.contains("Next action:"));
        assert!(!message.contains("test-only-secret"));
        assert!(!message.contains("private-key-material"));
        assert!(!message.contains("file-content-sentinel"));
    }
}
