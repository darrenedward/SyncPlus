use std::{
    fmt,
    fs,
    path::{Path, PathBuf},
};

use zeroize::Zeroize;

use crate::{SavedSecretReference, SshAuthentication, SshPeer};

/// The fixed service namespace used for SyncPlus credentials in the desktop
/// OS keyring. Profile data stores only the username/reference portion.
pub const SSH_KEYRING_SERVICE: &str = "org.syncplus.SyncPlus";

/// A short-lived password held only in memory while an SSH operation is
/// being prepared. Its formatting implementations are deliberately redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStoreError {
    Missing,
    Unavailable,
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Missing => "the selected saved SSH secret is not available",
            Self::Unavailable => "the desktop OS keyring is not available",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SecretStoreError {}

/// Storage boundary for saved SSH passwords. Implementations must store the
/// secret under the opaque reference and must never persist it elsewhere.
pub trait SecretStore {
    fn save(
        &self,
        reference: &SavedSecretReference,
        secret: &SecretValue,
    ) -> Result<(), SecretStoreError>;

    fn load(&self, reference: &SavedSecretReference) -> Result<SecretValue, SecretStoreError>;

    fn delete(&self, reference: &SavedSecretReference) -> Result<(), SecretStoreError>;
}

/// Desktop OS keyring implementation for saved SSH passwords.
#[derive(Debug, Clone, Copy, Default)]
pub struct DesktopKeyring;

impl DesktopKeyring {
    pub const fn new() -> Self {
        Self
    }

    pub const fn service_name(self) -> &'static str {
        SSH_KEYRING_SERVICE
    }

    fn entry(
        self,
        reference: &SavedSecretReference,
    ) -> Result<keyring::Entry, SecretStoreError> {
        keyring::Entry::new(SSH_KEYRING_SERVICE, reference.as_str()).map_err(map_keyring_error)
    }
}

impl SecretStore for DesktopKeyring {
    fn save(
        &self,
        reference: &SavedSecretReference,
        secret: &SecretValue,
    ) -> Result<(), SecretStoreError> {
        self.entry(reference)?
            .set_password(secret.as_str())
            .map_err(map_keyring_error)
    }

    fn load(&self, reference: &SavedSecretReference) -> Result<SecretValue, SecretStoreError> {
        self.entry(reference)
            .and_then(|entry| entry.get_password().map(SecretValue::new).map_err(map_keyring_error))
    }

    fn delete(&self, reference: &SavedSecretReference) -> Result<(), SecretStoreError> {
        self.entry(reference)?
            .delete_credential()
            .map_err(map_keyring_error)
    }
}

fn map_keyring_error(error: keyring::Error) -> SecretStoreError {
    if matches!(error, keyring::Error::NoEntry) {
        SecretStoreError::Missing
    } else {
        SecretStoreError::Unavailable
    }
}

/// The only supported source of an interactive SSH password. A GUI can
/// implement this trait with a controlled askpass dialog; stdin and command
/// arguments are intentionally not part of the interface.
pub trait AskpassProvider {
    fn prompt(&self, prompt: &str) -> Result<SecretValue, AskpassError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskpassError {
    Cancelled,
    Unavailable,
    Failed,
}

impl fmt::Display for AskpassError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Cancelled => "the SSH password prompt was cancelled",
            Self::Unavailable => "the controlled SSH password prompt is unavailable",
            Self::Failed => "the controlled SSH password prompt failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AskpassError {}

/// Availability checks used before a credential can authorize a run. The
/// default implementation checks only key-file accessibility and the agent
/// socket; it never reads private-key contents or attempts another method.
pub trait CredentialAvailability {
    fn identity_available(&self, identity: &Path) -> bool;

    fn agent_available(&self) -> bool;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCredentialAvailability;

impl CredentialAvailability for SystemCredentialAvailability {
    fn identity_available(&self, identity: &Path) -> bool {
        let Ok(metadata) = fs::metadata(identity) else {
            return false;
        };
        metadata.is_file() && fs::OpenOptions::new().read(true).open(identity).is_ok()
    }

    fn agent_available(&self) -> bool {
        let Some(socket) = std::env::var_os("SSH_AUTH_SOCK") else {
            return false;
        };
        let Ok(metadata) = fs::metadata(socket) else {
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;

            metadata.file_type().is_socket()
        }
        #[cfg(not(unix))]
        {
            metadata.is_file()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshRunMode {
    Interactive,
    Unattended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSource {
    InteractiveAskpass,
    SavedSecret,
}

/// A resolved credential containing only the selected authentication method.
/// There is deliberately no retry or fallback method in this type.
#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedSshCredential {
    Key { identity: PathBuf },
    Agent,
    Password { source: PasswordSource, secret: SecretValue },
}

impl fmt::Debug for ResolvedSshCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key { identity } => formatter
                .debug_struct("Key")
                .field("identity", identity)
                .finish(),
            Self::Agent => formatter.write_str("Agent"),
            Self::Password { source, .. } => formatter
                .debug_struct("Password")
                .field("source", source)
                .field("secret", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialResolutionError {
    IdentityNotSelected,
    IdentityUnavailable,
    AgentUnavailable,
    PromptRequiredForUnattended,
    InteractivePromptUnavailable,
    InteractivePromptCancelled,
    SavedSecretUnavailable,
}

impl fmt::Display for CredentialResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IdentityNotSelected => {
                "SSH key authentication is selected but no identity file was configured"
            }
            Self::IdentityUnavailable => {
                "the selected SSH identity file is unavailable or unreadable"
            }
            Self::AgentUnavailable => {
                "SSH agent authentication is selected but no available SSH agent was found"
            }
            Self::PromptRequiredForUnattended => {
                "unattended SSH run requires a noninteractive credential; interactive password authentication is unavailable"
            }
            Self::InteractivePromptUnavailable => {
                "the controlled SSH password prompt is unavailable"
            }
            Self::InteractivePromptCancelled => "the controlled SSH password prompt was cancelled",
            Self::SavedSecretUnavailable => {
                "the selected saved SSH credential is unavailable; no authentication fallback was attempted"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CredentialResolutionError {}

/// Resolves exactly the authentication method selected on an SSH peer.
/// Failures stop the run; this type intentionally does not contain fallback
/// configuration or retry another credential.
pub struct CredentialResolver<S> {
    secret_store: S,
    availability: Box<dyn CredentialAvailability>,
}

impl<S> CredentialResolver<S> {
    pub fn new(secret_store: S) -> Self {
        Self::with_availability(secret_store, SystemCredentialAvailability)
    }

    pub fn with_availability<A: CredentialAvailability + 'static>(
        secret_store: S,
        availability: A,
    ) -> Self {
        Self {
            secret_store,
            availability: Box::new(availability),
        }
    }

    pub fn secret_store(&self) -> &S {
        &self.secret_store
    }
}

impl<S: SecretStore> CredentialResolver<S> {
    pub fn resolve(
        &self,
        peer: &SshPeer,
        mode: SshRunMode,
        askpass: Option<&dyn AskpassProvider>,
    ) -> Result<ResolvedSshCredential, CredentialResolutionError> {
        match peer.authentication() {
            SshAuthentication::Key => {
                let identity = peer
                    .identity()
                    .ok_or(CredentialResolutionError::IdentityNotSelected)?;
                if !self.availability.identity_available(identity) {
                    return Err(CredentialResolutionError::IdentityUnavailable);
                }
                Ok(ResolvedSshCredential::Key {
                    identity: identity.to_path_buf(),
                })
            }
            SshAuthentication::Agent => {
                if !self.availability.agent_available() {
                    return Err(CredentialResolutionError::AgentUnavailable);
                }
                Ok(ResolvedSshCredential::Agent)
            }
            SshAuthentication::InteractivePassword => {
                if mode == SshRunMode::Unattended {
                    return Err(CredentialResolutionError::PromptRequiredForUnattended);
                }
                let provider = askpass.ok_or(CredentialResolutionError::InteractivePromptUnavailable)?;
                let secret = provider.prompt("SSH password").map_err(|error| match error {
                    AskpassError::Cancelled => CredentialResolutionError::InteractivePromptCancelled,
                    AskpassError::Unavailable | AskpassError::Failed => {
                        CredentialResolutionError::InteractivePromptUnavailable
                    }
                })?;
                Ok(ResolvedSshCredential::Password {
                    source: PasswordSource::InteractiveAskpass,
                    secret,
                })
            }
            SshAuthentication::SavedPassword(reference) => {
                let secret = self
                    .secret_store
                    .load(&reference)
                    .map_err(|_| CredentialResolutionError::SavedSecretUnavailable)?;
                Ok(ResolvedSshCredential::Password {
                    source: PasswordSource::SavedSecret,
                    secret,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::{atomic::{AtomicUsize, Ordering}, Mutex},
    };

    use crate::{
        AskpassError, AskpassProvider, CredentialAvailability, CredentialResolutionError,
        CredentialResolver, PasswordSource, Peer, ProcessSpecification, ResolvedSshCredential,
        SavedSecretReference, SecretStore, SecretStoreError, SecretValue, SshAuthentication,
        SshPeer, SshRunMode, SyncProfile,
    };

    #[derive(Default)]
    struct FakeSecretStore {
        values: Mutex<HashMap<String, SecretValue>>,
        fail_load: bool,
    }

    impl SecretStore for FakeSecretStore {
        fn save(
            &self,
            reference: &SavedSecretReference,
            secret: &SecretValue,
        ) -> Result<(), SecretStoreError> {
            self.values
                .lock()
                .expect("fake store lock")
                .insert(reference.as_str().to_owned(), secret.clone());
            Ok(())
        }

        fn load(&self, reference: &SavedSecretReference) -> Result<SecretValue, SecretStoreError> {
            if self.fail_load {
                return Err(SecretStoreError::Unavailable);
            }
            self.values
                .lock()
                .expect("fake store lock")
                .get(reference.as_str())
                .cloned()
                .ok_or(SecretStoreError::Missing)
        }

        fn delete(&self, reference: &SavedSecretReference) -> Result<(), SecretStoreError> {
            self.values
                .lock()
                .expect("fake store lock")
                .remove(reference.as_str());
            Ok(())
        }
    }

    struct FakeAskpass {
        calls: AtomicUsize,
        response: Mutex<Result<SecretValue, AskpassError>>,
    }

    impl FakeAskpass {
        fn returning(response: Result<SecretValue, AskpassError>) -> Self {
            Self { calls: AtomicUsize::new(0), response: Mutex::new(response) }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl AskpassProvider for FakeAskpass {
        fn prompt(&self, _prompt: &str) -> Result<SecretValue, AskpassError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.response.lock().expect("fake prompt lock").clone()
        }
    }

    #[derive(Default)]
    struct FakeCredentialAvailability {
        identity_available: bool,
        agent_available: bool,
    }

    impl CredentialAvailability for FakeCredentialAvailability {
        fn identity_available(&self, _identity: &std::path::Path) -> bool {
            self.identity_available
        }

        fn agent_available(&self) -> bool {
            self.agent_available
        }
    }

    fn peer(authentication: SshAuthentication, identity: Option<PathBuf>) -> SshPeer {
        SshPeer::new(
            "backup.example.test",
            "sync-user",
            2222,
            identity,
            authentication,
            "/srv/sync",
        )
        .expect("SSH fixture should be valid")
    }

    #[test]
    fn key_authentication_is_the_default_and_returns_only_the_selected_identity() {
        assert_eq!(SshAuthentication::default(), SshAuthentication::Key);

        let identity = std::env::current_exe().expect("the test executable should be available");
        let ssh_peer = peer(SshAuthentication::Key, Some(identity.clone()));
        let resolver = CredentialResolver::new(FakeSecretStore::default());

        assert_eq!(
            resolver.resolve(&ssh_peer, SshRunMode::Unattended, None),
            Ok(ResolvedSshCredential::Key { identity }),
        );
    }

    #[test]
    fn interactive_password_uses_controlled_askpass_and_redacts_secret_material() {
        let prompt = FakeAskpass::returning(Ok(SecretValue::new("not-for-logs")));
        let resolver = CredentialResolver::new(FakeSecretStore::default());
        let ssh_peer = peer(SshAuthentication::InteractivePassword, None);

        let credential = resolver
            .resolve(&ssh_peer, SshRunMode::Interactive, Some(&prompt))
            .expect("interactive askpass should resolve");

        assert!(matches!(
            credential,
            ResolvedSshCredential::Password { source: PasswordSource::InteractiveAskpass, .. }
        ));
        assert_eq!(prompt.calls(), 1);
        assert!(!format!("{credential:?}").contains("not-for-logs"));
    }

    #[test]
    fn unattended_interactive_password_stops_without_invoking_a_prompt() {
        let prompt = FakeAskpass::returning(Ok(SecretValue::new("not-for-logs")));
        let resolver = CredentialResolver::new(FakeSecretStore::default());
        let ssh_peer = peer(SshAuthentication::InteractivePassword, None);

        let error = resolver
            .resolve(&ssh_peer, SshRunMode::Unattended, Some(&prompt))
            .expect_err("unattended runs must not prompt");

        assert_eq!(error, CredentialResolutionError::PromptRequiredForUnattended);
        assert_eq!(prompt.calls(), 0);
        assert!(error.to_string().contains("noninteractive credential"));
    }

    #[test]
    fn saved_password_loads_from_a_secret_store_using_only_an_opaque_reference() {
        let reference = SavedSecretReference::new("backup-password").expect("valid reference");
        let store = FakeSecretStore::default();
        store
            .save(&reference, &SecretValue::new("not-for-logs"))
            .expect("fake store save");
        let resolver = CredentialResolver::new(store);
        let ssh_peer = peer(SshAuthentication::SavedPassword(reference.clone()), None);

        let credential = resolver
            .resolve(&ssh_peer, SshRunMode::Unattended, None)
            .expect("saved password should be available");

        assert!(matches!(
            credential,
            ResolvedSshCredential::Password { source: PasswordSource::SavedSecret, .. }
        ));
        assert!(!format!("{ssh_peer:?}").contains("not-for-logs"));
        assert!(!format!("{credential:?}").contains("not-for-logs"));
    }

    #[test]
    fn selected_key_failure_does_not_fall_back_to_agent_or_password() {
        let prompt = FakeAskpass::returning(Ok(SecretValue::new("not-for-logs")));
        let resolver = CredentialResolver::with_availability(
            FakeSecretStore::default(),
            FakeCredentialAvailability::default(),
        );
        let ssh_peer = peer(
            SshAuthentication::Key,
            Some(PathBuf::from("/home/user/.ssh/id_sync")),
        );

        assert_eq!(
            resolver.resolve(&ssh_peer, SshRunMode::Unattended, Some(&prompt)),
            Err(CredentialResolutionError::IdentityUnavailable),
        );
        assert_eq!(prompt.calls(), 0);
    }

    #[test]
    fn unavailable_identity_is_reported_before_authentication_can_start() {
        let identity = PathBuf::from("/home/user/.ssh/id_sync");
        let resolver = CredentialResolver::with_availability(
            FakeSecretStore::default(),
            FakeCredentialAvailability::default(),
        );
        let ssh_peer = peer(SshAuthentication::Key, Some(identity));

        assert_eq!(
            resolver.resolve(&ssh_peer, SshRunMode::Unattended, None),
            Err(CredentialResolutionError::IdentityUnavailable),
        );
    }

    #[test]
    fn unavailable_agent_is_reported_without_key_or_password_fallback() {
        let resolver = CredentialResolver::with_availability(
            FakeSecretStore::default(),
            FakeCredentialAvailability::default(),
        );
        let prompt = FakeAskpass::returning(Ok(SecretValue::new("not-for-logs")));
        let ssh_peer = peer(SshAuthentication::Agent, None);

        assert_eq!(
            resolver.resolve(&ssh_peer, SshRunMode::Unattended, Some(&prompt)),
            Err(CredentialResolutionError::AgentUnavailable),
        );
        assert_eq!(prompt.calls(), 0);
    }

    #[test]
    fn system_identity_probe_does_not_read_private_key_contents() {
        let identity = std::env::current_exe().expect("the test executable should be available");

        assert!(
            crate::SystemCredentialAvailability.identity_available(&identity),
            "an accessible regular file should be available as a selected identity"
        );
    }

    #[test]
    fn saved_secret_failure_is_reported_without_prompt_fallback() {
        let reference = SavedSecretReference::new("backup-password").expect("valid reference");
        let store = FakeSecretStore { values: Mutex::new(HashMap::new()), fail_load: true };
        let resolver = CredentialResolver::new(store);
        let prompt = FakeAskpass::returning(Ok(SecretValue::new("not-for-logs")));
        let ssh_peer = peer(SshAuthentication::SavedPassword(reference), None);

        assert_eq!(
            resolver.resolve(&ssh_peer, SshRunMode::Unattended, Some(&prompt)),
            Err(CredentialResolutionError::SavedSecretUnavailable),
        );
        assert_eq!(prompt.calls(), 0);
    }

    #[test]
    fn askpass_cancellation_stops_without_authentication_fallback() {
        let prompt = FakeAskpass::returning(Err(AskpassError::Cancelled));
        let resolver = CredentialResolver::new(FakeSecretStore::default());
        let ssh_peer = peer(SshAuthentication::InteractivePassword, None);

        assert_eq!(
            resolver.resolve(&ssh_peer, SshRunMode::Interactive, Some(&prompt)),
            Err(CredentialResolutionError::InteractivePromptCancelled),
        );
        assert_eq!(prompt.calls(), 1);
    }

    #[test]
    fn saved_secret_reference_never_enters_the_process_preview_as_secret_material() {
        let reference = SavedSecretReference::new("backup-password").expect("valid reference");
        let ssh = Peer::from_ssh(
            "SSH peer",
            peer(SshAuthentication::SavedPassword(reference), None),
        );
        let profile = SyncProfile::new("SSH profile", Peer::new("Local", "/source".into()), ssh);
        let specification = ProcessSpecification::from_profile(&profile).expect("valid profile");

        assert!(!specification.preview().contains("not-for-logs"));
    }
}
