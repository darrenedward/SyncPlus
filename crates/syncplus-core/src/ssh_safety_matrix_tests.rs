use std::{
    ffi::{OsStr, OsString},
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AccessSnapshot, ContentProof, FreshAnalysis, HostTrustMode, OneWaySource, Peer,
    AskpassError, AskpassProvider, CredentialResolver, DesktopKeyring, ProcessInvocation,
    ProcessSpecError, ProcessSpecification, RecoveryEvidence,
    RemotePrecheckObservation, RemotePrecheckRequest, RemoteRsyncCapability,
    RemoteSha256Capability, RemoteTrashCapability, ResolvedSshCredential, RunEvidenceStore,
    SshAuthentication, SshHostFingerprint, SshHostIdentityError, SshHostIdentityProbe,
    SshHostTrustController, SshPeer, SshRemotePrecheckProbe, SshRunBackend, SshRunError,
    SshTransferEvidence, SshTransferRequest, SourceInventory, SyncProfile,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct DisposableSshPeer {
    root: PathBuf,
    remote_root: PathBuf,
    identity: PathBuf,
    known_hosts: PathBuf,
    peer: SshPeer,
    fingerprint: SshHostFingerprint,
    server: Child,
}

impl DisposableSshPeer {
    fn start() -> Result<Self, String> {
        let root = unique_temp_path("syncplus-ssh-matrix");
        fs::create_dir(&root).map_err(|error| format!("create SSH fixture: {error}"))?;
        let result = Self::start_in_root(root.clone());
        if result.is_err() {
            let _ = fs::remove_dir_all(root);
        }
        result
    }

    fn start_in_root(root: PathBuf) -> Result<Self, String> {
        let identity = root.join("client_ed25519");
        let host_key = root.join("host_ed25519");
        let known_hosts = root.join("known_hosts");
        let authorized_keys = root.join("authorized_keys");
        let config = root.join("sshd_config");
        let pid_file = root.join("sshd.pid");
        let log_file = root.join("sshd.log");
        let remote_root = root.join("remote root 世界");
        fs::create_dir(&remote_root).map_err(|error| format!("create remote root: {error}"))?;

        run_checked(
            "ssh-keygen",
            [
                OsString::from("-q"),
                OsString::from("-t"),
                OsString::from("ed25519"),
                OsString::from("-N"),
                OsString::new(),
                OsString::from("-f"),
                identity.as_os_str().to_os_string(),
            ],
        )?;
        run_checked(
            "ssh-keygen",
            [
                OsString::from("-q"),
                OsString::from("-t"),
                OsString::from("ed25519"),
                OsString::from("-N"),
                OsString::new(),
                OsString::from("-f"),
                host_key.as_os_str().to_os_string(),
            ],
        )?;

        let client_public = fs::read_to_string(identity.with_extension("pub"))
            .map_err(|error| format!("read client public key: {error}"))?;
        fs::write(&authorized_keys, client_public)
            .map_err(|error| format!("write authorized keys: {error}"))?;
        let host_public = fs::read_to_string(host_key.with_extension("pub"))
            .map_err(|error| format!("read host public key: {error}"))?;
        let mut host_fields = host_public.split_whitespace();
        let host_algorithm = host_fields
            .next()
            .ok_or_else(|| "host public key has no algorithm".to_owned())?;
        let host_key_data = host_fields
            .next()
            .ok_or_else(|| "host public key has no key data".to_owned())?;
        let port = free_port()?;
        fs::write(
            &known_hosts,
            format!("[127.0.0.1]:{port} {host_algorithm} {host_key_data}\n"),
        )
        .map_err(|error| format!("write temporary known-hosts file: {error}"))?;

        let username = std::env::var("USER").map_err(|_| "USER is unavailable".to_owned())?;
        if username.is_empty() {
            return Err("USER is empty".to_owned());
        }
        fs::write(
            &config,
            format!(
                "Port {port}\n\
                 ListenAddress 127.0.0.1\n\
                 HostKey {}\n\
                 AuthorizedKeysFile {}\n\
                 PubkeyAuthentication yes\n\
                 PasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 PermitUserEnvironment no\n\
                 AllowUsers {username}\n\
                 PidFile {}\n\
                 LogLevel ERROR\n",
                config_word(&host_key),
                config_word(&authorized_keys),
                config_word(&pid_file),
            ),
        )
        .map_err(|error| format!("write sshd config: {error}"))?;

        let mut server = Command::new("/usr/sbin/sshd")
            .args([OsStr::new("-D"), OsStr::new("-E")])
            .arg(&log_file)
            .args([OsStr::new("-f")])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("start disposable sshd: {error}"))?;
        if let Err(error) = wait_for_server(&mut server, port) {
            stop_server(&mut server);
            let detail = fs::read_to_string(&log_file).unwrap_or_default();
            return Err(format!("{error}: {detail}"));
        }

        let peer = match SshPeer::new(
            "127.0.0.1",
            username,
            port,
            Some(identity.clone()),
            SshAuthentication::Key,
            remote_root.to_string_lossy().to_string(),
        ) {
            Ok(peer) => peer,
            Err(error) => {
                stop_server(&mut server);
                return Err(format!("construct SSH peer: {error}"));
            }
        };
        Ok(Self {
            root,
            remote_root,
            identity,
            known_hosts,
            peer,
            fingerprint: SshHostFingerprint::sha256([7; 32]),
            server,
        })
    }

    fn peer(&self) -> &SshPeer {
        &self.peer
    }

    fn strict_ssh_arguments(&self) -> Vec<OsString> {
        vec![
            OsString::from("-p"),
            OsString::from(self.peer.port().to_string()),
            OsString::from("-i"),
            self.identity.as_os_str().to_os_string(),
            OsString::from("-o"),
            OsString::from("IdentitiesOnly=yes"),
            OsString::from("-o"),
            OsString::from("IdentityAgent=none"),
            OsString::from("-o"),
            OsString::from("PreferredAuthentications=publickey"),
            OsString::from("-o"),
            OsString::from("PasswordAuthentication=no"),
            OsString::from("-o"),
            OsString::from("KbdInteractiveAuthentication=no"),
            OsString::from("-o"),
            OsString::from(format!("UserKnownHostsFile={}", self.known_hosts.display())),
            OsString::from("-o"),
            OsString::from("StrictHostKeyChecking=yes"),
            OsString::from(format!(
                "{}@{}",
                self.peer.username(),
                self.peer.server()
            )),
        ]
    }

    fn run_ssh(&self, remote_command: String) -> Result<Output, String> {
        let mut arguments = self.strict_ssh_arguments();
        arguments.push(OsString::from(remote_command));
        Command::new("ssh")
            .args(arguments)
            .output()
            .map_err(|error| format!("run controlled SSH command: {error}"))
    }

    fn run_rsync(&self, invocation: &ProcessInvocation) -> Result<Output, String> {
        let mut arguments = invocation.arguments().to_vec();
        let known_hosts_option = format!(
            " -o UserKnownHostsFile={} -o StrictHostKeyChecking=yes",
            shell_word(&self.known_hosts)
        );
        let mut found_transport = false;
        for argument in &mut arguments {
            if let Some(transport) = argument.to_str().filter(|value| value.starts_with("--rsh=ssh ")) {
                let mut secured = transport.to_owned();
                secured.push_str(&known_hosts_option);
                *argument = OsString::from(secured);
                found_transport = true;
            }
        }
        if !found_transport {
            return Err("core invocation did not contain its SSH transport".to_owned());
        }
        Command::new(invocation.program())
            .args(arguments)
            .output()
            .map_err(|error| format!("run core-generated rsync invocation: {error}"))
    }

    fn remote_sha256(&self, path: &Path) -> Result<[u8; 32], String> {
        let output = self.run_ssh(format!("sha256sum -- {}", shell_word(path)))?;
        if !output.status.success() {
            return Err(format!("remote SHA-256 helper failed with {}", output.status));
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| "remote SHA-256 helper returned non-UTF-8 output".to_owned())?;
        let digest = text
            .split_whitespace()
            .next()
            .ok_or_else(|| "remote SHA-256 helper returned no digest".to_owned())?;
        let digest = digest.strip_prefix('\\').unwrap_or(digest);
        parse_digest(digest).map_err(|error| {
            format!(
                "{error}; helper output shape was {:?}",
                text.lines().next().unwrap_or_default()
            )
        })
    }

    fn install_remote(&self, staging: &Path, destination: &Path) -> Result<(), String> {
        let output = self.run_ssh(format!(
            "mv -- {} {}",
            shell_word(staging),
            shell_word(destination)
        ))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("remote staging install failed with {}", output.status))
        }
    }
}

impl Drop for DisposableSshPeer {
    fn drop(&mut self) {
        stop_server(&mut self.server);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stop_server(server: &mut Child) {
    let _ = server.kill();
    let _ = server.wait();
}

struct FixedHostProbe(SshHostFingerprint);

impl SshHostIdentityProbe for FixedHostProbe {
    fn probe(&self, _peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError> {
        Ok(self.0)
    }
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn free_port() -> Result<u16, String> {
    TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("reserve disposable SSH port: {error}"))
        .and_then(|listener| {
            listener
                .local_addr()
                .map(|address| address.port())
                .map_err(|error| format!("read disposable SSH port: {error}"))
        })
}

fn wait_for_server(server: &mut Child, port: u16) -> Result<(), String> {
    let started = std::time::Instant::now();
    while started.elapsed() < TEST_TIMEOUT {
        if let Some(status) = server
            .try_wait()
            .map_err(|error| format!("poll disposable sshd: {error}"))?
        {
            return Err(format!("disposable sshd exited with {status}"));
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for disposable sshd".to_owned())
}

fn run_checked<I>(program: &str, arguments: I) -> Result<(), String>
where
    I: IntoIterator<Item = OsString>,
{
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {}", output.status))
    }
}

fn config_word(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '_' | '-'))
    {
        value.into_owned()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn shell_word(path: &Path) -> String {
    let mut value = String::from("'");
    for character in path.to_string_lossy().chars() {
        if character == '\'' {
            value.push_str("'\\''");
        } else {
            value.push(character);
        }
    }
    value.push('\'');
    value
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("remote SHA-256 helper returned an invalid digest".to_owned());
    }
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hexadecimal digest".to_owned()),
    }
}

fn local_plan(source: &Path, destination: &Path, source_side: OneWaySource) -> SyncProfile {
    SyncProfile::new(
        "disposable SSH plan",
        Peer::new("Peer A", source.to_path_buf()),
        Peer::new("Peer B", destination.to_path_buf()),
    )
    .with_source(source_side)
}

fn ssh_profile(local: &Path, peer: &SshPeer, source_is_remote: bool) -> SyncProfile {
    SyncProfile::new(
        "disposable SSH run",
        Peer::new("local", local.to_path_buf()),
        Peer::from_ssh("SSH peer", peer.clone()),
    )
    .with_source(if source_is_remote {
        OneWaySource::PeerB
    } else {
        OneWaySource::PeerA
    })
}

struct BlockingSshBackend {
    fingerprint: SshHostFingerprint,
    observation: RemotePrecheckObservation,
    backend_operations: Arc<AtomicUsize>,
}

impl SshHostIdentityProbe for BlockingSshBackend {
    fn probe(&self, _peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError> {
        Ok(self.fingerprint)
    }
}

impl crate::SshRemotePrecheckProbe for BlockingSshBackend {
    fn probe(
        &self,
        _peer: &SshPeer,
        _credential: &ResolvedSshCredential,
        _host_permit: &crate::SshHostTrustPermit,
        _request: &RemotePrecheckRequest,
    ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
        Ok(self.observation.clone())
    }
}

impl SshRunBackend for BlockingSshBackend {
    fn inventory(
        &self,
        _peer: &SshPeer,
        _credential: &ResolvedSshCredential,
        _host_permit: &crate::SshHostTrustPermit,
        _exclusions: &[String],
    ) -> Result<SourceInventory, SshRunError> {
        self.backend_operations.fetch_add(1, Ordering::Relaxed);
        Err(SshRunError::RemoteUnavailable)
    }

    fn transfer(
        &self,
        _request: &SshTransferRequest<'_>,
        _should_cancel: &dyn Fn() -> bool,
        _progress: &mut dyn FnMut(u64),
    ) -> Result<SshTransferEvidence, SshRunError> {
        self.backend_operations.fetch_add(1, Ordering::Relaxed);
        Err(SshRunError::RemoteUnavailable)
    }

    fn recover_source(
        &self,
        _request: &SshTransferRequest<'_>,
        _transfer: &SshTransferEvidence,
        _should_cancel: &dyn Fn() -> bool,
    ) -> Result<RecoveryEvidence, SshRunError> {
        self.backend_operations.fetch_add(1, Ordering::Relaxed);
        Err(SshRunError::RemoteRecoveryFailed {
            boundary: crate::SshRecoveryBoundary::BeforeRecovery,
            evidence: None,
        })
    }
}

struct PassingRemoteProbe;

impl SshRemotePrecheckProbe for PassingRemoteProbe {
    fn probe(
        &self,
        _peer: &SshPeer,
        _credential: &ResolvedSshCredential,
        _host_permit: &crate::SshHostTrustPermit,
        _request: &RemotePrecheckRequest,
    ) -> Result<RemotePrecheckObservation, crate::PrecheckError> {
        Ok(RemotePrecheckObservation::new(
            true,
            AccessSnapshot::new(true, true, true),
            RemoteRsyncCapability::Compatible,
            RemoteSha256Capability::Available,
            RemoteTrashCapability::verified("/srv/.syncplus-trash")
                .expect("test Trash location should be valid"),
        ))
    }
}

struct FixedPasswordPrompt;

impl AskpassProvider for FixedPasswordPrompt {
    fn prompt(&self, _prompt: &str) -> Result<crate::SecretValue, AskpassError> {
        Ok(crate::SecretValue::new("password-never-logged"))
    }
}

#[test]
fn interactive_password_auth_uses_the_selected_method_and_redacts_the_secret() {
    let peer = SshPeer::new(
        "backup.example.test",
        "sync-user",
        2222,
        None,
        SshAuthentication::InteractivePassword,
        "/srv/sync",
    )
    .expect("password SSH fixture should be valid");
    let credential = CredentialResolver::new(DesktopKeyring::new())
        .resolve(
            &peer,
            crate::SshRunMode::Interactive,
            Some(&FixedPasswordPrompt),
        )
        .expect("interactive askpass should resolve");
    assert!(matches!(
        credential,
        ResolvedSshCredential::Password {
            source: crate::PasswordSource::InteractiveAskpass,
            ..
        }
    ));
    assert!(!format!("{credential:?}").contains("password-never-logged"));

    let profile = SyncProfile::new(
        "interactive password",
        Peer::new("local", PathBuf::from("/tmp/source")),
        Peer::from_ssh("SSH peer", peer),
    );
    let specification = ProcessSpecification::from_profile(&profile)
        .expect("password SSH specification should be valid");
    let invocation = specification
        .invocation()
        .expect("password One-Way invocation should be valid");
    assert!(invocation.arguments().iter().any(|argument| {
        argument.to_string_lossy().contains("PreferredAuthentications=keyboard-interactive,password")
    }));
    assert!(!specification.preview().contains("password-never-logged"));
}

fn approved_remote_permit(
    profile: &SyncProfile,
    peer: &SshPeer,
    fingerprint: SshHostFingerprint,
) -> (ResolvedSshCredential, crate::SshHostTrustPermit, crate::RemotePrecheckPermit) {
    let credential = ResolvedSshCredential::Key {
        identity: peer
            .identity()
            .expect("key fixture should have an identity")
            .to_path_buf(),
    };
    let mut controller = SshHostTrustController::new(
        RunEvidenceStore::open_in_memory().expect("trust store should open"),
    );
    let host_probe = FixedHostProbe(fingerprint);
    let decision = controller
        .inspect(peer, &host_probe)
        .expect("host identity inspection should succeed");
    controller
        .approve(peer, &decision, HostTrustMode::Interactive)
        .expect("host approval should succeed");
    let host_permit = controller
        .pre_mutation_permit(peer, &host_probe)
        .expect("host permit should be available");
    let (_, request) = RemotePrecheckRequest::from_profile(profile)
        .expect("SSH profile should have a remote precheck request");
    let permit = crate::SshRemotePrecheck::check(
        peer,
        &credential,
        &host_permit,
        &request,
        &PassingRemoteProbe,
    )
    .expect("passing remote precheck should complete")
    .require_passed()
    .expect("passing remote precheck should yield a permit");
    (credential, host_permit, permit)
}

#[test]
fn remote_precheck_failures_stop_before_any_backend_mutation() {
    let root = unique_temp_path("syncplus-ssh-blocked");
    let local = root.join("local");
    fs::create_dir_all(&local).expect("local fixture should be creatable");
    let peer = SshPeer::new(
        "backup.example.test",
        "sync-user",
        2222,
        Some(PathBuf::from("/keys/syncplus")),
        SshAuthentication::Key,
        "/srv/sync",
    )
    .expect("SSH fixture should be valid");
    let profile = ssh_profile(&local, &peer, false);
    let expected_fingerprint = SshHostFingerprint::sha256([7; 32]);
    let (credential, host_permit, precheck) =
        approved_remote_permit(&profile, &peer, expected_fingerprint);

    let observations = [
        (
            "credentials",
            RemotePrecheckObservation::new(
                false,
                AccessSnapshot::new(true, true, true),
                RemoteRsyncCapability::Compatible,
                RemoteSha256Capability::Available,
                RemoteTrashCapability::unavailable(),
            ),
        ),
        (
            "permissions",
            RemotePrecheckObservation::new(
                true,
                AccessSnapshot::new(true, false, true),
                RemoteRsyncCapability::Compatible,
                RemoteSha256Capability::Available,
                RemoteTrashCapability::unavailable(),
            ),
        ),
        (
            "rsync",
            RemotePrecheckObservation::new(
                true,
                AccessSnapshot::new(true, true, true),
                RemoteRsyncCapability::Missing,
                RemoteSha256Capability::Available,
                RemoteTrashCapability::unavailable(),
            ),
        ),
        (
            "hash",
            RemotePrecheckObservation::new(
                true,
                AccessSnapshot::new(true, true, true),
                RemoteRsyncCapability::Compatible,
                RemoteSha256Capability::Unavailable,
                RemoteTrashCapability::unavailable(),
            ),
        ),
    ];

    for (name, observation) in observations {
        let backend_operations = Arc::new(AtomicUsize::new(0));
        let backend = BlockingSshBackend {
            fingerprint: expected_fingerprint,
            observation,
            backend_operations: backend_operations.clone(),
        };
        let result = crate::RunWorkflow::new(crate::RecoveryMethod::trash(root.join("trash")))
            .execute_ssh(
                crate::RunId::new(1),
                &profile,
                &credential,
                &host_permit,
                &precheck,
                &backend,
                |_| true,
                &mut RunEvidenceStore::open_in_memory().expect("evidence store should open"),
                || false,
            );
        assert!(result.is_err(), "{name} failure must block the run");
        assert_eq!(
            backend_operations.load(Ordering::Relaxed),
            0,
            "{name} failure must stop before inventory or transfer"
        );
    }

    let backend_operations = Arc::new(AtomicUsize::new(0));
    let changed_host = BlockingSshBackend {
        fingerprint: SshHostFingerprint::sha256([8; 32]),
        observation: RemotePrecheckObservation::new(
            true,
            AccessSnapshot::new(true, true, true),
            RemoteRsyncCapability::Compatible,
            RemoteSha256Capability::Available,
            RemoteTrashCapability::unavailable(),
        ),
        backend_operations: backend_operations.clone(),
    };
    let result = crate::RunWorkflow::new(crate::RecoveryMethod::trash(root.join("trash")))
        .execute_ssh(
            crate::RunId::new(2),
            &profile,
            &credential,
            &host_permit,
            &precheck,
            &changed_host,
            |_| true,
            &mut RunEvidenceStore::open_in_memory().expect("evidence store should open"),
            || false,
        );
    assert!(result.is_err(), "changed host identity must block the run");
    assert_eq!(backend_operations.load(Ordering::Relaxed), 0);

    let wrong_credential = ResolvedSshCredential::Agent;
    let backend_operations = Arc::new(AtomicUsize::new(0));
    let backend = BlockingSshBackend {
        fingerprint: expected_fingerprint,
        observation: RemotePrecheckObservation::new(
            true,
            AccessSnapshot::new(true, true, true),
            RemoteRsyncCapability::Compatible,
            RemoteSha256Capability::Available,
            RemoteTrashCapability::unavailable(),
        ),
        backend_operations: backend_operations.clone(),
    };
    let result = crate::RunWorkflow::new(crate::RecoveryMethod::trash(root.join("trash")))
        .execute_ssh(
            crate::RunId::new(3),
            &profile,
            &wrong_credential,
            &host_permit,
            &precheck,
            &backend,
            |_| true,
            &mut RunEvidenceStore::open_in_memory().expect("evidence store should open"),
            || false,
        );
    assert!(result.is_err(), "credential mismatch must block the run");
    assert_eq!(backend_operations.load(Ordering::Relaxed), 0);

    let _ = fs::remove_dir_all(root);
}

fn assert_success(output: Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed with {}; stderr was {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "release gate: requires sshd, ssh-keygen, ssh, and rsync"]
fn disposable_ssh_peer_exercises_push_pull_strict_identity_and_hostile_paths() {
    let peer = DisposableSshPeer::start().expect("disposable SSH peer should start");
    let relative = PathBuf::from("$(touch pwned); user's\nreport 世界\t.txt");
    let local_source = peer.root.join("local source with spaces");
    let local_destination = peer.root.join("local destination with spaces");
    fs::create_dir(&local_source).expect("local source should be creatable");
    fs::create_dir(&local_destination).expect("local destination should be creatable");
    let source_path = local_source.join(&relative);
    let content = b"real disposable SSH transfer";
    if let Some(parent) = source_path.parent() {
        fs::create_dir_all(parent).expect("source parent should be creatable");
    }
    fs::write(&source_path, content).expect("source should be writable");

    let mut trust = SshHostTrustController::new(
        RunEvidenceStore::open_in_memory().expect("trust store should open"),
    );
    let first_use = trust
        .inspect(peer.peer(), &FixedHostProbe(peer.fingerprint))
        .expect("first-use probe should complete");
    assert!(!first_use.is_approved());
    assert!(trust.pre_mutation_permit(peer.peer(), &FixedHostProbe(peer.fingerprint)).is_err());
    trust
        .approve(peer.peer(), &first_use, HostTrustMode::Interactive)
        .expect("explicit host approval should succeed");
    trust
        .pre_mutation_permit(peer.peer(), &FixedHostProbe(peer.fingerprint))
        .expect("approved fingerprint should permit the run");
    assert!(trust
        .pre_mutation_permit(peer.peer(), &FixedHostProbe(SshHostFingerprint::sha256([8; 32])))
        .is_err());

    let plan = FreshAnalysis::analyze(&local_plan(
        &local_source,
        &peer.remote_root,
        OneWaySource::PeerA,
    ))
    .expect("local plan should be analyzable");
    let action = plan
        .plan()
        .action_for(&relative)
        .expect("hostile path should be included in the plan")
        .clone();
    let push_spec = ProcessSpecification::from_profile(&ssh_profile(local_source.as_path(), peer.peer(), false))
        .expect("push SSH specification should be valid");
    let remote_destination = peer.remote_root.join(&relative);
    let remote_staging = peer.remote_root.join(".syncplus-e2e-staging");
    let push_invocation = push_spec
        .ssh_item_invocation_to(&action, &remote_staging)
        .expect("push invocation should use the typed SSH path boundary");
    assert!(push_invocation.preview().contains("\\n"));
    assert!(push_invocation
        .arguments()
        .iter()
        .filter_map(|argument| argument.to_str())
        .any(|argument| argument.contains("$(touch pwned)")));
    assert_success(peer.run_rsync(&push_invocation).expect("push should run"), "SSH push");
    peer.install_remote(&remote_staging, &remote_destination)
        .expect("remote staging install should succeed");
    assert_eq!(
        peer.remote_sha256(&remote_destination).expect("remote digest"),
        *ContentProof::from_path(&source_path)
            .expect("source digest")
            .sha256()
    );
    assert!(!peer.root.join("pwned").exists());

    let pull_plan = FreshAnalysis::analyze(&local_plan(
        &local_destination,
        &peer.remote_root,
        OneWaySource::PeerB,
    ))
    .expect("pull plan should be analyzable");
    let pull_action = pull_plan
        .plan()
        .action_for(&relative)
        .expect("remote source should be included in the pull plan")
        .clone();
    let pull_spec = ProcessSpecification::from_profile(&ssh_profile(
        local_destination.as_path(),
        peer.peer(),
        true,
    ))
    .expect("pull SSH specification should be valid");
    let local_staging = local_destination.join(".syncplus-e2e-staging");
    let pull_invocation = pull_spec
        .ssh_item_invocation_to(&pull_action, &local_staging)
        .expect("pull invocation should use the typed SSH path boundary");
    assert_success(peer.run_rsync(&pull_invocation).expect("pull should run"), "SSH pull");
    let pulled_path = local_destination.join(&relative);
    fs::rename(&local_staging, &pulled_path).expect("pull staging install should succeed");
    assert_eq!(fs::read(&pulled_path).expect("pulled file"), content);
    assert!(!peer.root.join("pwned").exists());
}

#[test]
fn ssh_to_ssh_remains_unavailable_at_the_user_workflow_boundary() {
    let first = Peer::from_ssh(
        "first",
        SshPeer::new(
            "first.example.test",
            "sync-user",
            22,
            Some(PathBuf::from("/keys/first")),
            SshAuthentication::Key,
            "/srv/first",
        )
        .expect("first peer should be valid"),
    );
    let second = Peer::from_ssh(
        "second",
        SshPeer::new(
            "second.example.test",
            "sync-user",
            22,
            Some(PathBuf::from("/keys/second")),
            SshAuthentication::Key,
            "/srv/second",
        )
        .expect("second peer should be valid"),
    );
    assert!(matches!(
        ProcessSpecification::from_profile(&SyncProfile::new("SSH-to-SSH", first, second)),
        Err(ProcessSpecError::UnsupportedSshTopology)
    ));
}
