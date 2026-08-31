use std::{fs, path::PathBuf};

use crate::{
    AnalysisError, AuthorizationSnapshot, DeletionMethod, FreshAnalysis, MetadataRequirements,
    OneWaySource, ProcessArgument, ProcessSpecError, ProcessSpecification, Peer,
    RemoteHelperInvocation, RemoteHelperKind, RsyncFlag,
    RunId, RunSnapshot, SshAuthentication, SshPeer, SshPeerError, SyncMode,
    SyncOptions, SyncProfile,
    SpecialistMetadataRequirements,
};

fn profile(source: PathBuf, destination: PathBuf) -> SyncProfile {
    SyncProfile::new(
        "Process specification",
        Peer::new("Source", source),
        Peer::new("Destination", destination),
    )
    .with_source(OneWaySource::PeerA)
}

fn ssh_peer(remote_path: &str) -> Peer {
    Peer::ssh(
        "SSH peer",
        "backup.example.test",
        "sync-user",
        2222,
        Some(PathBuf::from("/home/user/.ssh/id_sync")),
        SshAuthentication::Key,
        remote_path,
    )
    .expect("the SSH fixture should be valid")
}

#[test]
fn unknown_and_destructive_raw_options_are_rejected() {
    assert!(matches!(
        RsyncFlag::try_from("--not-a-real-option"),
        Err(ProcessSpecError::UnknownArgument { .. })
    ));
    assert!(matches!(
        RsyncFlag::try_from("--delete"),
        Err(ProcessSpecError::ArbitraryArgument { .. })
    ));
}

#[test]
fn specialist_metadata_is_named_and_disabled_by_default() {
    let defaults = MetadataRequirements::default().specialist_metadata();
    assert!(!defaults.any());

    let specialist = MetadataRequirements::default().with_specialist_metadata(
        SpecialistMetadataRequirements::new(false, true, true),
    );
    let specification = ProcessSpecification::from_profile(
        &profile(PathBuf::from("/source"), PathBuf::from("/destination"))
            .with_options(SyncOptions { metadata: specialist, ..SyncOptions::default() }),
    )
    .expect("named specialist options should validate");
    assert!(specification.arguments().contains(&ProcessArgument::Flag(RsyncFlag::Acls)));
    assert!(specification.arguments().contains(&ProcessArgument::Flag(RsyncFlag::Xattrs)));
}

#[test]
fn mirror_is_explicit_and_rejects_one_way_deletion_options() {
    let mirror = profile(PathBuf::from("/a"), PathBuf::from("/b"))
        .with_mode(SyncMode::Mirror);
    assert_eq!(mirror.mode(), SyncMode::Mirror);
    assert_eq!(ProcessSpecification::from_profile(&mirror).unwrap().mode(), SyncMode::Mirror);

    let invalid = mirror.clone().with_options(SyncOptions {
        safe_delete: true,
        deletion_method: Some(DeletionMethod::Trash),
        ..SyncOptions::default()
    });
    assert!(matches!(
        ProcessSpecification::from_profile(&invalid),
        Err(ProcessSpecError::InvalidOptionCombination { .. })
    ));
    let specification = ProcessSpecification::from_profile(&mirror).expect("Mirror is valid");
    assert!(matches!(
        specification.invocation(),
        Err(ProcessSpecError::MirrorRequiresReviewedPlan)
    ));
    assert!(specification.preview().contains("per reviewed plan action"));
}

#[test]
fn peer_paths_are_single_structured_process_arguments() {
    let source = PathBuf::from("/tmp/source; touch /tmp/pwned/世界\n");
    let destination = PathBuf::from("/tmp/destination $(touch /tmp/pwned)");
    let specification =
        ProcessSpecification::from_profile(&profile(source.clone(), destination.clone()))
            .expect("valid peer paths should produce a specification");
    let invocation = specification.invocation().expect("One-Way invocation");

    assert!(invocation
        .arguments()
        .iter()
        .any(|argument| argument == source.as_os_str()));
    assert!(invocation
        .arguments()
        .iter()
        .any(|argument| argument == destination.as_os_str()));
    assert_eq!(
        invocation
            .arguments()
            .iter()
            .filter(|argument| *argument == source.as_os_str())
            .count(),
        1
    );
    assert!(invocation
        .arguments()
        .iter()
        .all(|argument| argument != std::ffi::OsStr::new("touch")));

    let end_of_options = invocation
        .arguments()
        .iter()
        .position(|argument| argument == std::ffi::OsStr::new("--"))
        .expect("the invocation must delimit options before peer paths");
    assert!(invocation.arguments()[end_of_options + 1..]
        .iter()
        .all(|argument| argument != std::ffi::OsStr::new("--not-a-real-option")));
}

#[test]
fn local_to_ssh_profiles_use_structured_transport_and_remote_path_arguments() {
    let remote_path = "/srv/sync/$(touch pwned); user's report/世界\n";
    let specification = ProcessSpecification::from_profile(
        &SyncProfile::new(
            "SSH process specification",
            Peer::new("Local", PathBuf::from("/home/user/source")),
            ssh_peer(remote_path),
        )
        .with_source(OneWaySource::PeerA),
    )
    .expect("local-to-SSH profiles should produce a specification");
    let invocation = specification.invocation().expect("One-Way invocation");

    let remote_target = invocation
        .arguments()
        .iter()
        .find(|argument| argument.to_string_lossy().contains("backup.example.test:"))
        .expect("the remote peer should be one typed argument");
    assert_eq!(
        remote_target.to_string_lossy(),
        "sync-user@backup.example.test:/srv/sync/$(touch pwned); user's report/世界\n"
    );
    assert!(invocation.arguments().iter().any(|argument| {
        argument == "--rsh=ssh -p 2222 -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -i '/home/user/.ssh/id_sync'"
    }));
    assert_eq!(
        invocation
            .arguments()
            .iter()
            .filter(|argument| argument.to_string_lossy().contains("backup.example.test:"))
            .count(),
        1
    );
    assert!(invocation
        .arguments()
        .iter()
        .all(|argument| argument != "touch"));
    assert!(specification.preview().contains("backup.example.test:"));
    assert_eq!(
        specification
            .ssh_transport()
            .expect("the SSH transport should be present")
            .authentication(),
        SshAuthentication::Key
    );
}

#[test]
fn ssh_to_local_profiles_reverse_the_typed_peer_arguments() {
    let specification = ProcessSpecification::from_profile(
        &SyncProfile::new(
            "SSH process specification",
            ssh_peer("/srv/sync/incoming"),
            Peer::new("Local", PathBuf::from("/home/user/destination")),
        )
        .with_source(OneWaySource::PeerA),
    )
    .expect("SSH-to-local profiles should produce a specification");
    let invocation = specification.invocation().expect("One-Way invocation");
    let end_of_options = invocation
        .arguments()
        .iter()
        .position(|argument| argument == "--")
        .expect("peer arguments should follow the option boundary");

    assert_eq!(
        invocation.arguments()[end_of_options + 1].to_string_lossy(),
        "sync-user@backup.example.test:/srv/sync/incoming"
    );
    assert_eq!(
        invocation.arguments()[end_of_options + 2],
        "/home/user/destination"
    );
}

#[test]
fn ssh_transport_disables_unselected_authentication_methods() {
    let cases = [
        (
            SshAuthentication::Key,
            Some(PathBuf::from("/home/user/.ssh/id_sync")),
            "--rsh=ssh -p 2222 -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -i '/home/user/.ssh/id_sync'",
        ),
        (
            SshAuthentication::Agent,
            None,
            "--rsh=ssh -p 2222 -o IdentityFile=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no",
        ),
        (
            SshAuthentication::InteractivePassword,
            None,
            "--rsh=ssh -p 2222 -o IdentityFile=none -o IdentityAgent=none -o PreferredAuthentications=keyboard-interactive,password -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes",
        ),
        (
            SshAuthentication::SavedPassword(
                crate::SavedSecretReference::new("backup-password").expect("valid reference"),
            ),
            None,
            "--rsh=ssh -p 2222 -o IdentityFile=none -o IdentityAgent=none -o PreferredAuthentications=keyboard-interactive,password -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes",
        ),
    ];

    for (authentication, identity, expected_transport) in cases {
        let remote = Peer::ssh(
            "SSH peer",
            "backup.example.test",
            "sync-user",
            2222,
            identity,
            authentication,
            "/srv/sync",
        )
        .expect("SSH fixture should be valid");
        let profile = SyncProfile::new(
            "SSH profile",
            Peer::new("Local", PathBuf::from("/source")),
            remote,
        );
        let invocation = ProcessSpecification::from_profile(&profile)
            .expect("valid SSH profile")
            .invocation()
            .expect("One-Way invocation");

        assert!(invocation
            .arguments()
            .iter()
            .any(|argument| argument == expected_transport));
    }
}

#[test]
fn two_ssh_peers_are_rejected_before_process_construction() {
    let error = ProcessSpecification::from_profile(
        &SyncProfile::new(
            "SSH topology",
            ssh_peer("/srv/one"),
            ssh_peer("/srv/two"),
        ),
    )
    .expect_err("SSH-to-SSH is outside the supported topology");

    assert!(matches!(error, ProcessSpecError::UnsupportedSshTopology));
}

#[test]
fn remote_peers_use_the_ssh_workflow_boundary_but_not_local_filesystem_analysis() {
    let profile = SyncProfile::new(
        "SSH workflow boundary",
        Peer::new("Local", PathBuf::from("/home/user/source")),
        ssh_peer("/srv/sync"),
    );

    assert!(matches!(
        FreshAnalysis::analyze(&profile),
        Err(AnalysisError::UnsupportedRemotePeer { peer }) if peer == "SSH peer"
    ));
    assert!(RunSnapshot::from_profile(
        RunId::new(1),
        &profile,
        AuthorizationSnapshot::default()
    )
    .is_ok());
}

#[test]
fn remote_sha256_helper_is_fixed_and_keeps_the_path_in_one_encoded_command_argument() {
    let peer = SshPeer::new(
        "backup.example.test",
        "sync-user",
        2222,
        None,
        SshAuthentication::Agent,
        "/srv/sync",
    )
    .expect("SSH fixture should be valid");
    let path = PathBuf::from("/srv/sync/$(touch pwned); user's report/世界\n");
    let helper = RemoteHelperInvocation::sha256(&peer, path.clone())
        .expect("the fixed helper should accept a validated path");

    assert_eq!(helper.kind(), RemoteHelperKind::Sha256);
    assert_eq!(helper.path(), path.as_path());
    assert_eq!(helper.invocation().program(), std::ffi::OsStr::new("ssh"));
    assert_eq!(helper.invocation().arguments().len(), 12);
    assert!(helper
        .invocation()
        .arguments()
        .last()
        .expect("fixed remote command")
        .to_string_lossy()
        .starts_with("sha256sum -- "));
    assert!(helper
        .invocation()
        .arguments()
        .iter()
        .all(|argument| argument != std::ffi::OsStr::new("touch")));
    assert!(helper.invocation().preview().contains("sha256sum"));
}

#[test]
fn malformed_ssh_fields_are_rejected_at_the_structured_peer_boundary() {
    let cases = [
        SshPeer::new(
            "",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        ),
        SshPeer::new(
            "backup.example.test;touch",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        ),
        SshPeer::new(
            "backup.example.test",
            "sync user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        ),
        SshPeer::new(
            "backup.example.test",
            "sync-user",
            0,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        ),
        SshPeer::new(
            "backup.example.test",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "",
        ),
        SshPeer::new(
            "backup.example.test",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync\0unsafe",
        ),
    ];

    assert!(matches!(cases[0], Err(SshPeerError::EmptyServer)));
    assert!(matches!(cases[1], Err(SshPeerError::InvalidServer)));
    assert!(matches!(cases[2], Err(SshPeerError::InvalidUsername)));
    assert!(matches!(cases[3], Err(SshPeerError::InvalidPort)));
    assert!(matches!(cases[4], Err(SshPeerError::EmptyRemotePath)));
    assert!(matches!(cases[5], Err(SshPeerError::NulInRemotePath)));
    assert!(matches!(
        SshPeer::new(
            "backup.example.test:2222",
            "sync-user",
            22,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        ),
        Err(SshPeerError::InvalidServer)
    ));
    assert!(matches!(
        SshPeer::new(
            "backup.example.test",
            "sync-user",
            22,
            None,
            SshAuthentication::Key,
            "/srv/sync",
        ),
        Err(SshPeerError::MissingIdentityForKey)
    ));
}

#[test]
fn destructive_options_are_explicit_and_invalid_combinations_fail() {
    let defaults = SyncOptions::default().validate().expect("defaults are valid");
    assert!(!defaults.safe_delete());
    assert!(!defaults.destination_cleanup());
    assert_eq!(defaults.deletion_method(), None);

    let safe_delete = SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::Trash),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    }
    .validate()
    .expect("Safe Delete with an explicit recovery method is valid");
    assert!(safe_delete.safe_delete());
    assert_eq!(safe_delete.deletion_method(), Some(DeletionMethod::Trash));

    let missing_method = SyncOptions {
        safe_delete: true,
        destination_cleanup: false,
        deletion_method: None,
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    }
    .validate()
    .expect_err("Safe Delete without a recovery method is ambiguous");
    assert!(matches!(
        missing_method,
        ProcessSpecError::InvalidOptionCombination { .. }
    ));

    let invalid = SyncOptions {
        safe_delete: false,
        destination_cleanup: false,
        deletion_method: Some(DeletionMethod::PermanentRemoval),
        metadata: Default::default(),
        partial_transfer_policy: Default::default(),
        retry_policy: Default::default(),
    }
    .validate()
    .expect_err("a deletion method without a destructive action is ambiguous");
    assert!(matches!(
        invalid,
        ProcessSpecError::InvalidOptionCombination { .. }
    ));

    let destination_cleanup = profile(PathBuf::from("/source"), PathBuf::from("/destination"))
        .with_options(SyncOptions {
            safe_delete: false,
            destination_cleanup: true,
            deletion_method: None,
            metadata: Default::default(),
            partial_transfer_policy: Default::default(),
            retry_policy: Default::default(),
        });
    let specification = ProcessSpecification::from_profile(&destination_cleanup)
        .expect("destination cleanup must be enabled only by explicit profile configuration");
    assert!(specification.arguments().contains(&ProcessArgument::Flag(
        RsyncFlag::DestinationCleanup,
    )));

    let safe_delete = profile(PathBuf::from("/source"), PathBuf::from("/destination"))
        .with_options(SyncOptions {
            safe_delete: true,
            destination_cleanup: false,
            deletion_method: Some(DeletionMethod::Trash),
            metadata: Default::default(),
            partial_transfer_policy: Default::default(),
            retry_policy: Default::default(),
        });
    let specification = ProcessSpecification::from_profile(&safe_delete)
        .expect("Safe Delete must be valid with an explicit recovery method");
    assert!(!specification.arguments().contains(&ProcessArgument::Flag(
        RsyncFlag::DestinationCleanup,
    )));
}

#[test]
fn preview_and_invocation_come_from_the_same_validated_specification() {
    let specification = ProcessSpecification::from_profile(&profile(
        PathBuf::from("/home/user/source"),
        PathBuf::from("/media/backup/destination"),
    ))
    .expect("valid profile should produce a specification")
    .with_secret_binding("SYNCPLUS_TOKEN")
    .expect("a valid secret binding should be accepted");
    let invocation = specification.invocation().expect("One-Way invocation");
    let preview = specification.preview();

    for argument in invocation.arguments() {
        let rendered = argument.to_string_lossy();
        assert!(preview.contains(rendered.as_ref()));
    }
    assert!(preview.contains("SYNCPLUS_TOKEN=<redacted>"));
    assert!(!preview.contains("secret-value"));
}

#[test]
fn item_invocation_uses_typed_paths_without_tree_cleanup() {
    let specification = ProcessSpecification::from_profile(&profile(
        PathBuf::from("/source"),
        PathBuf::from("/destination"),
    ))
    .expect("valid profile should produce a specification");
    let invocation = specification
        .item_invocation(
            &PathBuf::from("/source/file with spaces"),
            &PathBuf::from("/destination/.syncplus-temporary"),
        )
        .expect("valid item paths should produce a typed invocation");

    assert_eq!(invocation.program(), std::ffi::OsStr::new("rsync"));
    assert!(invocation
        .arguments()
        .iter()
        .any(|argument| argument == "/source/file with spaces"));
    assert!(invocation
        .arguments()
        .iter()
        .any(|argument| argument == "/destination/.syncplus-temporary"));
    assert!(!invocation
        .arguments()
        .iter()
        .any(|argument| argument == "--delete"));
}

#[test]
fn transfer_paths_are_bound_to_the_validated_plan_scope() {
    let root = std::env::temp_dir().join(format!(
        "syncplus-process-scope-{}",
        std::process::id()
    ));
    let source = root.join("source");
    let destination = root.join("destination");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&destination).unwrap();
    fs::write(source.join("approved.txt"), b"approved").unwrap();

    let profile = profile(source.clone(), destination.clone());
    let analysis = FreshAnalysis::analyze(&profile).expect("analysis should succeed");
    let action = analysis
        .plan()
        .actions()
        .first()
        .expect("the source item should have a copy action");
    let (resolved_source, resolved_destination) = analysis
        .specification()
        .transfer_paths(action)
        .expect("a plan action should resolve inside the profile roots");

    assert_eq!(resolved_source, source.join("approved.txt"));
    assert_eq!(resolved_destination, destination.join("approved.txt"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn mirror_transfer_paths_allow_each_peer_to_be_the_item_source() {
    let root = std::env::temp_dir().join(format!(
        "syncplus-mirror-process-scope-{}",
        std::process::id()
    ));
    let peer_a = root.join("peer-a");
    let peer_b = root.join("peer-b");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&peer_a).unwrap();
    fs::create_dir_all(&peer_b).unwrap();
    fs::write(peer_b.join("from-b.txt"), b"peer b").unwrap();

    let profile = profile(peer_a.clone(), peer_b.clone()).with_mode(SyncMode::Mirror);
    let analysis = FreshAnalysis::analyze(&profile).expect("Mirror analysis should succeed");
    let action = analysis
        .plan()
        .actions()
        .first()
        .expect("Peer B item should produce a copy action");
    assert_eq!(action.source_side(), crate::PeerSide::PeerB);

    let (resolved_source, resolved_destination) = analysis
        .specification()
        .transfer_paths(action)
        .expect("Mirror should allow the reverse direction");
    assert_eq!(resolved_source, peer_b.join("from-b.txt"));
    assert_eq!(resolved_destination, peer_a.join("from-b.txt"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn process_arguments_are_named_and_not_an_unrestricted_vector() {
    let specification = ProcessSpecification::from_profile(&profile(
        PathBuf::from("/source"),
        PathBuf::from("/destination"),
    ))
    .expect("valid profile should produce a specification");

    assert!(specification.arguments().iter().all(|argument| matches!(
        argument,
        ProcessArgument::Flag(_) | ProcessArgument::PeerPath(_)
    )));
}

#[test]
fn exclusions_are_typed_arguments_and_never_imply_deletion() {
    let specification = ProcessSpecification::from_profile(
        &profile(PathBuf::from("/source"), PathBuf::from("/destination"))
            .with_exclusion("*.tmp $(touch pwned)"),
    )
    .expect("a non-empty exclusion pattern should be valid data");

    assert!(specification
        .arguments()
        .contains(&ProcessArgument::ExclusionPattern(
            "*.tmp $(touch pwned)".to_owned(),
        )));
    assert!(specification
        .invocation()
        .expect("One-Way invocation")
        .arguments()
        .iter()
        .any(|argument| argument == "--exclude=*.tmp $(touch pwned)"));
    assert!(!specification.arguments().contains(&ProcessArgument::Flag(
        RsyncFlag::DestinationCleanup,
    )));

    let invalid = ProcessSpecification::from_profile(
        &profile(PathBuf::from("/source"), PathBuf::from("/destination"))
            .with_exclusion(""),
    )
    .expect_err("empty exclusion patterns are ambiguous");
    assert!(matches!(
        invalid,
        ProcessSpecError::InvalidExclusionPattern { .. }
    ));
}

#[test]
fn preview_quotes_shell_metacharacters_and_escapes_control_characters() {
    let specification = ProcessSpecification::from_profile(&profile(
        PathBuf::from("/source/with spaces/$(touch pwned)/世界\n"),
        PathBuf::from("/destination/with 'quotes' and\ttabs"),
    ))
    .expect("shell metacharacters are valid path data");

    let preview = specification.preview();

    assert!(preview.contains("'/source/with spaces/$(touch pwned)/世界\\n'"));
    assert!(preview.contains("'/destination/with '\\''quotes'\\'' and\\ttabs'"));
    assert!(!preview.contains("secret-value"));
}

#[test]
fn secret_bindings_accept_only_names_without_shell_syntax() {
    let specification = ProcessSpecification::from_profile(&profile(
        PathBuf::from("/source"),
        PathBuf::from("/destination"),
    ))
    .expect("valid profile should produce a specification");

    let invalid = specification
        .with_secret_binding("TOKEN; touch /tmp/pwned")
        .expect_err("secret bindings must not accept shell syntax");
    assert!(matches!(
        invalid,
        ProcessSpecError::InvalidSecretBinding { .. }
    ));
}

#[test]
fn peer_paths_with_nul_are_rejected_before_invocation() {
    let invalid = ProcessSpecification::from_profile(&profile(
        PathBuf::from("/source\0with-nul"),
        PathBuf::from("/destination"),
    ))
    .expect_err("process arguments cannot contain NUL");

    assert!(matches!(invalid, ProcessSpecError::NulInPeerPath { .. }));
}
