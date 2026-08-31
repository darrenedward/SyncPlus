use std::{fs, path::PathBuf};

use crate::{
    DeletionMethod, FreshAnalysis, MetadataRequirements, OneWaySource, ProcessArgument, ProcessSpecError,
    ProcessSpecification, Peer, RsyncFlag, SyncOptions, SyncProfile,
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
fn peer_paths_are_single_structured_process_arguments() {
    let source = PathBuf::from("/tmp/source; touch /tmp/pwned/世界\n");
    let destination = PathBuf::from("/tmp/destination $(touch /tmp/pwned)");
    let specification =
        ProcessSpecification::from_profile(&profile(source.clone(), destination.clone()))
            .expect("valid peer paths should produce a specification");
    let invocation = specification.invocation();

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
    let invocation = specification.invocation();
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
