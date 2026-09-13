## Problem Statement

SyncPlus needs a clear contract for what belongs in Simple Mode and what belongs in Advanced Mode. Everyday users should be able to configure a safe Sync Profile without understanding rsync, specialist filesystem metadata, SSH internals, or unattended execution. Experienced users still need additional comparison, metadata, transport, performance, scheduling, and diagnostic controls.

## Solution

Simple Mode is the default, plain-language setup for everyday synchronisation. Advanced Mode is an explicit opt-in view for specialist controls and technical evidence. Advanced Mode is not an unsafe bypass: all safety policies, verification, source-preservation, reconciliation, recovery, and SSH identity rules remain enforced in both modes.

Use the product term **Simple Mode**, not Basic Mode, and **Advanced Mode**, not Unsafe Mode or Expert Bypass.

## User Stories

1. As a new user, I want Simple Mode to be the default, so that I can create a safe Sync Profile without specialist knowledge.
2. As a user, I want source and destination folders clearly shown, so that I know which files are in scope and where they will go.
3. As a user, I want One-Way Sync and Mirror Sync described in plain language, so that I understand direction and authority.
4. As a user, I want One-Way Sync to be the new-profile default, so that creating a profile never implies bidirectional or destructive behaviour.
5. As a user, I want one combined exclusion list for file and folder patterns such as `*.tmp` and `node_modules/`, so that I can keep unwanted items outside the approved scope.
6. As a user, I want exclusions explained as scope rules rather than deletion, so that excluded items are not misunderstood.
7. As a user, I want hidden files included by default, so that important configuration files are not silently missed.
8. As a user, I want symbolic links preserved as links by default, so that linked targets are not unexpectedly followed.
9. As a user, I want changed destination files handled through verified replacement, so that overwrites cannot silently corrupt data.
10. As a user, I want source files preserved by default, so that ordinary synchronisation never removes originals.
11. As a user, I want Safe Delete visible but disabled by default, so that source removal is deliberate.
12. As a user, I want Safe Delete to explain independent verification and recoverable Trash, so that I understand its protection and limitations.
13. As a user, I want Permanent Removal hidden from Simple Mode, so that irreversible deletion is not presented as an ordinary setting.
14. As an experienced user, I want to opt into Advanced Mode, so that specialist controls are available when needed.
15. As an experienced user, I want Permanent Removal and Destination Cleanup in Advanced Mode with explicit consequence text, so that destructive choices are informed.
16. As an experienced user, I want metadata controls for executable permissions, timestamps, ownership, ACLs, and extended attributes, so that specialist fidelity requirements can be met.
17. As an experienced user, I want comparison and Mirror Equality controls explained, so that I know which metadata contributes to “same”.
18. As an experienced user, I want named bandwidth and bounded retry controls, so that constrained or unreliable connections can be handled predictably.
19. As a user, I want a simple SSH connection flow for server, username, authentication choice, and required credential, so that remote setup remains understandable.
20. As an experienced user, I want SSH port, selected key, and host identity details available in Advanced Mode, so that I can inspect a specialist connection safely.
21. As an experienced user, I want read-only generated process commands and technical diagnostics, so that I can inspect intended execution without editing commands.
22. As a user, I want all command previews and diagnostics to redact passwords, passphrases, private keys, and other secrets.
23. As an experienced user, I want Scheduled Runs available only in Advanced Mode, so that unattended execution is deliberate.
24. As a user, I want unattended recoverable deletion and unattended Permanent Removal to require separate authorizations, so that Trash authorization never implies irreversible deletion.
25. As a user, I want every option to explain why it matters, when to use it, and its limitations, so that I can make an informed choice.
26. As a user, I want invalid combinations rejected or clearly gated, so that a profile cannot save a contradictory configuration.
27. As a user, I want changing an option, endpoint, exclusion, mode, or authorization to invalidate the old plan, so that Synchronise always uses Fresh Analysis.
28. As a user, I want effective options frozen into the Profile Snapshot when a Sync Run starts, so that later edits cannot alter an active run.
29. As a user, I want Simple Mode and Advanced Mode preference remembered across restarts, so that the app opens where I left it.
30. As a user, I want imported and cloned profiles to obey the same visibility, validation, and safety rules, without copying secrets.
31. As a user, I want the Review and Execution Confirmation surfaces to restate destructive consequences, so that saved settings cannot hide what will happen.
32. As a user, I want specialist settings subordinate to Source, Destination, Review, Dry run, and Synchronise, so that advanced controls do not obscure the primary decision.

## Implementation Decisions

- Add or complete a persisted application-level display preference. First launch defaults to Simple Mode; the preference is remembered across restarts.
- Keep display preference separate from Sync Profile configuration. It must not change the profile’s effective Sync Options.
- Use the existing validated Sync Option boundary shared by the GUI and `syncplus-core`. The GUI chooses named typed values and never constructs arbitrary process arguments.
- Simple Mode contains source, destination, One-Way Sync or Mirror Sync, combined exclusions, hidden-file inclusion, symlink preservation, ordinary verified replacement behaviour, Safe Delete with plain-language consequences, Dry run, and Synchronise.
- Advanced Mode contains Permanent Removal, Destination Cleanup, specialist metadata, comparison/equality controls, performance controls, SSH transport details, scheduling, unattended authorization, command preview, and technical diagnostics.
- Permanent Removal is labelled irreversible. It is never silently substituted when Trash is unavailable.
- Safe Delete remains disabled by default. Manual Safe Delete requires fresh Execution Confirmation and asks for the Deletion Method at run time. Scheduled destructive runs require explicit unattended authorization; unattended Permanent Removal requires a separate authorization.
- No setting can disable SHA-256 verification, source identity/stability checks, destination verification, Completion Reconciliation, recovery journaling, SSH host identity checks, or source preservation on uncertainty.
- No raw rsync flags, shell commands, arbitrary remote commands, free-form process arguments, passwords, or private-key contents are exposed.
- Every visible option has a stable named identity, typed value, validation rule, default, persistence representation, and plain-language help.
- Validation considers Sync Mode, endpoint type, available recovery method, and interactive versus unattended execution.
- Profile import/export contains validated nonsecret configuration only. Saved credentials remain in the desktop OS keyring.
- Any effective setting change invalidates the current analysis and requires Fresh Analysis before Synchronise.
- Run start freezes all effective settings in the Profile Snapshot.
- Progress, Review, Run Report, Recovery Review, and failure evidence remain in the main workflow and are not hidden in Advanced Mode.
- Update domain documentation or an ADR if the final grouping introduces a new persistence or architectural decision.

## Testing Decisions

- Assert external behaviour: visible options, accepted values, persisted values, explanations, and execution permission. Do not test incidental widget structure or private helper names.
- Use the shared validated profile/options contract as the highest seam. Cover defaults, persistence round trips, mode validation, incompatible combinations, plan invalidation, and immutable Profile Snapshot capture.
- Extend existing core policy, Fresh Analysis, process specification, precheck, transfer, verification, journal, recovery, SSH safety, and release-gate tests rather than duplicating policy in the GUI.
- Test that new profiles default to One-Way Sync, Safe Delete off, Destination Cleanup off, hidden files included, and symlinks preserved.
- Test that Advanced-only options remain validated and enforced even when Simple Mode hides them.
- Test that Permanent Removal and unattended authorizations require the correct explicit authorization, including their separate scopes.
- Test import and cloning for validated nonsecret options and absence of secret duplication.
- UI tests verify Simple Mode’s common settings, Advanced Mode opt-in, plain-language consequence text, dangerous labels, and absence of editable raw commands.
- Integration tests verify that the GUI and Background Scheduler use the same effective options and core workflow.
- Run `cargo fmt --check`, `cargo test`, `cargo clippy -- -D warnings`, and the disposable end-to-end safety matrix required by the project plan before release claims.

## Out of Scope

- Replacing the existing Synchronise, Options, Review, and Report workflow.
- Arbitrary rsync or shell command editing, raw command-line configuration, or unsafe flags.
- Disabling verification, journaling, reconciliation, source preservation, recovery, or SSH identity checks.
- SSH-to-SSH synchronisation, a file-content merge editor, or Real-Time Sync.
- A Dark Appearance / Light Appearance setting.
- Scheduled Runs in Simple Mode.
- Automatic enabling of Safe Delete, Destination Cleanup, Permanent Removal, scheduling, or unattended authorization.
- Changing the underlying Safe Delete, Mirror Sync, Recovery Review, or Verified Removal contracts.
- Silent fallback to a riskier operation when an advanced option is unavailable.

## Further Notes

Simple Mode help text should say: “The normal safe setup for everyday synchronisation.” Advanced Mode help text should say: “Additional comparison, metadata, transport, performance, scheduling, and diagnostic controls. The same safety rules still apply.”

The Options surface should remain compact. Group Advanced Mode sections by purpose: comparison and metadata, transport, performance, and scheduling/automation. Place consequence text beside settings that affect deletion or unattended execution.

Preserve the product promise: “Review the plan. Confirm what changes. Uncertainty preserves the source.”
