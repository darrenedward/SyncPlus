# SyncPlus — a safety-first desktop synchronization app

> Status: implementation complete pending review · 2026-08-31 · Mirror Resolution Runs now share the verified workflow, durable resolution reports, and strict two-peer Completion Reconciliation for issue #47

## Product goal

SyncPlus is a native Linux desktop application that makes synchronization understandable and safe. It shows the user what will happen, why it will happen, which files are affected, and what recovery is available before any data-changing action begins.

The application uses rsync as a transfer engine, but rsync's exit code is never treated as proof that a Safe Delete operation was complete. SyncPlus owns the safety policy, verification, review, recovery, and reporting layers around the transfer engine.

## First-release scope

V1 includes:

- local folder ↔ local folder synchronization, including external drives;
- local folder ↔ one SSH peer in either direction;
- One-Way Sync, Mirror Sync, and One-Way Safe-Delete Sync;
- source-authoritative conflict handling for One-Way Sync;
- explicit per-file Mirror conflict review;
- hidden files included by default and an exclusion-pattern editor;
- Interactive and Unattended runs;
- optional Advanced Mode scheduling through a per-OS-user background scheduler;
- recoverable Trash where it can be verified, and explicitly authorized Permanent Removal;
- SHA-256 content verification and essential metadata verification;
- resumable recovery after cancellation, crashes, connection loss, or external-drive removal;
- SQLite-backed profiles, schedules, baselines, reports, action journals, and recovery state;
- SSH key authentication recommended, password authentication supported interactively and optionally through the desktop keyring;
- plain-language Help, plan review, notifications, durable reports, and dark/light theme support.

Explicitly outside v1:

- SSH ↔ SSH transfers;
- rsync daemon URLs (`rsync://` and `host::module`);
- automatic `~/.ssh/config` import;
- arbitrary shell or rsync argument entry;
- automatic permission elevation;
- automatic file-content merging or an editable merge editor;
- a malicious-remote/high-assurance read-back mode that downloads every remote file for local verification.

## Canonical terminology and behavior

### Sync Profile

A saved configuration containing two peer endpoints, mode, validated options, exclusions, and optional schedule/authorization settings. A Clone Profile action opens an editable copy, displays both endpoints, clears saved credential references for intentional reconfiguration, and requires at least one endpoint to differ before saving. Non-permanent destructive unattended authorization may be copied only after a dedicated warning and explicit Advanced Mode choice; Permanent Removal authorization is never copied.

### Sync Run

One execution of a profile. At execution start it stores a frozen Profile Snapshot. Later profile edits cannot alter the active run.

### Run Report

The retained record of a run, including the plan, action journal, verification evidence, warnings, unresolved items, decisions, and final status. Completed reports remain until the user removes them. Unresolved reports require a separate **Discard Unresolved Run** action.

### One-Way Sync

Copies from the selected source to the destination. The source is authoritative when the same path differs. Safe Delete and Destination Cleanup are separate options and are disabled by default.

### One-Way Safe-Delete Sync

Copies the approved source scope to the destination, verifies each result, and removes the corresponding source item only after the per-item proof boundary. Excluded, changed, failed, unavailable, or unresolved items remain at the source. The source is considered drained only when final reconciliation proves that every approved included item was handled.

### Mirror Sync

Reconciles two peers to the same approved result. Both peers remain populated. Neither peer is inherently authoritative. A first Mirror Run without a baseline never infers deletion from absence; one-sided items are copy candidates. Deletions require evidence, review, and confirmation.

### Conflict Review

A read-only side-by-side or split-pane comparison used for same-path conflicts, possible rename/duplicate candidates, destination naming conflicts, and other items requiring a decision. Text files show safe content differences; binary or unreadable files show metadata, size, type, and hashes. The user chooses a whole-file resolution; SyncPlus does not edit or merge file content.

### Run completion

Execution Result and final run status are separate. A transfer pass can finish while review remains open. The final **Complete** action is visible only after every required item is resolved and its resulting action succeeds.

Run statuses:

- `Completed` — every approved action succeeded and no required review remains;
- `Completed with Review Required` — safe work finished but conflicts/deferred items remain;
- `Failed` — a required action failed;
- `Cancelled` — the user stopped the run;
- `Interrupted` — the run stopped at an unsettled boundary and requires safe re-analysis;
- `Blocked` — precheck, permissions, capability, identity, or recovery requirements prevented execution;
- `Recovery Review` — the result around an interruption boundary is ambiguous;
- `Complete`/`Review-Cleared` — the user has reviewed all required items and explicitly closed the run.

`Source Drained` means every approved included source item was verified and removed. `Source Not Empty` lists exclusions, newly appeared items, failures, and unresolved items; it never implies that the entire folder is empty.

## Safety contract

### User confirmation

Every data-changing run shows a fresh **Execution Confirmation** immediately before execution. It lists:

- mode and exact source/destination mapping;
- counts and sizes for copies, overwrites, removals, preserved copies, conflicts, exclusions, and unresolved items;
- whether the source or destination changes;
- deletion method, recoverability, expected space use, and Trash limitations;
- any Path Risk Warning and the affected paths.

Destructive actions are reviewed per path in the plan and then confirmed once for the run, rather than displaying one popup per file.

Simple Mode uses plain language. Advanced Mode may show the exact generated command and diagnostics, but secrets are always redacted. No raw command field exists.

### Run Precheck

Before Analyze and before execution, the non-mutating Run Precheck checks:

- source readability and destination writability;
- permissions needed for configured metadata and removal methods;
- source/destination equality, overlap, nesting, and normalized peer scopes;
- filesystem/volume identity and mount availability;
- available space, including additional space required for Trash or cross-filesystem recovery;
- filename case, Unicode normalization, reserved names, invalid characters, path lengths, and destination restrictions;
- remote SSH host identity, credentials, remote rsync capability, remote hash capability, and remote recovery capability where relevant;
- SQLite integrity and the required pre-run database backup.

Required permission, capability, naming, recovery, or database failures block all file-changing execution. Read-only analysis may explain the issue and its remediation. SyncPlus never invokes `sudo`, changes ownership/permissions, or recommends broad permissions such as `chmod 777`.

### Fresh Analysis and Source Inventory

Opening a pending, interrupted, or review-needed run triggers a Fresh Analysis. A further Fresh Analysis happens immediately before confirmation. Completed reports remain historical and are not silently recalculated.

Fresh Analysis records a Source Inventory after applying exclusions, with hidden files included by default. A Mirror Run freezes one inventory for each peer so first-run copy candidates and both directions can be reconciled. It distinguishes eligible, excluded, newly appeared, changed, unavailable, and unresolved items. Old plans are never blindly replayed.

### Per-item Safe Delete proof

Safe Delete processes one item at a time:

1. Record source identity, type, size, metadata, and initial SHA-256.
2. Transfer to a temporary destination-side item.
3. Independently hash the temporary destination and compare SHA-256 and size.
4. Re-check source identity, size, metadata, and content stability. Any change preserves the source and requires review.
5. Flush and install the verified destination atomically, protecting the old destination version.
6. Verify the installed destination again.
7. Move the exact source item to the selected recovery location or permanently remove it only at the proof boundary.
8. Persist the action outcome before moving to the next item.

Empty source directories may be removed only after all children are settled and the directory is confirmed empty. The selected source root is never removed.

At the end, Completion Reconciliation independently compares the current source and destination against the Source Inventory and Action Journal. Any unexplained source item prevents Source Drained and Review-Cleared status.

No software can guarantee against hardware failure, a malicious peer, or every uncooperative concurrent writer. SyncPlus's product guarantee is fail-closed behavior: uncertainty preserves the source.

### Destination overwrites

An overwrite uses a Verified Replacement: write to a temporary destination file, verify it, preserve the old destination using the selected method, and atomically install the new file. The old destination remains intact if transfer or verification fails. Byte-identical files do not trigger replacement or deletion.

### Deletion methods and recovery

- Simple Mode offers recoverable Trash where supported.
- Permanent Removal is Advanced Mode only, clearly labeled irreversible, and separately authorized for unattended use.
- Manual Safe Delete asks for the deletion method every run.
- An authorized schedule uses its explicitly configured method; unavailable Trash never falls back to permanent deletion.
- Same-filesystem recovery uses an atomic move.
- Cross-filesystem recovery may copy, independently verify, and then remove the original, with a space precheck.
- Local OS Trash uses native provenance metadata. Custom/remote recovery uses a small sidecar manifest as well as SQLite.
- Restore rechecks the target and never overwrites newer/different content automatically.

### Cancellation, interruption, and resume

Cancel stops launching new actions and terminates the current transfer promptly. The Action Journal records the plan, pre-state, start, progress, and `Cancelled Action` outcome. The source remains preserved. Partial destination data is removed by default; the user may explicitly choose **Keep Partial for Resume**, in which case it remains hidden, incomplete, outside the baseline, and is removed after successful completion.

Crashes, process termination, transport loss, drive removal, and database-boundary ambiguity create an Interrupted Run or Recovery Review. Resume uses the durable journal, continues from the last verified boundary, performs Fresh Analysis, and requires new confirmation where needed. It never blindly replays deletion.

The shared core `RunWorkflow` persists the frozen Source Inventory and complete action plan before mutation; Mirror additionally persists the Peer B inventory. It uses the controlled process-group transfer boundary, applies the frozen Retry Policy only to typed transient failures, and creates a new Sync Run for resume. It performs Completion Reconciliation after every settled workflow run and persists its findings before deriving Source Drained, Source Not Empty, Completed with Review Required, or Review-Cleared status.

## Mirror and conflict policy

- One-way conflicts use source authority by default.
- A per-path override may retain the destination version; under Safe Delete, the source is removed only after the retained destination is verified.
- Mirror conflicts have no implicit winner. Choices include Keep Peer A, Keep Peer B, Preserve Both, Rename/Preserve for Review, or Defer.
- The core `ConflictReview` is read-only: same-path differences retain both peer evidences, text previews are bounded in memory, and binary, large, or unreadable files expose only safe metadata and available hashes.
- Same-hash files at different paths are emitted as possible duplicate/rename candidates only. Structured destination compatibility conflicts use the same review entries and remain blocked from mutation.
- Every Conflict Review entry accepts exactly one typed whole-file resolution: Keep Peer A, Keep Peer B, Preserve Both, Rename/Preserve for Review, or Defer. A complete decision set remains non-executable until final Execution Confirmation is accepted.
- Keep decisions create a directed whole-file copy operation. Preserve Both, Rename/Preserve for Review, and Defer never discard either peer version; the latter choices keep the run review-required for later preservation or removal decisions.
- Preserved copies receive deterministic human-readable collision-safe names and remain listed with both original and new paths under the report's conflict section.
- A skipped/deferred item keeps the run open. Removing an item from scope is an explicit recorded decision and does not count as a successful transfer.
- Same-hash files at different paths are possible duplicates/rename candidates only; hash equality never automatically moves or deletes them.
- Mirror deletion candidates are derived only when a two-sided Sync Baseline proves one peer absent and the remaining peer unchanged. Each candidate exposes its baseline/current evidence and affected peer; a missing baseline, changed counterpart, exclusion, or other uncertainty produces no deletion candidate.
- Mirror deletion requires an explicit per-path decision and final Execution Confirmation. A failed deletion preserves the remaining copy and leaves the Mirror Invariant unresolved.
- A Resolution Run starts with Fresh Analysis, binds every reviewed decision to both peer revisions and the applicable Sync Baseline state, and refuses stale content, metadata, path identity, or baseline evidence. Data-changing resolutions require fresh Execution Confirmation; failed actions remain unresolved and preserved.
- Resolution Runs execute through the shared core workflow, persist each reviewed outcome and preserved-copy path in SQLite, and reconcile Keep decisions against the selected post-resolution version before updating the Sync Baseline.
- Preserved conflict copies use the effective destination naming policy to reserve deterministic generated paths before execution. The local preserved-copy boundary creates each copy with no-replace installation, verifies its content, and reports any failed copy as Review Later; a later Resolution Run owns explicit removal.
- Only successfully reconciled and verified paths enter the Sync Baseline.

The core `SyncBaseline` is persisted in SQLite per Sync Profile and peer pair. It
stores the verified state of each settled path and compares later inventories
per peer as unchanged, new, changed, or absent. `MirrorEquality` always
requires content and item type and applies only the enabled metadata
requirements; unavailable required evidence leaves a path unsettled.

## Filesystem and path policy

- Hidden files and folders are included by default.
- Exclusions are entered as patterns such as `*.tmp` or `node_modules/`; matching is shown in a preview before execution. Exclusions prevent synchronization and deletion; optional Excluded Item Cleanup is a separate reviewed action.
- Symlinks are preserved as links and are not followed by default.
- Regular files, directories, and symlinks are first-release scope. Unsupported special files are skipped and reported.
- Destination Compatibility Conflicts block affected actions before changes.
- Peer Scope Locks prevent concurrent overlapping runs across different profiles, not only identical profiles.
- Path Risk Warnings are advisory for One-Way Safe Delete. Common user-data subdirectories such as `/home/<user>/projects`, `/home/<user>/public_html`, and user-owned mounted data folders normally receive no special warning. Broad/system-sensitive paths such as `/`, `/home`, `/root`, `/etc`, `/usr`, `/var`, `/boot`, `/bin`, `/sbin`, `/lib`, `/dev`, `/proc`, and `/sys` receive a clear warning. This is not an allow/deny list; an intentionally selected old server volume may proceed after stronger confirmation. Mirror does not show this special source-draining warning.

For high-risk source scopes, Advanced Mode requires the user to type the exact source path in addition to the final confirmation. The selected source root is never removed.

## SSH policy

V1 supports one local peer and one SSH peer in either direction. SSH-to-SSH is not supported.

- SSH keys are recommended; the identity-file picker defaults to `~/.ssh`.
- Interactive password authentication is supported through a controlled askpass bridge. Passwords are held in memory only unless the user explicitly saves a secret in the desktop keyring.
- Unattended SSH requires a noninteractive credential available through the configured key, SSH agent, or keyring. Missing credentials stop and notify; there is no hidden prompt or silent fallback.
- Core credential resolution carries only the selected key, agent, or in-memory askpass/keyring secret; saved-password profile state is an opaque keyring reference.
- A new host fingerprint requires explicit approval. A changed fingerprint is rejected and reported for review.
- Host-trust state is persisted as a nonsecret server/port fingerprint record; only an explicit interactive approval can create or replace that record.
- A non-mutating remote preflight verifies compatible `rsync` and controlled SHA-256 capability before changes.
- Remote preflight also verifies the authenticated account's requested access and remote Trash location/access when recovery is required; missing capabilities block without an execution permit or fallback.
- After transfer, SyncPlus verifies the actual remote destination digest. If it cannot obtain or match the digest, the source remains preserved.
- The shared core SSH workflow re-runs the typed remote precheck around confirmation, freezes endpoint-specific staging paths, and accepts only path-bound source/destination metadata and content proofs from the platform SSH adapter.
- Remote Trash requires a verified recovery location and access for the remote account. Otherwise deletion stops or requires the separately authorized Permanent Removal option.
- Remote source recovery is a typed backend operation after the journaled Safe Delete proof boundary; successful results must prove source absence, recovery presence, destination continuity, and peer/path/run/type/digest provenance. Failed or ambiguous recovery remains in Recovery Review and preserves the source.
- Server, username, port, identity, and remote path are structured fields. User values are safely encoded into controlled process arguments; no arbitrary remote command is accepted.
- The core owns validated SSH endpoint fields and the typed Process Specification used by both preview and execution; credential handling, host trust, capability checks, and remote recovery remain mandatory pre-mutation gates.

## Scheduling and unattended operation

Scheduling is Advanced Mode only and disabled by default. A per-OS-user Background Scheduler can start profiles while the window is closed and uses the same core run workflow, normal permissions, credentials, prechecks, verification, and reports. It never installs a root service.

The current core scheduler persists a validated interval, timezone, enabled
state, and next-run timestamp. It claims due occurrences atomically with the
frozen Run Snapshot, and the desktop's fixed `--background-scheduler` command
provides the user-level launch point while leaving registration to the native
packaging integration.

Automatic schedules:

- are Unattended;
- may perform destructive actions only with explicit per-profile **Allow unattended destructive actions** authorization;
- require separate **Allow unattended permanent removal** authorization for irreversible deletion;
- store an explicitly authorized deletion method;
- never bypass Fresh Analysis, prechecks, SHA-256 verification, Completion Reconciliation, identity checks, or source preservation on uncertainty;
- never run concurrently with overlapping peer scopes;
- retry transient actions only within the bounded Retry Policy, defaulting to three attempts with increasing delays;
- coalesce missed triggers into one catch-up opportunity rather than queueing duplicates.

Unattended destructive authorization is cleared when a profile's endpoints,
mode, source, options, or exclusions change. SSH schedules resolve only the
selected noninteractive credential, reject interactive prompts, and refresh
host identity and remote capability permits before mutation. A blocked
scheduled report includes the profile, peer scope, reason, and safe next action
without secrets or file contents.

If a schedule cannot run, SyncPlus records and notifies the reason. The user can choose **Yes, Run Now** or **No, Not Now**. Run Now becomes an Interactive Run with fresh analysis and confirmation. No leaves the event visible.

Scheduler outcomes and decisions are durable events with canonical reason and
next-action text. The future tray and Quit surfaces consume typed safe intents
that can open a Run Report or start the already-gated interactive catch-up
flow; notification delivery never changes the report or safety outcome.

If the same profile is already active, the schedule is skipped and the user is told why, with **Open Running Sync** and **Dismiss**. Dismissal does not erase the event.

## Persistence, privacy, and recovery metadata

SQLite is the primary nonsecret store. Suggested layout:

```text
~/.local/share/syncplus/
├── syncplus.db
├── backups/                 # at most two validated *.sqlite.gz snapshots
├── quarantine/              # explicitly retained corrupt databases
├── recovery/                # custom recovery data and sidecar manifests
└── temp/
```

The application must resolve these locations through the operating system's XDG data and cache directories. It must never create a database beside a selected source, destination, project, or synchronized folder. There is one canonical live database per OS user; temporary SQLite files and test databases must use explicitly managed temporary directories.

The database contains profiles, settings, schedules, fingerprints, reports, action journals, baselines, hashes, and recovery state. Passwords, passphrases, and private-key material are not stored in SQLite; saved secrets use the desktop OS keyring. Files are created with user-only permissions.

Before a file-changing run, migration, or repair, SyncPlus integrity-checks the live database, creates a consistent SQLite snapshot, gzip-compresses it with a timestamp, validates it, and retains at most two validated backups. It does not create idle daily backups and never deletes the last known-good backup. If backup creation or validation fails, read-only analysis remains available but all file-changing execution is blocked.

If the database is corrupt, the app opens a Database Recovery Screen. Before restoring a validated backup, it quarantines the corrupt database with a timestamp. Restoration is explicit; no older database is silently substituted.

Completed reports remain until the user selects Remove. Unresolved reports require Discard Unresolved Run and a warning that recovery/review metadata will be lost. Removing reports or profiles never changes user files.

Explicit configuration migration uses a versioned JSON export/import workflow.
Exports contain only validated application settings, Sync Profiles, named
options, exclusions, and schedule definitions; run evidence, host-trust
records, recovery state, credential references, and secret values are not
exported. Imports are previewed and fully validated before one SQLite
transaction replaces editable configuration. Imported schedules are disabled,
saved-password authentication requires interactive reconfiguration, and
destructive options plus unattended authorizations are stripped so importing a
file cannot silently grant destructive or unattended authority.

## Architecture

Use a Cargo workspace with a GUI crate and a GUI-free core crate:

```text
SyncPlus/
├── Cargo.toml
├── README.md
├── rustfmt.toml
├── crates/
│   ├── syncplus-core/
│   │   └── src/
│   │       ├── model.rs          # profiles, peers, modes, options, statuses
│   │       ├── policy.rs         # safety invariants and validated options
│   │       ├── location.rs       # local/SSH structured locations
│   │       ├── precheck.rs       # permissions, space, names, identity, capability
│   │       ├── inventory.rs      # source inventory and completion reconciliation
│   │       ├── plan.rs           # explainable plan entries and counts
│   │       ├── conflict.rs       # resolutions, preserved copies, review state
│   │       ├── baseline.rs       # Mirror baseline comparison/update rules
│   │       ├── hash.rs           # streamed SHA-256 and metadata evidence
│   │       ├── transfer.rs       # typed rsync/SSH process specification
│   │       ├── parser/            # itemize, progress, and controlled diagnostics
│   │       ├── runner.rs         # process groups, cancellation, events
│   │       ├── recovery.rs       # Trash/recovery moves, manifests, Restore
│   │       ├── journal.rs        # durable per-item Action Journal
│   │       ├── scope_lock.rs     # normalized cross-profile peer locks
│   │       ├── storage.rs        # SQLite migrations, transactions, integrity
│   │       ├── backup.rs         # snapshot, gzip, validation, rotation
│   │       ├── ssh.rs            # identity, askpass protocol, capability checks
│   │       └── scheduler.rs      # typed scheduled-run entry point
│   └── syncplus/
│       └── src/
│           ├── main.rs
│           ├── app.rs            # UI state machine and event handling
│           ├── theme.rs
│           ├── help.rs
│           └── panels/
│               ├── profile_panel.rs
│               ├── locations_panel.rs
│               ├── options_panel.rs
│               ├── plan_panel.rs
│               ├── conflict_review.rs
│               ├── progress_panel.rs
│               ├── results_panel.rs
│               ├── reports_panel.rs
│               ├── recovery_panel.rs
│               └── scheduler_panel.rs
```

The core must not depend on egui. The UI and Background Scheduler both call the same core run workflow. All process execution uses `std::process::Command` with typed argument vectors and controlled environment variables; user input is never concatenated into a shell command. The command preview is generated from the same validated Process Specification used for execution.

The initial native desktop shell, typed Sync Profile editor, read-only Fresh
Analysis/precheck/Execution Confirmation review boundary, and Mirror
Conflict Review/Resolution Run review boundary are implemented in
`crates/syncplus`; reporting, recovery, and scheduler panels are delivered by
their respective child issues.

Use SQLite through a synchronous Rust driver such as `rusqlite`; asynchronous runtime infrastructure is not required for the two-pipe rsync workflow. Use transactions, schema migrations, foreign keys, integrity checks, and crash-safe journal boundaries. Database transactions do not make filesystem operations atomic, so Recovery Review remains mandatory.

## Run state machine

```text
Idle/Edit
  → Prechecking
  → Analyzing
  → PlanReview
  → ExecutionConfirmation
  → Executing
  → CompletionReconciliation
  → Completed with Review Required
  → Conflict/Recovery Review
  → Resolution Run
  → ExecutionConfirmation
  → Review-Cleared / Complete
```

Any state can become `Blocked`, `Failed`, `Cancelled`, or `Interrupted` according to the event. Editing a profile invalidates the current plan. Opening a pending report refreshes it. The final Complete control is derived from persisted unresolved-item state, not a manually editable flag.

## Rsync integration constraints

- Use deterministic, validated option builders; provide no unrestricted argument field.
- Expose named options only: mode, Safe Delete, Destination Cleanup, Resume, compression, bandwidth limit, essential metadata, specialist metadata, exclusions, SSH port/identity/auth, and retry policy.
- `--delete` is never used to implement Safe Delete. Destination Cleanup is a separate opt-in action with its own plan and confirmation.
- Itemized output and progress parsing are covered by fixture tests with chunk-split input, carriage returns, `*deleting`, escaped control characters, spaces, Unicode, and unknown flags.
- Treat rsync partial/vanished-source outcomes as incomplete until SyncPlus reconciles the current state. Exit code 0 is not a Safe Delete proof.
- Run rsync and SSH in a process group. Cancellation sends a graceful termination, escalates if necessary, records the boundary, and verifies no orphaned child processes remain.
- Partial transfer retention is explicit. Default cleanup must not delete the prior verified destination version.
- Remote capability checks must happen before any mutating SSH action.

## Implementation milestones

Each milestone must be independently testable and leave the workspace buildable.

- **M0 — Workspace and safety skeleton:** Cargo workspace, core/UI split, linting, error model, status model, README, no file-changing behavior.
- **M1 — Domain and validated options:** peers, modes, profiles, exclusions, path normalization, typed Process Specification, plain-language action model, unit tests.
- **M2 — SQLite and recovery records:** migrations, profile snapshots, reports, journals, baselines, integrity checks, atomic transactions, two-backup rotation, quarantine flow.
- **M3 — Inventory, precheck, and planning:** hidden-file inventory, exclusions, permissions, space, naming compatibility, path warnings, scope locks, Fresh Analysis, Completion Reconciliation.
- **M4 — Local transfer engine:** rsync runner, itemize/progress parsers, SHA-256, metadata verification, temporary replacements, cancellation, per-item Safe Delete, recovery moves.
- **M5 — Core UI:** Simple/Advanced mode, location mapping, options, exclusion editor, plain-language plan, generated-command diagnostics, confirmations, progress, results.
- **M6 — Conflict and recovery UX:** side-by-side read-only review, preserved copies, Resolution Runs, Restore, Recovery Review, report retention/discard flows.
- **M7 — SSH v1:** key/password interactive auth, keyring integration, host fingerprints, remote rsync/hash/recovery prechecks, local↔SSH push/pull, friendly diagnostics.
- **M8 — Scheduling v1:** per-user background scheduler, profile authorization wizard, missed-run/catch-up behavior, retry/backoff, tray/quit behavior, notifications.
- **M9 — Release hardening:** real external filesystem matrix, crash/interrupt tests, permission fixtures, SQLite corruption/recovery, SSH failure matrix, packaging, documentation, and release gates.

The release artifact includes a versioned Debian package (`.deb`) for the supported Linux architecture, a desktop entry, application icons, Help/docs assets, and the per-user Background Scheduler integration. Installation must not enable a root daemon or grant runtime privileges.

## Required tests and release gates

Tests express intended product behavior and safety contracts, not accidental implementation details.

### Core contract tests

- new profiles default to non-destructive One-Way Sync;
- Safe Delete, Destination Cleanup, Mirror, scheduling, and Permanent Removal require deliberate configuration;
- excluded and hidden files follow the documented scope rules;
- source authority, Mirror baseline, first-run deletion rules, and per-file conflict decisions are correct;
- same-hash different-path items never auto-rename or delete;
- invalid raw options, shell metacharacters, unsafe paths, nested scopes, and malformed remote fields cannot alter process intent;
- plan counts/actions and command preview match the validated Process Specification;
- stale plans are invalidated after material changes;
- the final Complete control remains hidden while required review exists.

### Safe Delete and recovery tests

- source and temporary destination SHA-256 mismatch preserves the source;
- source changes during transfer preserve the source;
- a simulated missed/unverifiable critical file remains at the source, appears in the report, blocks Complete, and can be safely resumed;
- every item is journaled before the next item settles;
- identical source/destination content is verified and can be safely removed from the source;
- destination overwrite preserves the old version until the replacement is verified;
- cancellation, crash, drive removal, process kill, and failure between destination install/source removal create correct recovery states;
- default partial cleanup does not destroy a prior verified destination; Keep Partial remains hidden and incomplete;
- same-filesystem recovery uses move; cross-filesystem recovery verifies before removal;
- Restore refuses to overwrite newer/different content;
- corrupt SQLite is not backed up, good backups are not rotated away, corrupt DB is quarantined, and explicit restore works.

### SSH and filesystem tests

- host fingerprint approval and changed-fingerprint rejection are fail-closed;
- missing remote rsync/hash/recovery capability stops before mutation;
- remote post-transfer SHA-256 mismatch preserves the source;
- missing unattended credentials do not prompt or fall back;
- the ignored disposable SSH release gate starts an ephemeral loopback `sshd`,
  verifies its approved host key through a temporary known-hosts file, and
  exercises core-generated push and pull transfers with hostile path data;
- remote paths with spaces, Unicode, control characters, and shell metacharacters remain data, not commands;
- permission failures identify the account/path and block before changes;
- real case-insensitive/restricted filesystem coverage includes NTFS, FAT32, or exFAT where available;
- case, Unicode, reserved-name, invalid-character, and path-length collisions are reported before changes.

### Scheduling and process tests

- overlapping profiles are blocked by Peer Scope Lock;
- repeated schedules coalesce and do not run concurrently;
- missed schedules explain the reason and offer Run Now/Not Now;
- Run Now is Interactive; automatic schedules are Unattended;
- unattended destructive authorization and separate permanent-removal authorization are enforced;
- bounded retries resume the affected action without replaying completed actions;
- window X hides to tray; Menu → Quit asks about active manual runs; no orphaned rsync/SSH processes remain;
- background scheduling works with the UI closed and uses no root privileges.
- the `.deb` installs cleanly, registers the desktop entry/user scheduler integration correctly, preserves the canonical XDG storage locations, and does not install or require a privileged runtime service.

### Quality and compliance gates

At every milestone run configured formatting, compiler checks, `cargo clippy -- -D warnings`, unit/integration tests, dependency/license checks, and security review of process invocation. Before release, run the disposable end-to-end matrix on local folders, an external filesystem, and a real SSH peer. The SSH gate is run with `cargo test -p syncplus-core --lib disposable_ssh_peer_exercises_push_pull_strict_identity_and_hostile_paths -- --ignored`; it requires `sshd`, `ssh-keygen`, `ssh`, and `rsync`. A green UI test suite alone is not release evidence.

## Help and user-facing requirements

Help must explain exactly what each mode and option does, why it matters, when to use it, what it may remove, what recovery costs, and what limitations apply. Important messages must identify the path, peer, account, reason, and next action.

The desktop Help catalog is the shared text source for these explanations and
exposes a visible, keyboard-addressable topic pane. Contextual links from the
profile, plan, Conflict Review, progress, Run Report, Recovery Review, and
Clone Profile surfaces select their corresponding topic. Structured precheck
diagnostics include the profile, peer, remote account when applicable, scope,
reason, requirement, and next safe action without carrying secrets or file
contents. Help and diagnostics describe safety gates; they never bypass them.
Execution failures route to failure/recovery guidance rather than precheck
guidance, and an SSH boundary without a remote probe result is reported as an
unproven requirement with the affected account and scope; it cannot be
confirmed or treated as complete.

Examples of required messages:

- “SyncPlus cannot read `/home/name/public_html` as the current user. Check ownership, group membership, and permissions, then retry.”
- “This scheduled sync did not run because the external drive was unavailable. Would you like to run it now?”
- “This profile allows unattended data deletion. Continue copying this authorization to the new profile?”
- “The destination file was verified, but the source changed during transfer. The source was preserved and needs review.”

## Deferred design work

After v1, consider SSH↔SSH, rsync daemon URLs, SSH config import, high-assurance local read-back verification of remote bytes, richer metadata/ACL support, content merge tooling, and broader platform installers. None of these may weaken the v1 safety contract when added.
