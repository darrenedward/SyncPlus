# SyncPlus agent instructions

SyncPlus is a native Linux desktop synchronization application built with Rust, `egui`/`eframe`, rsync, SSH, and SQLite. It is safety-critical file-management software: preserving user data and explaining actions are product requirements.

## Before changing code

- Read `PLAN.md`, `CONTEXT.md`, and the ADRs relevant to the change.
- Use the domain terms from `CONTEXT.md`: Sync Profile, Sync Run, Run Report, One-Way Sync, One-Way Safe-Delete Sync, Mirror Sync, Conflict Review, Source Inventory, Completion Reconciliation, Recovery Review, and Verified Removal.
- Check the working tree and preserve unrelated user changes.
- Do not invent a weaker interpretation when an ADR or the context glossary is more specific.

## Non-negotiable safety rules

- Never provide arbitrary shell or rsync argument input. Expose validated, named options only.
- Build process invocations from typed argument vectors. Never concatenate user-controlled paths, hosts, usernames, or options into shell commands.
- Never invoke `sudo`, elevate privileges automatically, modify ownership/permissions, or recommend broad permissions such as `chmod 777`.
- Never treat rsync exit code 0, a transfer count, size/mtime, or one hash as proof that Safe Delete is safe.
- Safe Delete removes one source item only after independent SHA-256 and size verification, source identity/stability checks, destination installation and final verification, and a durable journal entry.
- Preserve the source whenever anything is changed, unavailable, unverified, ambiguous, or outside the approved scope.
- Perform Completion Reconciliation before Source Drained or Review-Cleared status. Unexplained items keep the run open.
- Never silently fall back from Trash to Permanent Removal, from key authentication to another credential, or from a failed safety mechanism to a riskier operation.
- Treat Permanent Removal as irreversible. It is Advanced Mode only and requires explicit authorization for unattended schedules.
- Do not trust SSH host identity automatically. Reject changed fingerprints and require review.
- Do not put passwords, passphrases, private-key contents, or file contents in SQLite, reports, logs, previews, notifications, or sidecar manifests. Use the desktop OS keyring for saved secrets.
- Do not use a database transaction as a substitute for filesystem recovery. Record action boundaries and use Recovery Review for ambiguous crashes.

## Architecture

- Keep synchronization policy and all safety-critical logic in `syncplus-core`; it must not depend on GUI types.
- The GUI and Background Scheduler must call the same core run workflow.
- Keep process execution, parsing, inventory, hashing, prechecks, planning, journal, recovery, and storage behind small testable interfaces.
- Use SQLite as the primary nonsecret store with migrations, foreign keys, integrity checks, and crash-safe transactions. Use JSON only for explicit export/import or backup workflows; do not use YAML as live state.
- Use per-user XDG locations and user-only file permissions. The canonical live database is `~/.local/share/syncplus/syncplus.db`; validated backups are under `~/.local/share/syncplus/backups/`, quarantined databases under `~/.local/share/syncplus/quarantine/`, custom recovery under `~/.local/share/syncplus/recovery/`, and temporary data under `~/.cache/syncplus/`. Never create SQLite files beside a source, destination, project, or sync folder. Secrets belong in the desktop keyring.
- Freeze a Profile Snapshot at run start. Profile edits cannot affect an active run.
- Enforce Peer Scope Locks across profiles so overlapping scopes cannot run concurrently.
- Use process groups and verify that cancellation or termination leaves no orphaned rsync/SSH processes.
- Keep the command preview generated from the same validated Process Specification used for execution. Redact secrets.

## Packaging

- V1 ships a versioned `.deb` for the supported Linux architecture.
- Package the application binary, desktop entry, icons, Help assets, and user-level scheduler integration.
- Do not install a root daemon, grant broad capabilities, or require administrator privileges at runtime.
- Test install, launch, upgrade, uninstall, desktop-menu registration, scheduler registration, and preservation of the canonical XDG data paths.

## Synchronization behavior

- New profiles default to non-destructive One-Way Sync.
- Mirror Sync has no implicit authority; first-run absence is not deletion evidence.
- Conflict Review is read-only and whole-file based. Do not add an editable merge editor without a new decision.
- Hidden files are included by default. Exclusions prevent synchronization and deletion; Excluded Item Cleanup is a separate reviewed action.
- Preserve symlinks as links and do not follow them by default. Report unsupported special files.
- Use temporary destination files and Verified Replacement for overwrites. Preserve the old destination according to the selected recovery method.
- Same-filesystem Trash uses an atomic move. Cross-filesystem recovery requires verified copy-then-remove and sufficient space.
- Resume uses the durable Action Journal and Fresh Analysis; never blindly replay a stale plan.

## SSH behavior

- V1 supports local-to-SSH and SSH-to-local only; do not add SSH-to-SSH without a new design.
- SSH keys are the recommended authentication method. Interactive password authentication uses the controlled askpass flow; unattended runs require explicitly available noninteractive credentials.
- Preflight host identity, remote rsync capability, remote hash capability, permissions, and recovery capability before mutation.
- Verify the actual remote destination file after transfer. An unavailable or mismatched remote hash preserves the source.
- Keep remote commands fixed and controlled; safely encode user paths and never accept arbitrary remote commands.

## Testing and quality

Tests must express intended external behavior and safety contracts, not accidental implementation details. Prefer the highest seam available: core policy/inventory/journal tests first, then real filesystem/process integration, then UI tests.

At minimum, cover:

- all modes and deletion policies;
- missed, changed, locked, unreadable, and critical files;
- SHA-256 mismatch and source-preservation behavior;
- destination overwrite protection and Recovery Review;
- cancellation, crash, disconnect, resume, and orphan-process cleanup;
- SQLite backup rotation, corruption, quarantine, and explicit restore;
- SSH identity, credential, rsync/hash capability, and remote verification failures;
- filename collisions on a real case-insensitive/restricted filesystem;
- shell/argument injection attempts and secret redaction;
- schedule overlap, missed-run notices, bounded retries, and authorization boundaries.

Run the configured checks before handoff, including `cargo fmt --check`, `cargo test`, and `cargo clippy -- -D warnings`. Add dependency/license/security checks when the project tooling is established. Do not claim release readiness without the disposable end-to-end safety matrix in `PLAN.md`.

## Change discipline

- Keep changes narrow and explain user-visible safety consequences.
- Use `apply_patch` for local edits.
- Do not reset, clean, stash, overwrite, or delete unrelated work.
- Do not remove a safety check to make a test or transfer pass.
- Update `PLAN.md`, `CONTEXT.md`, or an ADR when behavior or architecture changes.

## Agent skills

### Issue tracker

GitHub Issues in the public `darrenedward/SyncPlus` repository; external PRs are not a triage request surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix` labels. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout using root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
