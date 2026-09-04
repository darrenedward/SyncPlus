# SyncPlus

SyncPlus helps users review and apply file synchronization between local or remote locations, with explicit visibility into changes that may overwrite or remove data.

## Synchronization

**Peer**:
One of the two locations participating in a bidirectional synchronization. Neither peer is inherently authoritative.
_Avoid_: Source, destination, master

**Sync Profile**:
A saved, editable configuration containing two peer endpoints, synchronization mode, validated options, exclusions, and—when explicitly enabled—schedule and unattended authorization settings. A profile is configuration, not an execution result.
_Avoid_: Job, task, stored command

New profiles default to non-destructive One-Way Sync with Safe Delete and Destination Cleanup disabled. Mirror Sync and all deletion options require deliberate selection.

**Sync Run**:
A single reviewed operation that compares peers, presents proposed file actions, and applies only the actions the user approves.
_Avoid_: Job, copy

At execution start, a Sync Run captures a frozen Profile Snapshot containing its endpoints, mode, options, exclusions, and applicable authorizations. Editing a profile or schedule cannot change an active run; changes apply to a later run and require a new analysis.

**Conflict**:
A path whose relevant contents or metadata changed independently on both peers, requiring a user decision before either copy is applied.
_Avoid_: Error, mismatch

**Path Identity**:
The location of an item within a particular peer. A matching path is the default basis for comparing items; matching content at different paths is only evidence of a possible rename or duplicate.
_Avoid_: File identity, filename identity

**Content Match**:
Two regular files have identical byte content according to the selected content comparison. A content match does not by itself establish that the files represent the same logical item.
_Avoid_: Same file, same identity

**Sync Baseline**:
The last agreed state of a peer pair, used to distinguish an unchanged item, an edit, a new item, and a deletion during a later sync run.
_Avoid_: Cache, backup

The first Mirror Sync has no Sync Baseline. One-sided items are treated as copy candidates, not inferred deletions; deletion requires an explicit Resolution.

Only paths successfully reconciled and verified enter the Sync Baseline. Skipped, failed, unstable, or otherwise unresolved paths remain unsettled.

The baseline is durable SQLite evidence associated with the Sync Profile and
peer pair. Later comparisons classify each peer's path state as unchanged,
new, changed, or absent using Mirror Equality; content and item type are always
fundamental, while other fields are checked only when their named metadata
requirement is enabled.

**Resolution**:
The per-path decision that determines whether a conflict is copied from peer A to peer B, from peer B to peer A, preserved on both peers, skipped, or otherwise handled.
_Avoid_: Merge, overwrite

The typed Mirror choices are **Keep Peer A**, **Keep Peer B**, **Preserve Both**,
**Rename/Preserve for Review**, and **Defer**. SyncPlus requires one decision for
each reviewed path and a final Execution Confirmation before exposing any
whole-file copy operation. Preservation and deferral never remove either peer
version and keep the run reviewable.

**Removal**:
An action that deletes a path from one peer because the reviewed synchronization decision requires it to be absent there.
_Avoid_: Cleanup, overwrite

**One-Way Safe-Delete Sync**:
A one-way sync with the Safe Delete option enabled: it copies the selected source scope to the destination, verifies each destination result, and then removes the corresponding source item. The source is drained only after successful handling; failed or skipped items remain at the source and make the run incomplete.
_Avoid_: Mirror, bidirectional sync

**Sync Option**:
A user-selected policy that changes how a Sync Run is planned or applied, such as progress display, resumable transfer behavior, or source cleanup. An option may be implemented using one or more rsync arguments and application-level steps.
_Avoid_: Raw flag, command-line switch

**Metadata Requirements**:
The frozen set of file metadata that a Sync Run must preserve and verify before an action can enter the Verified Removal boundary. V1 requires file type, executable permissions, and symlink targets by default; timestamps are an explicit supported option. Unsupported specialist metadata remains a future Advanced option and cannot be silently ignored.
_Avoid_: Best-effort metadata, metadata inferred from a successful process

**Safe Delete**:
A Sync Option that permits source removal only after the destination result has been verified. It is distinct from rsync's destination-deletion behavior.
_Avoid_: `--delete`, force delete

**Destination Cleanup**:
A separate Sync Option that removes destination items absent from the selected source scope. It must never be implied by Safe Delete, which removes verified source items instead.
_Avoid_: Safe delete, source cleanup

**One-Way Authority**:
In a one-way sync, the selected source is authoritative for conflicting content; the destination version is overwritten according to the reviewed plan.
_Avoid_: Newest wins, destination authority

**Per-Path Override**:
A user decision that changes the default One-Way Authority for one reviewed path, such as retaining the destination version and removing the source under Safe Delete.
_Avoid_: Global mode change, conflict auto-resolution

**Approved Sync Scope**:
The set of source paths that the user has included and approved for a particular Sync Run. Safe Delete may remove only paths in this scope that were successfully handled and verified.
_Avoid_: Everything in the folder, scanned files

**Destination Cleanup** is opt-in and disabled by default. Enabling it is an explicit request to remove destination items absent from the source and requires destructive-action confirmation.

**Safe Delete** is also disabled by default. A manually started run with Safe Delete enabled requires a fresh destructive-action confirmation even when the option came from a saved profile. An automatic Scheduled Run requires the profile's explicit Unattended Destructive Authorization.

Safe Delete is a source-draining workflow, not a best-effort cleanup. It records an approved source inventory, verifies each destination result before removing its source item, and performs a final independent reconciliation. Any unexplained, excluded, newly appeared, changed, failed, or otherwise still in-scope source item keeps the run incomplete and prevents the final **Complete** action.

Simple Mode offers recoverable Trash deletion where supported. Permanent Removal is available only in Advanced Mode, is labeled as irreversible, and requires fresh confirmation for every run; it is never silently substituted when Trash is unavailable.

Manual Safe Delete runs ask for the Deletion Method every time. An authorized automatic schedule uses the method explicitly selected in its profile. If that method is unavailable, the schedule stops and notifies the user instead of falling back.

For an SSH peer, Trash mode is available only when SyncPlus can verify a configured remote recovery location and the remote account can use it. Otherwise the deletion stops or requires explicitly authorized Permanent Removal; SyncPlus never silently substitutes a remote `rm` operation.

When the recovery location is on the same filesystem as the item, SyncPlus uses an atomic move into recovery and does not copy the data first. When it is on a different filesystem, it may use copy-then-independent-verify-then-remove, with a space precheck; failure at any stage preserves the original.

Each recoverable item has provenance metadata: original peer and relative path, run identifier, removal time, item type, and SHA-256 where applicable. Restore must recheck the current target and never overwrite newer content without a separate reviewed decision.

SQLite is the primary recovery record. For custom or remote Recovery Folders, SyncPlus also writes a small sidecar manifest beside the recovered item because the database backup may predate the current run. Local operating-system Trash uses its native provenance metadata instead of duplicating an equivalent sidecar. Sidecars contain no secrets or file contents.

**Path Risk Warning**:
An advisory shown for one-way Safe Delete when the selected source appears broad or system-sensitive. Common user-data subdirectories such as `/home/<user>/projects`, `/home/<user>/public_html`, and user-owned folders on `/mnt` or `/media` normally receive no special path warning. Roots and system-sensitive paths such as `/`, `/home`, `/root`, `/etc`, `/usr`, `/var`, `/boot`, `/bin`, `/sbin`, `/lib`, `/dev`, `/proc`, and `/sys` receive a clear warning. The list is platform-aware and advisory, not an allow/deny rule; an old server volume may still proceed after the user understands the warning.

Mirror Sync does not show this special source-draining path warning. It still shows ordinary per-action deletion consequences and requires the normal review and confirmation for any removal.

Reports distinguish **Source Drained**—every approved, included item was verified and removed—from **Source Not Empty**—the source still contains exclusions, newly appeared items, failures, or unresolved items. The report must list the reasons and affected paths rather than implying that the whole source folder is empty.

**Execution Confirmation**:
The final explicit approval of the reviewed Sync Run immediately before destructive or data-changing actions begin. It summarizes the affected paths and action counts; per-path conflict decisions happen in the plan before this approval.
_Avoid_: Checkbox acknowledgement, implicit approval

**Verified Removal**:
Removal of a source item only after the selected destination result has been cryptographically verified and any enabled metadata requirements have been satisfied. A successful transfer process alone is not sufficient.
_Avoid_: Delete after copy, best-effort cleanup

Verified Removal is performed per item. SyncPlus hashes the source and temporary destination independently, compares SHA-256 and size, rechecks source identity and stability, installs the destination only after verification, verifies the installed result, and then removes or Trashes that exact source item. It proceeds to the next item only after the current item's removal outcome is journaled. Any uncertainty preserves the source.

**Safe Delete Proof Boundary**:
The point after an individual destination has been independently verified, the source is confirmed unchanged and still identifies the same item, and the deletion method is available. Only this boundary authorizes removal of that source item. A process exit code, transfer count, or one earlier matching hash is not sufficient.
_Avoid_: Batch deletion based on a plan, trusting rsync success alone, or deleting a path after its identity changed

**Deletion Method**:
The explicitly selected way a reviewed Removal is applied: move to a supported local Trash or permanently delete. The method must be visible in the Execution Confirmation and must not silently fall back to another method.
_Avoid_: Cleanup mode, automatic fallback

Manual Safe Delete runs ask for the Deletion Method every time. An authorized automatic schedule uses the explicitly selected profile method, records it with the run, and stops if that method is unavailable. A saved profile cannot silently select Permanent Removal for a manual run.

**Trash Removal**:
Moving a source item to the operating system or volume Trash when supported. It can be recovered, but it may continue consuming space and is not assumed to exist for remote SSH peers.
_Avoid_: Freed space, permanent deletion

**Permanent Removal**:
Irreversibly deleting a verified source item to reclaim its space. It requires explicit Execution Confirmation for manual runs or separate Unattended Permanent Removal authorization for an automatic schedule.
_Avoid_: Safe delete, recoverable cleanup

**Changed During Sync**:
A source item whose content or relevant metadata changed after planning or while it was being copied. It requires user review, is never eligible for Verified Removal in that run, and must be reported with enough context to identify possible causes such as an open editor, a growing log, or a system process.
_Avoid_: Transfer failure, harmless race

**Interactive Run**:
A Sync Run that pauses when a reviewable item such as Changed During Sync is detected and requests the user's decision before continuing that item.
_Avoid_: Live mode, attended mode

**Unattended Run**:
A Sync Run that continues with unaffected items and defers reviewable items until completion, notifying the user and preserving any item that was not safely verified. It may bypass waiting for user input, but it never bypasses Verified Removal.
_Avoid_: Force mode, force delete, unsafe mode

**Pending Review**:
The result state for items that an Unattended Run could not safely finish, such as files that changed during transfer. The items remain preserved and can be opened later in Conflict Review.
_Avoid_: Completed, ignored, abandoned

**Resolution Run**:
A follow-up Sync Run created from a Pending Review decision. It rechecks the current peer versions, applies the selected per-path resolution, and performs a new Execution Confirmation when the resolution changes or removes data.
_Avoid_: Retry blindly, resume prompt

**Rename Resolution**:
An explicit decision to preserve an item under a different path, normally after matching content or resolving a name conflict. Both the original and new paths remain visible in the Run Report and available for later review; the rename does not itself authorize deleting either copy.
_Avoid_: Automatic rename, inferred move

**Preserved Conflict Copy**:
A renamed or duplicated item retained so both versions remain available while the user decides whether one can be removed. It is not silently treated as disposable.
_Avoid_: Temporary file, junk copy

Preserved Conflict Copies use deterministic, human-readable generated names such as `report (Peer A).pdf` and `report (Peer B).pdf`. The planned names are shown before execution and receive collision-safe suffixes when needed.

**Review Later**:
A report state for a Preserved Conflict Copy or other unresolved choice that remains intentionally available until the user makes a separate decision.
_Avoid_: Ignored, completed deletion

**Run Report**:
The retained human-readable record of a Sync Run's results, grouped by outcomes such as copied, overwritten, removed, renamed, excluded, deferred, failed, and unresolved.
_Avoid_: Raw log, terminal output

**Mirror Sync**:
A reconciliation operation in which both peers remain populated and are brought to the same agreed result. Changes and deletions may flow in either direction, and conflicts require explicit resolution.
_Avoid_: One-way sync, move

**Mirror Invariant**:
After a successful Mirror Sync, both peers contain the same approved files and content within the selected scope. A missing item must be restored or explicitly removed from the other peer; it cannot remain unresolved.
_Avoid_: Best effort mirror, mostly synced

Mirror resolutions apply to both peers. If one side succeeds and the other fails, the run is incomplete and the mismatch remains visible for review; SyncPlus must not claim the Mirror Invariant was restored.

**Mirror Conflict**:
A path with different content on both peers during Mirror Sync. It has no implicit winner and must receive an explicit per-path Resolution before execution.
_Avoid_: Newest wins, automatic merge

**Partial Mirror Run**:
A Mirror Sync in which an approved change succeeded on one peer but not the other. It keeps successful work, leaves the mismatch visible, does not settle the affected path in the Sync Baseline, and offers repair or retry.
_Avoid_: Rolled back, mostly complete, successful mirror

**Interrupted Run**:
A Sync Run that stops because the app closes, the process crashes, the user cancels, or the transport ends unexpectedly before all approved actions are settled. Its report remains available for re-analysis and safe resume.
_Avoid_: Successful completion, lost run

**Resume**:
A new analysis of an Interrupted Run's remaining scope against the current peers, followed by fresh review and confirmation where needed. Resume never blindly replays the old plan.
_Avoid_: Continue blindly, replay

**Action Journal**:
The durable per-path record of a Sync Run's planned action, pre-action state, start, progress, and final outcome. It distinguishes completed, cancelled, interrupted, failed, deferred, and unresolved work; an open boundary is classified before a safe resume.
_Avoid_: Terminal log, aggregate count only

**Cancelled Action**:
An action stopped at the user's request before it reached a verified successful outcome. It is never included in completed or Verified Removal totals, and its source item remains preserved.
_Avoid_: Successful cancellation, failed transfer

By default, cancellation removes partial destination data. The user may explicitly choose Keep Partial for Resume; retained partial data remains hidden, incomplete, and outside the settled Sync Baseline until verified.

**Mirror Equality**:
The definition of “same” for a Mirror Sync: content and item type are fundamental, while permissions, timestamps, ownership, ACLs, extended attributes, and symlink behavior are included only when their corresponding options are enabled.
_Avoid_: Byte-identical, completely identical

Essential transfer fidelity includes regular-file content, file type, executable permissions, and symlink targets by default. Ownership, ACLs, extended attributes, and other specialist metadata are Advanced options; when enabled, their application and verification are part of the action's success criteria.

**Safety by Default**:
The product rule that ordinary actions preserve data, destructive options are opt-in, unsafe path relationships are blocked, and no action is hidden behind an ambiguous label or implicit fallback.
_Avoid_: Expert-only safety, best-effort safety

**Explainable Action**:
A planned sync action presented with its plain-language consequence, affected side, affected paths or counts, and any recovery or space implications before execution.
_Avoid_: Technical output only, opaque operation

Simple Mode presents Explainable Actions and plain-language summaries by default. Advanced Mode may reveal the exact generated command and technical diagnostics, but command previews and copyable output always redact passwords, key material, and other secrets. The Help section provides detailed explanations for users who want them.

Folder selection in Simple Mode abstracts rsync trailing-slash semantics and states the resulting mapping explicitly, such as “copy the contents of `public_html` into the remote `public_html` folder.” Advanced Mode may show the exact path syntax and generated command.

**Help Guidance**:
Plain-language information that explains what an option or result means, why it matters, when to use it, and what consequences or limitations apply.
_Avoid_: Reference dump, jargon-only help

The desktop Help & Support page presents each topic with What, Why, How, When,
Consequences, Limitations, and Next safe action text. Profile, plan, Conflict
Review, progress, Run Report, Recovery Review, and Clone Profile surfaces link
to the relevant topic in the dedicated Help & Support page. Precheck diagnostics identify
the Sync Profile, peer, remote account when applicable, exact scope, safety
requirement, reason, and remediation. These links and diagnostics explain a
blocked or review-required state; they never authorize bypassing prechecks,
verification, host-identity review, confirmation, or Recovery Review.
When a configured SSH peer reaches a desktop boundary without a remote probe
result, the diagnostic says that the required host, credential, account,
capability, and recovery evidence is not proven and keeps execution blocked.

**Simple Mode**:
The default SyncPlus experience showing the common source, destination, mode, exclusions, safety options, and run actions without exposing specialist filesystem or transport controls.
_Avoid_: Beginner mode, limited mode

**Advanced Mode**:
An opt-in view exposing additional comparison, metadata, transport, and performance controls for experienced users. It follows the same safety policies as Simple Mode.
_Avoid_: Unsafe mode, expert bypass

The first launch uses Simple Mode. SyncPlus remembers the user's Simple Mode or Advanced Mode preference across restarts, and either mode remains subject to all safety policies.

**Symlink Policy**:
The default rule that synchronization preserves a symbolic link as a link and does not follow it into another file or directory. Following links requires an explicit future policy.
_Avoid_: Follow links, dereference by default

**Desktop File Scope**:
The normal user-facing scope of regular files, folders, and symbolic links. Unusual system filesystem objects are outside this scope, are not followed or removed implicitly, and are reported plainly when encountered.
_Avoid_: Full filesystem semantics, special-file support

**Hidden Item Policy**:
Hidden files and folders are included in the Approved Sync Scope by default. Users may explicitly exclude them or other paths, and excluded items are never eligible for Safe Delete.
_Avoid_: Dotfile omission, hidden means ignored

**Exclusion Rule**:
A user-entered pattern that removes matching items and their descendants from the Approved Sync Scope. Exclusions prevent synchronization and Safe Delete; they do not imply deletion.
_Avoid_: Ignore means delete, filter after transfer

Exclusion patterns use intuitive scope matching: file patterns such as `*.tmp` match files anywhere below the selected source, while directory patterns such as `node_modules/` exclude the matching subtree. The UI previews the matching count before execution.

**Excluded Item Cleanup**:
A separate, optional cleanup action that lets the user review and explicitly remove selected excluded items from a chosen peer after a Sync Run. It is never automatic and requires its own Execution Confirmation.
_Avoid_: Automatic cleanup, Safe Delete

For one-way sync, Excluded Item Cleanup targets the source by default. Destination cleanup remains a separate explicit action.

**Conflict Review**:
A read-only side-by-side or split-pane comparison used for any item requiring a user decision, including same-path Mirror Conflicts, possible rename/duplicate candidates, and Destination Compatibility Conflicts. It shows content differences when files are safely readable and metadata, sizes, types, and hashes otherwise. The review presents the available Resolution choices before execution; it does not edit or merge file content.
_Avoid_: Automatic merge, text editor

Same-hash files at different paths open this same review with both paths visible. The matching hash is presented as evidence of byte equality, not as an automatic rename, merge, or deletion decision.

The core `ConflictReview` boundary is read-only and structured. It retains
both same-path evidences, limits text previews to a bounded in-memory size,
and represents binary, large, or unreadable items with safe type, size, and
hash evidence. Destination compatibility findings use the same review entry
boundary.

**Saved Secret**:
Sensitive authentication material that SyncPlus may use for a saved connection, such as a password. Saved Secrets are optional, are not written into profiles or history, and are stored through the desktop OS keyring where available.
_Avoid_: Credential in config, password in profile

**App Lock PIN**:
An optional local PIN that controls access to SyncPlus and its Saved Secrets. It is not an account password and cannot be reset to recover encrypted secrets.
_Avoid_: Master password, recovery password

**PIN Reset**:
A local recovery action for a forgotten App Lock PIN that removes encrypted Saved Secrets while preserving nonsecret settings and requiring credentials to be entered again.
_Avoid_: Password recovery, silent unlock

**SSH Server Identity**:
The remembered host-key fingerprint used to recognize an approved SSH server. A new server requires explicit approval; a changed fingerprint is rejected and reported for review.
Core host-trust evaluation exposes a pre-mutation permit only for an unchanged approved fingerprint; first-use and changed identities remain review decisions, and unattended runs cannot persist approval.
_Avoid_: Hostname alone, automatic trust

**SSH Authentication Preference**:
SSH key authentication is the recommended default and is presented through a simple connection flow; password authentication is an optional fallback and, if saved, uses a Saved Secret in the desktop keyring.
The core represents a saved password with an opaque reference and resolves exactly the selected method; a missing key, keyring secret, or controlled prompt stops the run without trying another credential.
_Avoid_: Password-first, key-only UI requirement

**SSH Connection Wizard**:
The Simple Mode flow for connecting to a remote peer using only the server, username, authentication choice, and key or password needed for the connection. Technical SSH controls remain in Advanced Mode.
_Avoid_: Raw SSH configuration, command-line setup

For an Unattended Run, an unapproved or changed SSH Server Identity stops the affected remote operation, preserves source items, and creates a user notification for interactive review.

SSH is a first-release peer type alongside local folders and external drives. Its first-release scope includes the same precheck, review, verification, confirmation, cancellation, resume, and reporting guarantees; SSH-specific capability and identity checks are mandatory rather than deferred features.
The shared core executes local-to-SSH and SSH-to-local runs through one typed SSH backend boundary. The boundary must recheck remote capabilities around confirmation, supervise SSH and rsync in the run's process group, stage destination-side data before installation, and return endpoint-bound metadata and content proofs; the platform adapter owns the network runtime while the core owns policy and journal decisions.
For remote Safe Delete, the same boundary exposes only verified remote Trash recovery: the adapter receives the journaled transfer proof, performs a controlled recovery operation, writes content-free provenance for custom/remote recovery, and returns evidence that the core validates and persists. Any unavailable or ambiguous recovery preserves the source and keeps the action in Recovery Review; Permanent Removal requires separate authorization and never occurs as fallback.

First-release SSH topology is one local peer and one SSH peer: local-to-SSH or SSH-to-local. SSH-to-SSH synchronization is outside the first-release scope.

**Scheduled Run**:
An optional recurring execution of a saved Sync Profile, available only in Advanced Mode and disabled by default. A Scheduled Run starts as Unattended and remains subject to all Run Precheck, verification, review, confirmation or explicit unattended authorization, source-preservation, and recovery rules. It cannot bypass unresolved review items or silently weaken a safety option.
_Avoid_: Hidden schedules, Simple Mode scheduling, or unattended execution that ignores pending safety decisions

**Background Scheduler**:
The per-OS-user scheduling component that can start authorized Scheduled Runs while the SyncPlus window is closed. It runs without root/administrator privileges, uses the profile's normal permissions and credentials, cannot bypass SyncPlus safety invariants, and persists reports and notifications for later review.
_Avoid_: Root daemons, hidden privileged services, or schedules that work only while the window is open

Closing the SyncPlus window hides it to the system tray and does not interrupt an active run. **Quit** is a separate action; when a manual run is active, it asks whether to stop and recover it. A crash or forced termination creates an Interrupted Run and follows the cleanup and resume policy.

If the user selects **No**, the active run continues. If the user selects **Yes**, SyncPlus stops the run safely, records the interrupted state, preserves the source, and applies the partial-transfer cleanup policy. When schedules are enabled, quitting the foreground UI does not disable the separate Background Scheduler; disabling schedules is a separate explicit action.

**Unattended Destructive Authorization**:
An explicit Advanced Mode, per-profile authorization allowing an automatic Scheduled Run to perform otherwise destructive actions such as Safe Delete, Destination Cleanup, or Permanent Removal while the user is away. It is granted only after a clear consequence warning, is revocable, and is recorded with each run. It authorizes unattended execution but never bypasses technical safety invariants or permits action when precheck, verification, reconciliation, or identity checks fail.
_Avoid_: Global destructive permission, hidden opt-in, or treating trust as a substitute for verification

Unattended Permanent Removal requires a separate authorization from unattended recoverable deletion. Authorizing Safe Delete or Trash does not authorize irreversible removal.

**Unattended Credential Availability**:
The condition that an automatic SSH run can authenticate without an interactive prompt, using an explicitly configured key, an available SSH agent, or a Saved Secret from the desktop keyring. If the credential is unavailable or requires user input, the run stops safely, preserves the source, and notifies the user.
_Avoid_: Hidden password prompts, automatic secret capture, or unattended fallback to another credential

**Retry Policy**:
A bounded setting controlling retries for transient transfer or connection failures. The default is 3 attempts, with increasing delays between attempts. Retries stop when the limit is reached; the affected action is deferred or failed with a clear explanation, and its source remains preserved. Permanent errors are not retried.
_Avoid_: Infinite restart loops, retrying destructive finalization blindly, or treating repeated transport failure as success

Retries are resumptions, not fresh runs: completed and verified actions are not replayed, and the current action resumes only from a validated transfer boundary. A retry never authorizes source removal without repeating the required verification.

**Source Inventory**:
The recorded set of source items eligible for a specific Sync Run after hidden-file handling and Exclusion Rules are applied. It is used to detect missed, changed, newly appeared, and unresolved items during final reconciliation. An inventory is evidence for the run, not permission to delete an item by itself.

**Completion Reconciliation**:
The final independent comparison of the current source and destination against the approved Source Inventory and Action Journal. Safe Delete cannot become Review-Cleared while an eligible source item lacks a verified destination result or while the app cannot explain why a source item remains.
_Avoid_: Declaring success from process exit code, transfer count, or partial per-file results alone

The shared core performs this comparison after each workflow run, persists the Source Inventory and typed findings in SQLite, and for Mirror persists one frozen inventory per peer. Mirror Resolution Runs also persist each reviewed outcome and preserved-copy original/generated path. Keep Peer A/B decisions are reconciled against the selected post-resolution version on both peers; a missing current peer is recorded as Unavailable, a missing proof is Unverifiable, and preserved, deferred, failed, or unresolved work remains review-required.

The contract test suite must include a simulated missed or unverifiable critical source item. The expected behavior is source preservation, clear reporting, blocked **Complete** action, and safe resume after correction. This is a release-blocking safety test.

Release verification also includes real external-filesystem coverage for at least one case-insensitive or restricted filesystem such as NTFS, FAT32, or exFAT, alongside portable unit tests. The test must prove that naming collisions and unsupported paths are detected before changes.

V1 release gates include disposable end-to-end tests for local Safe Delete and SHA-256 verification, missed or unreadable files, destination disconnect, permission failure, interrupted resume, SQLite recovery, SSH transfer and remote verification, and case-insensitive filename collisions. A passing UI test suite alone is insufficient evidence.

**Recovery Review**:
The review state for an item where interruption may have occurred between verified destination installation, source removal, or journal persistence. Resume rechecks current source and destination state before deciding whether the item is settled; it never blindly repeats an uncertain deletion. Recovery Review keeps the run open until the result is proven or explicitly resolved.
_Avoid_: Assuming a crash means either “nothing happened” or “everything succeeded”

Only one run may actively operate on a given profile's peer pair at a time. If a schedule fires while that profile is running, SyncPlus does not start a concurrent run. It records a Skipped Schedule event and notifies the user; **Dismiss** closes the notice but does not erase the event or authorize another run.

**Peer Scope Lock**:
A runtime lock over normalized local or remote peer scopes. SyncPlus blocks concurrent runs from different profiles when their source or destination trees overlap, not only when their profile names or exact endpoint strings match. The lock protects hashes, action journals, transfers, and deletion decisions from races.
_Avoid_: Per-profile-only locking, string comparison without normalization, or concurrent overlapping transfers

**Missed Schedule Notice**:
A notification explaining why a Scheduled Run did not start, such as an unavailable drive, failed precheck, or overlapping active run. It offers **Yes, Run Now** and **No, Not Now**. Run Now starts one catch-up execution only after a Fresh Analysis and Run Precheck; Not Now records the decision and leaves the missed event visible.

A Scheduled Run that starts automatically remains Unattended. A user selecting **Yes, Run Now** is explicitly starting the catch-up execution, so that execution becomes Interactive and presents its fresh plan and required confirmation.

**Remote Rsync Capability Preflight**:
Before any SSH-backed Sync Run can change files, SyncPlus verifies that the remote peer has a compatible `rsync` capability and that the required invocation is supported. A connection that authenticates successfully is not sufficient. If the capability is missing or incompatible, the affected operation stops before file changes, preserves the source, and reports clear remediation.
The core remote precheck accepts only a selected credential and approved host-identity permit, checks the remote account's requested access, hashing, rsync, and verified Trash capabilities, and yields no execution permit while any requirement is missing.
_Avoid_: Starting a transfer after connectivity-only checks, silently installing tools, or falling back to an unverified destructive method

**Run Precheck**:
The non-mutating validation phase before Analyze and Execution Confirmation. It checks the selected paths, source readability, destination writability, required removal permissions, path overlap, available space, Trash capacity when relevant, and remote capability when using SSH. Hard blockers prevent the run; clearly labeled warnings may require acknowledgement without silently changing the requested safety policy.
_Avoid_: Treating a successful path selection or SSH login as proof that a run is safe to execute

The Run Precheck also evaluates destination naming rules. It detects case-insensitive and Unicode-normalization collisions, reserved or invalid names, path-length limits, and other filesystem restrictions that could make distinct source items collide or fail at the destination. These findings are shown before confirmation and block affected actions until resolved.

Required permission failures are hard blockers before any run changes files. SyncPlus identifies the affected path, the current operating user or remote account, and the required access, then advises the user to correct ownership, group membership, or permissions and retry. SyncPlus never invokes `sudo`, changes permissions automatically, or recommends broad access such as `chmod 777`.

If access changes during execution, the affected item is preserved and unresolved; a Safe Delete run cannot be reported as complete. The user must correct access and retry or resolve the item explicitly.

**Destination Compatibility Conflict**:
A source path that cannot be represented safely at the selected destination because of case folding, Unicode normalization, reserved names, invalid characters, path length, filesystem restrictions, or equivalent naming rules. SyncPlus must not silently rename, overwrite, or omit the item; it reports the exact paths and requires an explicit resolution.
_Avoid_: Assuming the source filesystem's naming rules apply at the destination

**Clone Profile**:
An action that creates a new editable Sync Profile pre-filled from an existing profile. The editor shows both endpoints and requires at least one endpoint to differ before the new profile can be saved; an identical source/destination pair is rejected. Cloning copies validated nonsecret settings, clears saved credential references for intentional reconfiguration, and never copies, displays, or exports secret values.
_Avoid_: Silent duplicate profiles or secret duplication during cloning

If a profile contains an Unattended Destructive Authorization, the Clone Profile wizard must explicitly disclose that permission and ask whether to copy it. The user may continue with the authorization, disable it for the clone, or cancel. Unattended Permanent Removal remains a separate confirmation.

**Fresh Analysis**:
A new comparison of the current source and destination state immediately before a plan is confirmed. Saved profiles may provide settings, but never reuse an old file-change plan. Material changes invalidate the prior plan and require the user to review the new result.
_Avoid_: Blindly replaying stale plans after files, permissions, mounts, or remote state may have changed

Fresh Analysis is triggered when a user opens a pending, interrupted, or review-needed Sync Run and again immediately before confirmation or execution. Completed reports remain historical records and are not silently recalculated.

**Verified Replacement**:
A destination overwrite process that writes the incoming content to a temporary destination-side file, verifies the result, and only then replaces the existing destination item. The existing destination remains intact if transfer, verification, cancellation, or cleanup fails.
_Avoid_: Deleting the existing destination before the replacement is verified

When a Verified Replacement supersedes a different existing destination item, the old item follows the run's selected deletion method after the incoming content is verified. If the files are already byte-identical, SyncPlus performs no replacement or deletion. Trash unavailability blocks a Trash-mode overwrite rather than silently converting it to permanent removal.

**Execution Result**:
The outcome of the file operations in a run. It can show that transfers finished even when the run still has unresolved conflicts, deferred items, or failed actions. Execution Result is not the same as a fully cleared run.

**Review-Cleared Run**:
A run whose required conflicts, deferred items, failures, and preserved copies have all received an explicit resolution, and whose resulting actions have completed successfully. The final **Complete** action is available only when no required review items remain; until then the run stays visible and revisitable.
_Avoid_: Treating a finished transfer pass as permission to hide unresolved work

**Unresolved Item**:
A file or directory that was skipped, unavailable, locked, changing, failed, cancelled, or otherwise lacks a successfully completed resolution. An Unresolved Item keeps the run open and prevents the final **Complete** action. Removing an item from scope is itself an explicit, recorded resolution and must explain that the item will remain outside the run.
_Avoid_: Treating Skip as success or silently dropping an item from the report

An external-drive disconnect, unmount, or equivalent destination loss is an interruption. Affected actions stop, incomplete temporary data is removed by default, source items remain preserved, and the report remains available for safe resume after the destination returns. Safe Delete is never allowed for an action whose destination became unavailable.

**Volume Identity Check**:
The verification that a resumed local task is connected to the same external volume recorded when the task was created or last safely completed. A matching mount path is insufficient. A missing or changed identity blocks resume until the user explicitly confirms the replacement device.
_Avoid_: Resuming onto whichever device happens to reuse the same path

**Validated Sync Option**:
A named, typed setting controlled by SyncPlus, such as Safe Delete, Resume, Destination Cleanup, metadata preservation, bandwidth limit, or an exclusion pattern. Options are validated against the selected mode and cannot inject arbitrary shell or `rsync` arguments.
_Avoid_: Raw command fields, free-form shell input, or silently conflicting flags

**Mirror Deletion Decision**:
The reviewed decision to propagate a deletion from one Mirror peer to the other. A baseline may provide evidence that the deletion was intentional, but absence alone never authorizes removal. The decision must be visible in the plan and included in final confirmation.
_Avoid_: Treating baseline inference as silent deletion permission

The decision is available only for a candidate backed by a two-sided baseline,
where the missing peer is absent and the remaining peer is still unchanged.
Deletion, preservation, or deferral is selected per path; failed removal keeps
the remaining copy and leaves the Mirror Invariant unresolved.

**Content Verification Hash**:
The streamed SHA-256 digest used when SyncPlus needs cryptographic evidence that two regular files have identical bytes or that a destination transfer is safe for Verified Removal. Metadata may avoid unnecessary hashing, but metadata equality alone is not verification. Equal hashes at different paths indicate byte equality, not automatic logical identity or rename.
_Avoid_: Treating size/mtime as proof, or automatically merging same-hash files at different paths

For SSH destinations, SyncPlus must obtain a SHA-256 digest of the actual remote destination file after transfer and compare it with the source digest. A successful rsync exit code is not sufficient. If the remote digest is unavailable or differs, the source remains preserved and the action is unresolved.

**Run Report Retention**:
Completed run reports remain available until the user deliberately removes them with a clear Remove action. Unresolved or review-pending runs are not automatically removed. Reports contain operational metadata and decisions, not file contents or saved secrets.
_Avoid_: Automatic expiry of unresolved reviews or hidden report deletion

Completed reports use **Remove**. Unresolved, interrupted, or review-pending reports use a separate **Discard Unresolved Run** action with a clear warning that recovery state, action history, and pending review information will be lost. Discarding a report never changes user files.

**Application Database**:
The SQLite database used as SyncPlus's primary store for nonsecret settings, profiles, schedules, host fingerprints, run reports, action journals, Sync Baselines, hashes, and recovery state. It uses transactions and crash-safe persistence. JSON is reserved for explicit export/import or backup; YAML is not a live storage format. Saved credentials remain in the desktop keyring.
_Avoid_: Split competing JSON state stores, YAML configuration, or secrets in SQLite

Before a destructive run, SyncPlus creates a small rotating backup of the Application Database. This protects profiles, baselines, action journals, and recovery records, but it does not restore user files or replace Trash/recovery handling.

Explicit configuration migration is a versioned JSON workflow, not a second
live store. An export contains validated application settings, Sync Profiles,
named Sync Options, exclusions, and schedule definitions. It does not contain
run evidence, SSH host-trust records, recovery state, passwords, passphrases,
private-key contents, keyring values, or saved credential references. Imports
are previewed and validated as a complete document before an atomic SQLite
replacement of editable configuration. Imported schedules are disabled,
saved-password authentication becomes interactive reconfiguration, and Safe
Delete, Destination Cleanup, deletion methods, and unattended authorizations
are stripped until the user deliberately configures them again.

Backups are created only before a file-changing run, database migration, or repair; an idle tray application does not create daily backups. SyncPlus integrity-checks the live database before snapshotting and validates the new timestamped, gzip-compressed snapshot before retaining it. The rotation keeps at most two validated backups and never removes the last known-good backup. If the live database is corrupt, it is not backed up and existing good backups are left untouched.

**Database Recovery Screen**:
A UI state shown when the live Application Database fails integrity validation or cannot be opened safely. It explains the problem and offers only validated backups for explicit user-selected restoration; it never silently replaces the live database or treats a corrupt snapshot as recoverable.

Before restoring, SyncPlus quarantines the corrupt live database under a timestamped diagnostic name. The quarantined copy is excluded from active storage and has a separate user-controlled Remove action.

## Appearance

**Dark Appearance**:
The first-class dark theme: warm ink surfaces, copper primary accent, and steel companion accent. It is not pure black and not a neon-on-black HUD.
_Avoid_: OLED black, cyberpunk, treating dark as the only real product

**Light Appearance**:
The first-class light theme: warm paper, cream, and stone surfaces. The canvas is not white and is not a brightness-inverted Dark Appearance.
_Avoid_: White sheet, bright fallback, leftover dark-mode chrome

**Brand Theme**:
The desktop GUI token set that supplies canvas, surface, elevated, field, text, muted, border, copper, steel, danger, warning, and their on/soft pairs for both appearances. Core stores only the named preference System, Light, or Dark; it does not store colours.
_Avoid_: Per-screen one-off colours, user-supplied chrome, colours in SQLite
