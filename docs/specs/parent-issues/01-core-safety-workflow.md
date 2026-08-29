## Problem Statement

Users cannot safely trust a raw rsync command or exit code to explain whether a synchronization completed, whether a file was missed, or whether source data can be removed. The safety rules must live in a testable core workflow rather than being scattered through the UI.

## Solution

Build the GUI-free core synchronization workflow that performs Run Precheck, Fresh Analysis, Source Inventory, explainable planning, validated process execution, per-item verification, Action Journal persistence, Completion Reconciliation, cancellation, retry/resume, and final run-state calculation. The core owns all safety invariants and exposes typed results to the UI and Background Scheduler.

## User Stories

1. As a desktop user, I want a Fresh Analysis before every execution, so that I never run an obsolete plan.
2. As a desktop user, I want a Run Precheck before any file changes, so that missing permissions, space, paths, naming compatibility, and capabilities are found first.
3. As a desktop user, I want the plan to state what each action will do in plain language, so that I can understand the consequences before confirming.
4. As a desktop user, I want hidden files included by default, so that important configuration files are not silently missed.
5. As a desktop user, I want exclusions to be part of a recorded Approved Sync Scope, so that excluded data is never accidentally treated as transferred or deleted.
6. As a desktop user, I want each source item recorded in a Source Inventory, so that SyncPlus can detect items it failed to consider.
7. As a desktop user, I want independent SHA-256 and size verification, so that an rsync success code is not mistaken for proof of correct data.
8. As a Safe Delete user, I want source removal to occur one item at a time only after the Safe Delete Proof Boundary, so that an unverified item remains recoverable.
9. As a desktop user, I want a final Completion Reconciliation, so that a missed critical file prevents Source Drained and Review-Cleared status.
10. As a desktop user, I want cancellation to stop new actions, terminate the current transfer, record a Cancelled Action, and preserve the source, so that stopping is safe and explainable.
11. As a desktop user, I want retries to resume from the last verified boundary without replaying completed actions, so that a transient failure does not restart or repeat destructive work.
12. As a desktop user, I want an interrupted run to remain visible and resumable, so that a crash, disconnect, or forced termination does not lose the action history.
13. As a desktop user, I want overlapping profiles blocked by Peer Scope Locks, so that concurrent runs cannot invalidate each other’s hashes or deletion decisions.
14. As a security-conscious user, I want no arbitrary shell or rsync arguments, so that paths and options cannot become unintended commands.
15. As a desktop user, I want the final run state to distinguish Completed, Completed with Review Required, Failed, Cancelled, Blocked, Recovery Review, and Review-Cleared, so that I know whether more work is required.

## Implementation Decisions

- Keep synchronization policy, safety invariants, inventory, planning, hashing, process execution, journaling, recovery boundaries, and status calculation in the GUI-free core.
- Expose typed Process Specifications and validated Sync Options; do not expose unrestricted command arguments.
- Use structured process argument vectors and controlled environment variables. User-controlled paths, hosts, usernames, and options are data, never shell syntax.
- Model the workflow as `Idle/Edit → Prechecking → Analyzing → PlanReview → ExecutionConfirmation → Executing → CompletionReconciliation → Review/Resolution → Review-Cleared` with fail-closed Blocked, Failed, Cancelled, and Recovery Review outcomes.
- Treat metadata equality as triage only. Stream SHA-256 for content proof and preserve the source on mismatch or uncertainty.
- Persist a Profile Snapshot, Source Inventory, Action Journal, and evidence for each run. Database transactions do not replace filesystem Recovery Review.
- Use temporary destination files and Verified Replacement for overwrites. Preserve existing destination content until the replacement is verified.
- Use process groups for rsync/SSH execution, graceful cancellation followed by escalation, and orphan-process checks.
- Keep retry count configurable in Advanced Mode with a default of three, increasing delays, transient-error classification, and no blind retry of destructive finalization.
- Enforce Peer Scope Locks across profiles using normalized local and remote scopes.

## Testing Decisions

- Tests assert external behavior and safety contracts, not private implementation details.
- The highest seam is the core Sync Workflow with injected peer, process, clock, hash, journal, and recovery capabilities. UI and scheduling tests consume its results rather than reimplement policy.
- Test Fresh Analysis invalidation, precheck blockers, hidden/excluded inventory rules, source authority, action counts, SHA-256 mismatches, source changes, missed files, cancellation, retries, crashes, scope locks, and every terminal status.
- Add parser/property/fuzz coverage for malformed itemized output, carriage-return progress, escaped names, Unicode, spaces, unknown flags, partial exits, and vanished sources.
- Make the simulated missed/unverifiable critical file a release-blocking contract test: the source remains, the report identifies it, Complete is unavailable, and resume is safe.
- Test process-group cleanup and verify no orphaned rsync/SSH processes remain after cancel, crash simulation, or forced termination.

## Out of Scope

- GUI implementation, SSH-specific capability discovery, scheduling, packaging, and full Mirror Conflict Review UI.
- Arbitrary command execution, automatic privilege elevation, and a mathematical guarantee against hardware failure or a malicious peer.

## Further Notes

This parent is the foundation for every other SyncPlus parent issue. No UI or scheduler code should duplicate the core safety rules. A parent is complete only when its child work and the cross-cutting release gates pass.
