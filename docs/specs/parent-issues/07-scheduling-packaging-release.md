## Problem Statement

Users want to run a sync while away, but unattended execution can create hidden deletion, credential, overlap, retry, and notification risks. The public Linux application also needs a reproducible package and release evidence before users can trust it.

## Solution

Implement Advanced Mode scheduling through a per-OS-user Background Scheduler, explicit per-profile unattended authorization, bounded retry/resume, missed-run notices, overlap prevention, tray/quit integration, a versioned `.deb`, and the complete disposable release-safety matrix.

## User Stories

1. As an experienced user, I want scheduling available in Advanced Mode and off by default, so that ordinary users are not exposed to hidden automation.
2. As an experienced user, I want a schedule to run while the window is closed, so that unattended operation is useful.
3. As a user, I want the Background Scheduler to use my normal OS-user permissions, so that it cannot affect unrelated system data through root privileges.
4. As a user, I want explicit per-profile authorization for unattended destructive actions, so that trust is my deliberate choice rather than an accidental global setting.
5. As a user, I want Permanent Removal to require a separate unattended authorization, so that recoverable deletion permission cannot become irreversible deletion permission.
6. As a user, I want scheduled Safe Delete to use an explicitly authorized deletion method, so that an unavailable Trash method never silently falls back.
7. As a user, I want a schedule blocked by missing credentials, host identity, permissions, or capabilities, so that an unattended run never guesses or hangs.
8. As a user, I want overlapping schedules skipped and recorded, so that two runs cannot modify the same peer scopes concurrently.
9. As a user, I want transient failures retried a bounded number of times with increasing delays, so that an intermittent network does not create a restart loop.
10. As a user, I want missed schedules to explain why they did not run and offer Yes, Run Now or No, Not Now, so that I can decide what happens next.
11. As a user, I want Run Now to become Interactive with fresh analysis and confirmation, so that a catch-up request is understandable while I am present.
12. As a user, I want automatic schedules to create reports and notifications, so that unattended work is reviewable when I return.
13. As a user, I want a `.deb` package with desktop integration, so that installation is predictable on supported Linux systems.
14. As a maintainer, I want release gates covering local, external-filesystem, SSH, crash, permission, hash, SQLite, and scheduling failures, so that the trust claims are demonstrated before release.

## Implementation Decisions

- Provide recurring Scheduled Runs only in Advanced Mode and keep them disabled by default.
- Use a per-OS-user Background Scheduler appropriate to the Linux desktop environment. Do not install or enable a root daemon.
- Automatically triggered schedules are Unattended. A user selecting Run Now receives an Interactive Run with Fresh Analysis and normal confirmation.
- Allow unattended destructive actions only through explicit per-profile authorization. Require separate authorization for unattended Permanent Removal. Invalidate authorization after safety-relevant profile or endpoint changes.
- Require noninteractive SSH credentials for schedules. Missing credentials, changed host identity, missing remote tools, unavailable recovery, or failed precheck produce a Blocked report and notification.
- Allow only one active run across overlapping normalized peer scopes. Coalesce missed triggers rather than queueing duplicates.
- Use the bounded Retry Policy, default three attempts with increasing delays, and resume the affected action without replaying completed work.
- Add clear desktop notifications with reason and next action; persist all events in Run Reports.
- Build a versioned `.deb` containing the binary, desktop entry, icons, Help assets, and user-level scheduler integration. Runtime must not require root.
- Use reproducible packaging metadata and test install, upgrade, uninstall, desktop registration, scheduler registration, and canonical XDG storage.

## Testing Decisions

- Test scheduling through the core scheduler/run seam with fake clocks and real process boundaries, then verify desktop integration separately.
- Test authorization matrix: ordinary schedule, recoverable deletion, Permanent Removal, profile clone, profile edits, unavailable method, and revocation.
- Test no concurrent overlapping runs, missed triggers, unavailable drives, asleep/offline recovery, Run Now conversion, bounded retries, notification content, and reports.
- Test background execution with the UI closed and assert no root privileges or hidden prompts are required.
- Build and install the `.deb` in a disposable environment; test launch, desktop entry, user scheduler, upgrade, removal, and retained user data.
- Run the full release matrix: critical missed file, source mutation, hash mismatch, permission failure, external-drive disconnect, real restricted filesystem, SQLite corruption/restore, SSH identity/capability failure, and orphan-process cleanup.

## Out of Scope

- SSH-to-SSH scheduling, system-wide/root scheduling, cloud notifications, email/SMS notifications, and cross-platform installers beyond the supported Debian package.

## Further Notes

Scheduling is valuable only if the same fail-closed core is used while the UI is closed. Packaging and release tests are part of the safety story, not post-release housekeeping.
