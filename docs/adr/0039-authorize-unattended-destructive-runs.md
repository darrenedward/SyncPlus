---
status: proposed
---

# Allow explicitly authorized unattended destructive schedules

Users may choose to trust SyncPlus to perform destructive actions while away, but that trust must be explicit and narrowly scoped. Advanced Mode will provide a per-profile **Allow unattended destructive actions** authorization after showing the consequences, affected options, and recovery limitations.

Without this authorization, an automatic Scheduled Run may perform only non-destructive synchronization and will defer destructive actions for review. With it, the schedule may use Safe Delete, Destination Cleanup, or Permanent Removal according to the saved profile, subject to every technical safeguard: Run Precheck, Fresh Analysis, SHA-256 verification, Completion Reconciliation, SSH identity and capability checks, and source preservation whenever anything is uncertain.

Unattended Permanent Removal requires a separate **Allow unattended permanent removal** authorization. Authorizing Safe Delete, Trash, or other recoverable deletion does not authorize irreversible removal. Each authorization is revocable, recorded with each run, and must not be global. It is invalidated when the user changes the profile's destructive options or endpoints in a safety-relevant way. A schedule that lacks valid authorization must notify the user instead of silently deleting data.

When cloning a profile, any destructive authorization is copied only after a dedicated warning and explicit user choice. It is never inherited silently.
