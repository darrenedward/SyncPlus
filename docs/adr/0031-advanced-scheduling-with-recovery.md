---
status: proposed
---

# Include optional scheduling and recovery in v1

SyncPlus v1 will include optional recurring Scheduled Runs in Advanced Mode. Scheduling is disabled by default, must be explicitly configured, and will launch Unattended Runs. Simple Mode will not expose scheduling controls.

Scheduled Runs use the same safety lifecycle as manually started runs: Run Precheck, Fresh Analysis, validated options, source-preserving uncertainty handling, cryptographic verification, durable reports, and review-required completion. A schedule must not bypass unresolved review items, changed or unavailable files, SSH identity/capability failures, or technical safety checks.

Destructive options remain disabled for automatic schedules unless the user explicitly grants that profile an Unattended Destructive Authorization in Advanced Mode after a clear consequence warning. This authorization is per profile, revocable, and recorded with each run. It permits the scheduled run to proceed without a live confirmation popup, but it never allows SyncPlus to bypass precheck, verification, completion reconciliation, or source preservation on uncertainty.

Recovery is a first-release capability. Interrupted, cancelled, failed, and review-pending runs remain visible and can be safely resumed or resolved after a Fresh Analysis and new confirmation where required.
