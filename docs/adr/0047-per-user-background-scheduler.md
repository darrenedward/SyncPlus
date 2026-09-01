---
status: accepted
---

# Run schedules through a per-user background component

Scheduled Runs must work while the SyncPlus window is closed. SyncPlus v1 will use a per-OS-user background scheduler appropriate to the Linux desktop environment, without installing a root or administrator service. The scheduler will launch only authorized profiles, use their normal user permissions and explicitly available credentials, and cannot bypass SyncPlus safety invariants.

The background component will persist run reports and missed-schedule events so the user can review them when SyncPlus is opened. It will not independently implement synchronization policy or maintain a second set of safety rules; it invokes the same core run workflow used by the UI.

The core implementation exposes a typed `BackgroundScheduler` poll boundary and
an explicit `ScheduledRun` launch boundary. A due occurrence advances its
persisted next-run timestamp and creates its immutable `RunSnapshot` in one
SQLite transaction, then `ScheduledRun::execute` invokes the shared
`RunWorkflow` unattended entry point. The desktop binary exposes that boundary
through the fixed `--background-scheduler` command for user-level registration;
it does not accept a command or credential payload and never installs a root
service.
