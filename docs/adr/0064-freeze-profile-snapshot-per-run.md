---
status: proposed
---

# Freeze profile settings for each run

At execution start, SyncPlus will persist a Profile Snapshot containing the endpoints, mode, every named metadata and transfer option, exclusions, deletion method, and applicable authorizations used by that Sync Run. Editing or removing the profile or its schedule cannot alter an active run; the snapshot remains linked to the Sync Run for reports, resume, and Recovery Review.

Profile and schedule writes use a durable revision check and SQLite transaction so a foreground UI and Background Scheduler cannot silently overwrite one another or expose a half-written configuration.

Changes take effect only on a later execution and require Fresh Analysis and the appropriate confirmation. This prevents mid-run edits from changing the scope, deletion policy, credentials, or safety guarantees under which the user approved the operation.
