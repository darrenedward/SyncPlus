---
status: proposed
---

# Freeze profile settings for each run

At execution start, SyncPlus will persist a Profile Snapshot containing the endpoints, mode, validated options, exclusions, deletion method, and applicable authorizations used by that Sync Run. Editing the profile or its schedule cannot alter an active run.

Changes take effect only on a later execution and require Fresh Analysis and the appropriate confirmation. This prevents mid-run edits from changing the scope, deletion policy, credentials, or safety guarantees under which the user approved the operation.
