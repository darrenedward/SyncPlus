---
status: proposed
---

# Use SQLite as the primary nonsecret application store

SyncPlus will use a local SQLite database as the primary store for settings, Sync Profiles, schedules, SSH host fingerprints, Run Reports, Action Journals, Sync Baselines, hashes, and recovery state. The database will use schema migrations, transactions, foreign-key enforcement, and crash-safe persistence appropriate to safety-critical journal updates. Concurrent profile writes use durable revisions, and complete profile reads use a single SQLite read transaction so UI and scheduler state cannot be silently lost or partially observed.

JSON will be supported for explicit export/import and backup workflows, not as the live source of truth. YAML will not be used for application state. Passwords, private-key material, and other saved credentials remain in the desktop OS keyring.

SQLite transactions cannot make database updates and filesystem operations a single atomic transaction. The per-item action protocol, durable journal boundaries, filesystem verification, and Recovery Review remain required for ambiguous crashes or partial operations.
