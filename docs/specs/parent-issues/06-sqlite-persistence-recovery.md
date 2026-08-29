## Problem Statement

Profiles, baselines, action outcomes, recovery state, and review decisions must survive crashes and remain available for later investigation. Scattered JSON files or an unprotected database could lose the evidence needed to determine whether a source item was removed.

## Solution

Use one local SQLite Application Database for all nonsecret SyncPlus state, with migrations, transactions, integrity checks, atomic snapshot backups, quarantine/restore, report retention, recovery provenance, and explicit separation of credentials into the desktop keyring.

## User Stories

1. As a desktop user, I want profiles, schedules, reports, baselines, journals, and recovery state stored consistently, so that the app has one source of truth.
2. As a desktop user, I want the database stored at the canonical per-user XDG location, so that SQLite files never appear randomly beside sync folders.
3. As a desktop user, I want saved credentials kept in the desktop keyring, so that passwords and private-key material are not in SQLite or logs.
4. As a desktop user, I want action state committed around each file boundary, so that recovery can determine what may or may not have happened.
5. As a desktop user, I want a validated compressed backup before file-changing runs, so that application metadata can be recovered after corruption.
6. As a desktop user, I want no idle daily backups, so that opening the tray app cannot eventually rotate away good backups.
7. As a desktop user, I want at most two validated timestamped backups, so that recovery is available without uncontrolled storage growth.
8. As a desktop user, I want corrupt databases quarantined before restoration, so that the current evidence is not silently overwritten.
9. As a desktop user, I want a Recovery Screen to choose a validated older database, so that restoration is explicit and understandable.
10. As a desktop user, I want local Trash and custom recovery items to retain provenance, so that Restore can identify the original path and avoid collisions.
11. As a desktop user, I want completed reports retained until I remove them, so that historical decisions remain inspectable.
12. As a desktop user, I want unresolved reports protected behind Discard Unresolved Run, so that recovery data cannot disappear through an ordinary Remove action.
13. As a desktop user, I want JSON export/import available without using JSON as live state, so that I can move or back up nonsecret configuration intentionally.

## Implementation Decisions

- Use a single SQLite Application Database per OS user for nonsecret state: settings, profiles, schedules, host fingerprints, reports, Action Journals, Sync Baselines, hashes, recovery state, and Profile Snapshots.
- Use schema migrations, foreign-key enforcement, integrity checks, transactions, crash-safe journal boundaries, and a synchronous Rust SQLite driver.
- Use the canonical data layout: live database under the per-user XDG data directory, validated backups/quarantine/recovery beneath the application data directory, and temporary data under the per-user cache directory. Never create databases beside selected peers.
- Store no passwords, passphrases, private-key contents, or file contents in SQLite. Use the desktop OS keyring for Saved Secrets and user-only filesystem permissions for local state.
- Before file-changing runs, migrations, or repair, integrity-check the live database, create a consistent snapshot, gzip it with a timestamp, validate it, and retain at most two validated backups.
- Do not create idle backups. Never let a corrupt live database displace a good backup and never remove the last known-good backup.
- On corruption, open Database Recovery Screen, quarantine the live database with a timestamp, and require explicit backup selection.
- Keep recovery provenance in SQLite; add sidecar manifests for custom/remote recovery where native Trash metadata is unavailable.
- Removing reports or profiles changes SyncPlus metadata only and never changes user files.

## Testing Decisions

- Test through the storage/recovery seam with temporary database locations and real SQLite behavior, not a fake map.
- Test migration, foreign keys, transactions, integrity failures, backup snapshot consistency, gzip validation, two-backup rotation, last-known-good protection, corruption quarantine, and explicit restore.
- Simulate crashes between journal states and filesystem boundaries; assert Recovery Review rather than guessed completion.
- Test concurrent UI/scheduler access, locking, atomic report updates, Profile Snapshot immutability, and report retention/discard.
- Test keyring boundaries and assert secrets never occur in database rows, backups, logs, previews, manifests, or notifications.
- Test recovery provenance, sidecar loss/corruption, Restore collisions, and user-only permissions.

## Out of Scope

- Cloud backup of user files, multi-user account synchronization, database encryption as a replacement for OS permissions/keyring, and automatic remote database replication.

## Further Notes

SQLite improves durable metadata but cannot make database commits and filesystem changes one transaction. Action Journal boundaries and Recovery Review remain mandatory.
