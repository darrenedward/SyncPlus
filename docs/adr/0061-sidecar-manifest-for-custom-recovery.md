---
status: proposed
---

# Add provenance sidecars to custom and remote recovery

SQLite backups remain the primary recovery record, but a pre-run backup may not contain the latest outcome if the database fails during execution. For custom or remote Recovery Folders, SyncPlus will therefore write a small sidecar manifest beside each recovered item or recovery batch, containing provenance and verification metadata but no secrets or file contents.

For local operating-system Trash, SyncPlus will use the operating system's native provenance metadata alongside SQLite rather than duplicating equivalent sidecars. Restore must be able to detect missing or invalid provenance and require review instead of guessing an original path.
