---
status: proposed
---

# Rotate only validated database backups

SyncPlus will create database backups only before file-changing runs, database migrations, or repair operations. An application that is merely open or idle in the system tray will not generate daily backups.

Before creating a backup, SyncPlus will integrity-check the live SQLite database. It will create a consistent snapshot, gzip it with a timestamp, validate the compressed snapshot, and only then rotate the backup set. At most two validated backups are retained, and the last known-good backup is never deleted. A corrupt live database is not backed up and cannot displace existing good backups.

When integrity validation fails, SyncPlus opens a Database Recovery Screen. The user chooses explicitly from validated backups; the app never silently restores an older database or presents an unvalidated snapshot as safe. A failed backup or recovery check blocks file-changing execution and leaves user files untouched.
