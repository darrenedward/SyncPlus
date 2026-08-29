---
status: proposed
---

# Back up recovery metadata before destructive runs

Before a run that can remove or overwrite data, SyncPlus will create a validated, rotating backup of its SQLite Application Database. The backup protects profiles, schedules, host fingerprints, Run Reports, Action Journals, Sync Baselines, hashes, and recovery state if the live database is damaged. It will not create backups merely because the app is open or idle in the tray; backups are taken before file-changing runs, database migrations, or repair operations.

The backup will be created from a consistent SQLite snapshot rather than by compressing the live file while it is being written. SyncPlus will integrity-check the live database first, gzip the validated snapshot with a timestamp, validate the compressed backup as readable and structurally sound, and retain at most two validated backups per database. It will remove the older backup only after the newer one has been validated, and it will never remove the last known-good backup. If the live database fails integrity validation, no new backup is created and existing good backups remain untouched.

The backup is not a backup of user files and cannot restore permanently removed source data. If the database backup cannot be created or validated, SyncPlus will allow read-only analysis but block all file-changing execution, report the condition before confirmation, and explain the remediation. It must not offer a Continue Anyway path for a destructive or overwrite action.
