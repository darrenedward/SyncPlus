---
status: proposed
---

# Quarantine the corrupt database before restoration

When the live Application Database fails integrity validation and the user chooses a validated backup on the Database Recovery Screen, SyncPlus will first move or copy the corrupt database to a timestamped quarantine location. It will not overwrite or silently discard the corrupt file.

The quarantined database is excluded from active application storage and cannot be selected as a trusted backup without validation. It remains available for diagnosis or later recovery until the user explicitly removes it through a separate action.
