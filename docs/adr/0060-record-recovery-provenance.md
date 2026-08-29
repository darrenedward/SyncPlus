---
status: proposed
---

# Record provenance for recoverable deletions

For every item moved to local or remote recovery, SyncPlus will record the original peer, relative path, run identifier, removal time, item type, and SHA-256 digest where applicable. The recovery record allows users to identify what was removed and supports a safe Restore action.

Restore will recheck the current destination path and compare existing content before writing. It will never overwrite newer or different content automatically; a collision becomes a reviewed action requiring an explicit decision and confirmation.
