---
status: proposed
---

# Make the selected source authoritative in one-way sync

One-way Sync will treat the selected source as authoritative when the same path differs: the destination version is planned for overwrite by the source version. SyncPlus must still show the overwrite in the dry-run plan and require the appropriate confirmation before applying it. This gives direction a clear meaning while preserving user visibility and control.

Conflict Review may create a Per-Path Override, allowing the user to retain the destination version for an individual path. This does not change source authority for the rest of the run; with Safe Delete enabled, the source item may be removed only after the retained destination result is verified.

Mirror Sync is separate: it has no inherent source authority and must finish with both peers containing the same approved result. Missing items therefore require an explicit restore-or-remove decision before the run can succeed.
