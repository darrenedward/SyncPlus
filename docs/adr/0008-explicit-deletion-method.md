---
status: proposed
---

# Ask for the deletion method on every Safe Delete run

When Safe Delete is enabled for a manually started run, SyncPlus will ask for the Deletion Method every time: supported local Trash or Permanent Removal. The Execution Confirmation will show recoverability and expected space impact. An automatic Scheduled Run may use a method explicitly selected and authorized in its profile, but unavailable Trash must not silently fall back to permanent deletion. Profiles may remember a suggestion, but they must not silently select permanent removal for a manual run.
