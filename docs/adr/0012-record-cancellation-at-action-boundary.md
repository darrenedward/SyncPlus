---
status: proposed
---

# Record cancellation without claiming completion

When the user cancels a Sync Run, SyncPlus will stop launching new actions and terminate the current transfer promptly. The Action Journal will retain the planned action, pre-action state, progress, and a Cancelled Action outcome; the item will not count as complete or be eligible for Verified Removal. The remaining scope remains available for safe resume after re-analysis.
