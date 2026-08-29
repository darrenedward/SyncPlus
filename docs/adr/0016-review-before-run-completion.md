---
status: proposed
---

# Keep runs open until required review is cleared

SyncPlus will distinguish the Execution Result from the lifecycle state of the run. File operations may finish while the run still contains conflicts, deferred or changed items, failed actions, cancelled actions, or preserved copies requiring review. The UI will show that execution has finished but will not present the run as fully complete.

The run remains visible and revisitable until every required review item has an explicit resolution and the resulting action has completed successfully. Only then does the user-facing **Complete** action become available. Clicking **Complete** records the user's acknowledgement and closes the run as Review-Cleared. If unresolved work remains, the run stays open rather than being silently archived.
