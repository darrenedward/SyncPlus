---
status: proposed
---

# Preserve interrupted runs for safe resume

SyncPlus will retain the report and remaining scope of an Interrupted Run so the user can review and resume it after cancellation, app closure, crash, or transport failure. Resume will re-analyze current peer state and require fresh confirmation for data-changing actions; it will never blindly replay the previous plan.
