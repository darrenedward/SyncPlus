---
status: proposed
---

# Protect unresolved run reports from ordinary removal

Completed Run Reports may be removed through a clearly labeled **Remove** action. Unresolved, interrupted, cancelled, or review-pending reports will not use the ordinary removal path; they require a separate **Discard Unresolved Run** action with an explicit warning that recovery state, Action Journal data, and pending review information will be lost.

Discarding a report removes SyncPlus metadata only. It never deletes, restores, or changes source, destination, Trash, or synced files.
