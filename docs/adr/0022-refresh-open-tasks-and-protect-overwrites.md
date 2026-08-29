---
status: proposed
---

# Refresh active tasks on opening and protect destination overwrites

SyncPlus will not silently recalculate completed historical reports. When a user opens a pending, interrupted, or review-needed Sync Run, the app will refresh its comparison so the displayed plan reflects current state. A further Fresh Analysis is required immediately before confirmation or execution.

Destination overwrites will use a Verified Replacement: transfer incoming content to a destination-side temporary file, verify it, and only then replace the existing destination item. A failed, cancelled, or interrupted replacement must leave the existing destination intact and must not count as a completed action.
