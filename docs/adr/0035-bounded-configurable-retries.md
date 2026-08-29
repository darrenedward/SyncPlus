---
status: proposed
---

# Use bounded configurable retries for transient failures

SyncPlus will expose a validated Retry Policy in Advanced Mode, defaulting to three attempts. Retry delays will increase between attempts so an intermittent network or external-drive problem has time to stabilize rather than causing rapid repeated starts and stops.

Only errors classified as transient may be retried. Permanent errors, safety-policy failures, identity changes, capability failures, and unresolved file changes must stop without pointless retries. After the retry limit, the action is deferred or failed, the user is told the reason and next step, and the source remains preserved. Destructive finalization requires fresh verification and is never blindly repeated.
