---
status: proposed
---

# Prefer atomic moves into same-filesystem recovery

When a local or verified remote recovery location is on the same filesystem as the source item, SyncPlus will move the item atomically into recovery after the destination proof boundary. It will not waste space or time copying and then deleting an item that can be moved directly.

When recovery crosses filesystem or volume boundaries, SyncPlus may use copy-then-independent-verify-then-remove. The Run Precheck must account for the required additional space, and any failed copy, verification, or removal preserves the original source item. Recovery remains unavailable when the cross-filesystem operation cannot be proven safe.
