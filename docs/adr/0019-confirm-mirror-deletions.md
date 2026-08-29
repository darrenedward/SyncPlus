---
status: proposed
---

# Require confirmation before propagating Mirror deletions

Mirror Sync must reconcile both peers to the same approved result, but a deletion remains a destructive action. Even when the Sync Baseline indicates that a file was intentionally removed from one peer, SyncPlus will present the resulting Mirror Deletion Decision for review and require explicit confirmation before removing the counterpart.

Absence without sufficient baseline evidence remains a conflict or one-sided item, not an automatic deletion. The action journal records the evidence, selected deletion method, confirmation, and final outcome.
