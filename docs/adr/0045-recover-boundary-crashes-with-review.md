---
status: proposed
---

# Review crashes at the destination/source-removal boundary

If SyncPlus stops between installing a verified destination replacement, removing or Trashing the source, and persisting the final action outcome, the item enters Recovery Review. Resume will inspect the current source, destination, Trash state where relevant, source identity, size, and SHA-256 evidence before deciding whether the item is settled.

If the source still exists, SyncPlus may reverify the destination and continue the reviewed removal protocol. If the source is absent and the destination matches, the report records the recovered outcome and any uncertainty; if evidence is insufficient, the item remains unresolved for user review. No uncertain deletion is repeated automatically.
