---
status: proposed
---

# Remove each source item only after an independent proof

Safe Delete will process and settle items one at a time. For each regular file, SyncPlus will record the source identity and metadata, compute a source SHA-256 digest, transfer to a temporary destination-side file, independently compute and compare the destination digest and size, re-check that the source is unchanged and still identifies the same item, flush and atomically install the verified destination, and verify the installed result before source removal.

Only then may SyncPlus move the exact source item to the selected Trash or permanently remove it. The action journal records the proof boundary and removal outcome before the next item is settled. Empty source directories are handled only after all child items are settled and the directory is confirmed empty; the selected source root is never removed.

If source identity, content, metadata, destination availability, or verification is uncertain, SyncPlus preserves the source and marks the item unresolved. It never converts uncertainty into deletion. Final Completion Reconciliation independently checks the remaining source scope so a missed item cannot be silently treated as complete.

No software can provide a mathematical guarantee against every external event such as hardware failure or an uncooperative concurrent writer. The product guarantee is fail-closed behavior: SyncPlus does not authorize removal without the complete proof, and recommends recoverable Trash whenever available.
