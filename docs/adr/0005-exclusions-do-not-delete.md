---
status: proposed
---

# Keep exclusions separate from deletion

An Exclusion Rule removes matching items from the Approved Sync Scope; it must not cause those items to be deleted. After a run, SyncPlus may offer Excluded Item Cleanup as a separate reviewed action with an item list, a selected peer, and a fresh Execution Confirmation. This lets users clean temporary or unwanted files without turning a pattern typo into silent data loss.

For one-way sync, the default cleanup target is the source; cleaning destination items remains a separate explicit operation.

The initial pattern experience will use intuitive matching for files and directory subtrees, with a preview of matching items before execution.
