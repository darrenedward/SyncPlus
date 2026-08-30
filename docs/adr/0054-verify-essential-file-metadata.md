---
status: accepted
---

# Preserve and verify essential file metadata

Content equality alone does not prove that a transferred application or script will work. SyncPlus will preserve and verify file type, executable permissions, and symlink targets by default, alongside regular-file content. The enabled metadata requirements are part of the frozen Sync Run snapshot; timestamps can be explicitly enabled and are applied and verified before a Safe Delete boundary.

Ownership, ACLs, extended attributes, and other specialist metadata will be explicit future Advanced options. When enabled, inability to apply or verify the requested metadata makes the action unresolved and prevents Verified Removal; SyncPlus will not claim a fully successful transfer when required metadata was lost.

The local transfer workflow now stages directories as directory entries, transfers symlinks without following their targets, preserves executable permissions, and records unsupported special files as unresolved during Completion Reconciliation. The corresponding metadata and item-type proof is persisted with the Source Inventory and verified again at the destination and Verified Removal boundaries.
