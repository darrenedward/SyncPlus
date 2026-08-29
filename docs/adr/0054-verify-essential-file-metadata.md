---
status: proposed
---

# Preserve and verify essential file metadata

Content equality alone does not prove that a transferred application or script will work. SyncPlus will preserve and verify file type, executable permissions, and symlink targets by default, alongside regular-file content.

Ownership, ACLs, extended attributes, timestamps, and other specialist metadata will be explicit Advanced options. When enabled, inability to apply or verify the requested metadata makes the action unresolved and prevents Verified Removal; SyncPlus will not claim a fully successful transfer when required metadata was lost.
