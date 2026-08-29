---
status: proposed
---

# Preserve both versions when a rename defers the decision

When a conflict is resolved by renaming or preserving both versions, SyncPlus will keep both copies, show the original and new paths in the Run Report, and mark the item Review Later. The rename does not authorize removal; deleting one copy requires a later explicit resolution and Execution Confirmation. This provides a recoverable path when the user is not yet sure which version to keep.

Generated preserved-copy names will be deterministic and human-readable, will be shown in the plan before execution, and will use collision-safe suffixes when necessary.
