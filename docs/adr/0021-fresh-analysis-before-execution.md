---
status: proposed
---

# Re-analyze current state before every execution

Every Sync Run, including runs started from a saved profile or resumed from an earlier report, will perform a Fresh Analysis of the current peers before Execution Confirmation. The resulting plan is based on current paths, metadata, content evidence, exclusions, permissions, and remote state.

SyncPlus will never blindly replay an old plan. If material state changes between analysis, confirmation, and execution, the affected plan or action is invalidated and follows the changed/unverifiable-item review policy. A new confirmation is required for data-changing actions.
