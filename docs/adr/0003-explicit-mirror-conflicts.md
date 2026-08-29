---
status: proposed
---

# Require explicit resolution for mirror conflicts

Mirror Sync will not choose a winner when both peers contain different versions of the same path. SyncPlus will show the conflict and require a per-path resolution; skipped conflicts remain unresolved and prevent the run from being reported as successfully mirrored. This preserves the Mirror Invariant without silently discarding either peer's changes.

On the first Mirror Sync, when no Sync Baseline exists, one-sided items are proposed for copying rather than interpreted as deletions. Deletion requires an explicit user Resolution.

The Sync Baseline records only paths successfully reconciled and verified. Unresolved, failed, or unstable paths remain outside the settled baseline.

Resolutions that affect both peers must be verified on both sides. A partial application is reported as incomplete and remains reviewable rather than being presented as a successful mirror.

For a Partial Mirror Run, SyncPlus keeps successful work and offers a repair or retry plan instead of attempting an automatic rollback. The affected path remains outside the settled Sync Baseline.
