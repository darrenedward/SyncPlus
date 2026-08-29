---
status: proposed
---

# Prevent concurrent runs on overlapping peer scopes

SyncPlus will enforce Peer Scope Locks across all manual, unattended, and scheduled runs. It will normalize local paths and remote endpoint paths, detect parent/child and equivalent overlaps, and block a new run when its source or destination scope could intersect an active run from another profile.

The user will be told which active run owns the overlapping scope and may review or wait for it; the blocked run will not modify files. This protects content verification, action journals, recovery boundaries, and source/destination deletion decisions from concurrent changes.
