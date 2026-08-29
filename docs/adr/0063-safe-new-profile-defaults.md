---
status: proposed
---

# Default new profiles to non-destructive synchronization

When creating a new Sync Profile, SyncPlus will default to non-destructive One-Way Sync. Safe Delete, Destination Cleanup, Mirror Sync, schedules, and unattended destructive authorization will be disabled until deliberately selected by the user.

The first Analyze and confirmation will clearly show the selected mode and consequences. This makes a new profile safe to test without assuming that the user intended source removal, destination cleanup, bidirectional reconciliation, or unattended execution.
