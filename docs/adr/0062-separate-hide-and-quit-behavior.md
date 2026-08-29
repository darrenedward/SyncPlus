---
status: proposed
---

# Separate window hiding from quitting

Closing the SyncPlus window will hide it to the system tray and leave an active run or Background Scheduler available. A distinct **Quit** action will explain the effect and, for an active manual run, ask whether to stop the run and recover it. **No** leaves the run active; **Yes** stops it safely, records the interrupted state, preserves the source, and applies the partial-transfer cleanup policy. Scheduled work owned by the background component can continue when the UI is hidden or quit; disabling schedules is separate.

Unexpected crashes or forced termination are treated as Interrupted Runs: child processes are stopped where possible, partial data follows the configured cleanup policy, the source remains preserved, and recovery state remains available for Fresh Analysis.
