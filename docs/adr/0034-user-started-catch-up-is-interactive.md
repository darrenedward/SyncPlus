---
status: proposed
---

# Make user-started schedule recovery interactive

Automatically triggered Scheduled Runs use Unattended behavior. If the user selects **Yes, Run Now** from a Missed Schedule Notice, SyncPlus will treat the catch-up as an Interactive Run because the user is present and has explicitly requested execution.

The catch-up still performs Run Precheck and Fresh Analysis, shows the current plan, and requires the normal Execution Confirmation. It does not silently reuse the missed schedule's old plan or bypass conflict and deletion safeguards.
