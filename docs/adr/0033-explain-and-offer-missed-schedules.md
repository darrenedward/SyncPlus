---
status: accepted
---

# Explain missed schedules and offer one catch-up run

When a Scheduled Run does not start because the computer, peer, drive, or precheck was unavailable, SyncPlus will notify the user with the specific reason and ask: “Would you like to run it now?” The actions are **Yes, Run Now** and **No, Not Now**.

Run Now starts one catch-up execution only after a Fresh Analysis and Run Precheck; it does not replay a stale plan or queue duplicate runs. Not Now records the user's choice and keeps the missed schedule event visible for later review. The notification must not imply that a sync succeeded when it never ran.

Implementation: missed schedule notices are durable SQLite records. A pending
notice is unique per Sync Profile and later missed occurrences increment its
count and update its latest reason. Settled Run Now and Not Now decisions stay
visible for review.
