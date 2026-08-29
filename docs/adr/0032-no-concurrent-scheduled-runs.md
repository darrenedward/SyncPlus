---
status: proposed
---

# Prevent concurrent runs for one profile

SyncPlus will allow only one active run for a profile's source and destination pair at a time. If a Scheduled Run fires while that profile is already running, the scheduled execution will be skipped rather than started concurrently.

The app will notify the user that the scheduled run did not start because the profile is already running, with actions to open the active run or dismiss the notification. Dismissal acknowledges the notification only; the Skipped Schedule event remains in history and is not treated as a successful sync.
