---
status: accepted
---

# Prevent concurrent runs for one profile

SyncPlus will allow only one active run for a profile's source and destination pair at a time. If a Scheduled Run fires while that profile is already running, the scheduled execution will be skipped rather than started concurrently.

The app will notify the user that the scheduled run did not start because the profile is already running, with actions to open the active run or dismiss the notification. Dismissal acknowledges the notification only; the Skipped Schedule event remains in history and is not treated as a successful sync.

The core records an overlapping unattended occurrence as a blocked Scheduled
Run with the active profile and scope in its reason. It shares the normalized
Peer Scope Lock registry with scheduler-launched workflows, so the occurrence
does not reach filesystem mutation.
