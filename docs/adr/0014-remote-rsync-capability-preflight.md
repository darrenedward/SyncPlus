---
status: proposed
---

# Verify remote rsync capability before SSH changes

SSH authentication and server-identity approval do not prove that the remote peer can safely perform the requested Sync Run. Before any SSH-backed operation that can change files, SyncPlus will run a non-mutating capability preflight and verify that the remote `rsync` is present, compatible with the local integration, and able to support the requested operation.

If the remote capability is missing or incompatible, SyncPlus will make no file changes for that operation, preserve the source, and show a clear remediation message. It will not silently install software or fall back to an unverified command or deletion method. Unattended Runs will report the operation as blocked/pending review rather than bypassing the preflight.
