---
status: proposed
---

# Require a verified recovery location for remote Trash

SSH systems do not provide a universal Trash, so SyncPlus will offer remote Trash only when it can verify a configured recovery location and the remote account has the required access. A remote source item is moved to that recovery location only after destination verification and the same per-item proof boundary.

If remote Trash is unavailable or cannot be verified, SyncPlus will stop the deletion or require the separately authorized Permanent Removal option. It will never silently invoke `rm` or treat an arbitrary remote directory as recoverable Trash.
