---
status: proposed
---

# Require explicit SSH server identity approval

SyncPlus will require the user to approve a new SSH server fingerprint before its first transfer and will reject a changed fingerprint rather than silently trusting it. This protects saved connections and Unattended runs from connecting to an unexpected server.

An Unattended Run must stop the affected remote operation and notify the user when server identity approval is required; it must not attempt to trust the server automatically.
