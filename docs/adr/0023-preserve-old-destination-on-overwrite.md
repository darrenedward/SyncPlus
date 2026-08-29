---
status: proposed
---

# Preserve the old destination version during overwrite

When a source-authoritative action replaces different destination content, SyncPlus will first transfer the incoming content to a temporary destination-side file and verify it. Only after successful verification will the old destination item be handled using the selected deletion method and the verified replacement installed.

If the old destination version is sent to Trash, the user retains a recovery path where supported. Permanent removal is allowed only when explicitly selected and confirmed. If the selected Trash method is unavailable, the overwrite stops rather than silently becoming permanent. Byte-identical items require no replacement or deletion.
