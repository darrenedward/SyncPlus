---
status: accepted
---

# Verify external volume identity before resume

For local external-drive peers, SyncPlus will record a stable volume identity where the operating system provides one and verify it before a task is resumed. A matching path or drive letter alone is not sufficient because a different device may be mounted there after disconnect.

If the recorded volume is missing or a different volume is present, resume is blocked and the user is shown the detected identity and expected identity. Explicit user confirmation is required before treating a replacement device as the intended peer; otherwise the source remains preserved and no changes are made.
