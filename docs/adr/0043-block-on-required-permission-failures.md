---
status: accepted
---

# Block runs when required permissions are insufficient

The Run Precheck will verify that the current local user or configured remote account can perform every required operation in the approved scope. If a required source cannot be read, a destination cannot be written, or the selected deletion method cannot remove or Trash the relevant item, SyncPlus will block the run before any file changes.

The UI will identify the affected path, account, and required access, with plain-language guidance to check ownership, group membership, and permissions before retrying. SyncPlus will never invoke `sudo`, elevate privileges automatically, alter ownership or permissions, or recommend blanket permissions such as `chmod 777`.

If permissions become insufficient during execution, the affected source remains preserved and unresolved. Safe Delete cannot become Review-Cleared until the item is successfully retried or explicitly removed from scope with acknowledgement.
