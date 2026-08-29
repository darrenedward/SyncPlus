---
status: proposed
---

# Expose validated sync options instead of arbitrary commands

SyncPlus will not provide a raw shell-command field or unrestricted `rsync` argument editor, including in Advanced Mode. Users will configure named, validated options whose compatibility and safety consequences are visible in the plan and final confirmation.

This prevents shell/argument injection, accidental destructive flags, malformed invocations, and conflicts between user input and SyncPlus's source-preservation, verification, conflict, and deletion guarantees. Advanced Mode may expose more validated controls, but it must not bypass the application's safety invariants.
