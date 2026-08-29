---
status: proposed
---

# Retain run reports until the user removes them

SyncPlus will retain completed run reports in local application storage until the user deliberately removes them through an explicit Remove action. Unresolved and review-pending reports will not be automatically purged, because they are part of the user's recovery and review workflow.

Reports will store operational metadata, file paths needed for review, hashes where required for evidence, decisions, and outcomes. They will not store file contents or saved authentication secrets. Removing a report must be clearly labeled and confirmed when it also removes associated baseline or review metadata.
