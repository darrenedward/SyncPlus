---
status: accepted
---

# Warn on sensitive paths only for source-draining actions

SyncPlus will show an advisory Path Risk Warning for one-way Safe Delete when the selected source is a broad or system-sensitive path. Common user-data subdirectories and user-owned data folders on mounted volumes normally receive no special warning. The warning set includes platform-aware system roots and sensitive locations such as `/`, `/home`, `/root`, `/etc`, `/usr`, `/var`, `/boot`, `/bin`, `/sbin`, `/lib`, `/dev`, `/proc`, and `/sys` on Linux.

The warning is not an allow/deny rule. It explains the consequence and leaves the decision to the user, with stronger confirmation for high-risk paths. A separately mounted old server volume can be backed up or drained when intentionally selected, but the user sees the warning if its selected scope appears sensitive.

Mirror Sync does not show the special source-draining Path Risk Warning because it keeps both peers populated and reconciles them. Ordinary deletion actions in Mirror still remain visible, reviewable, and confirmation-gated.
