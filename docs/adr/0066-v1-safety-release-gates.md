---
status: proposed
---

# Require end-to-end safety evidence before v1 release

SyncPlus v1 will not be considered release-ready based only on unit tests or UI tests. Disposable end-to-end release gates must exercise local Safe Delete and SHA-256 verification, missed or unreadable source items, destination disconnect, permission failure, interrupted resume, SQLite backup and recovery, SSH transfer and remote verification, and case-insensitive or restricted filename collisions.

The gates must assert intended safety outcomes: no unauthorized source removal, no silent omission or overwrite, correct unresolved reporting, blocked completion when required, safe recovery, and accurate user-facing explanations.

The repository implements the gate as `packaging/release-gate.sh`. Each run
retains a versioned evidence directory with tool versions, package digest,
sanitized case logs, and `manifest.json`. The command fails closed when a
required tool or scenario is unavailable and writes `RELEASE_READY` only after
every required case has passed.
