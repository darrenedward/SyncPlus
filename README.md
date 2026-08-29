# SyncPlus

SyncPlus is a safety-first Linux desktop application for reviewing and applying local and SSH file synchronization. It uses rsync for transfer while adding explicit planning, conflict review, SHA-256 verification, recovery, and durable reporting.

The project is currently specification-first. See [PLAN.md](PLAN.md) for the implementation plan and [CONTEXT.md](CONTEXT.md) for canonical terminology and safety invariants.

## Local application data

SyncPlus keeps one SQLite database per OS user at:

```text
~/.local/share/syncplus/syncplus.db
```

Related data is stored under the same application directory:

- `backups/` — validated compressed database backups;
- `quarantine/` — explicitly retained corrupt databases;
- `recovery/` — custom recovery data and manifests;
- `~/.cache/syncplus/` — temporary transfer and hash data.

The application never creates SQLite files beside selected source or destination folders. Credentials are stored only through the desktop OS keyring, not in SQLite, logs, reports, or sync folders.

## Design principles

- Safe Delete is opt-in and removes a source item only after independent verification.
- Uncertainty preserves the source and keeps the run open for review.
- Mirror Sync and One-Way Sync are separate modes.
- No arbitrary shell or rsync arguments and no automatic privilege escalation.
- Every data-changing action is visible, explainable, and recoverable where possible.
