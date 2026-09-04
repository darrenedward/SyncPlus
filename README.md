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

## Debian package

The supported Linux package is built from the locked Rust workspace with a
deterministic timestamp:

```sh
SOURCE_DATE_EPOCH=0 ./packaging/build-deb.sh
```

The resulting versioned package is written under `target/debian/`. It contains
the application, desktop entry, Brand Mark and desktop icons, Help asset, and fixed per-user systemd
service/timer. Installing the package does not enable a root daemon. Enable or
disable the scheduler explicitly as the desktop user with the desktop-menu
actions or `syncplus-scheduler-register` and `syncplus-scheduler-unregister`.

Run the disposable package contract before release:

```sh
./packaging/test-deb.sh
```

Run the complete disposable release gate, including the scheduling, recovery,
privacy, SSH, process, SQLite, filesystem, and installed-package matrix:

```sh
./packaging/release-gate.sh
```

Each run retains a machine-readable manifest, sanitized per-case logs, tool
versions, and package digest under `target/release-evidence/<run-id>/`. The
command exits nonzero and does not create `RELEASE_READY` when a required case
fails or cannot run.
