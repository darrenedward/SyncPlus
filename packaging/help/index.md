# SyncPlus Help

SyncPlus shows a fresh plan before a data-changing Sync Run. Review the source,
destination, exclusions, overwrites, removals, recovery method, and unresolved
items before confirming.

## Safety boundaries

- One-Way Sync treats the selected source as authoritative.
- Safe Delete preserves the source until destination installation, independent
  SHA-256 and size verification, source-stability checks, and a durable journal
  boundary all succeed.
- Mirror Sync has no implicit winner. Conflicts require whole-file review.
- Uncertainty, unavailable evidence, failed verification, and unresolved items
  keep the source and the Run Report available for Recovery Review.

## Background scheduling

Scheduling is disabled by default and runs as the current desktop user. The
package installs a fixed per-user systemd service and timer; it does not install
a root daemon. Use the desktop menu action **Enable user-level background
scheduler**, or run `syncplus-scheduler-register` as the intended user.

The scheduler uses the same core workflow as the visible application. It cannot
bypass prechecks, authorization, verification, confirmation policy, or Recovery
Review. Disable it with the matching desktop action or
`syncplus-scheduler-unregister` before uninstalling the package.

## Data and uninstall

Profiles, schedules, Run Reports, recovery records, and database backups live
under the per-user XDG SyncPlus data directory. Package installation, upgrade,
and removal operate on application files only and preserve that user data.
