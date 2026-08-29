---
status: proposed
---

# Treat safe source deletion as a one-way sync option

SyncPlus will expose Safe Delete as an option on one-way sync, separate from Mirror Sync. With Safe Delete enabled, the app applies the reviewed source-to-destination plan, verifies each destination result, and then removes the corresponding source item. A run is not successful while selected source items remain; failed, skipped, or unstable items must be reported as incomplete. Mirror Sync keeps both peers populated and reconciles changes in both directions. The distinction prevents source cleanup from being accidentally applied to a mode whose purpose is to preserve matching copies.

Safe Delete and Destination Cleanup are independent options: the former removes verified source items, while the latter removes destination items absent from the source. Neither option silently enables the other.

Safe Delete is limited to the Approved Sync Scope. Excluded, skipped, failed, or unstable source items remain in place and prevent the run from being reported as fully drained.

Safe Delete requires Verified Removal: regular-file content must be cryptographically verified at the destination before the source item is removed; a successful rsync exit alone is insufficient.

If a source item changes after planning or during transfer, SyncPlus must notify the user, preserve the source item, and require review before retrying or removing it. Such an item cannot be reported as safely handled in that run.

SyncPlus will provide Interactive and Unattended Run behaviors. Interactive Run pauses for review; Unattended Run defers the changed item, continues unaffected work, and notifies the user at completion. Unattended behavior must not bypass Verified Removal or be presented as force deletion.

An Unattended Run may end with Pending Review items. Opening one presents the read-only peer comparison and creates a Resolution Run from the user's decision. The Resolution Run rechecks the current files before applying the decision and requires fresh Execution Confirmation for data-changing actions.

Source cleanup must preserve the Symlink Policy: a symbolic link is verified and removed as a link, without following it into its target.

Destination Cleanup is independent, opt-in, and disabled by default; enabling it never follows automatically from Safe Delete.

Safe Delete is disabled by default and requires a fresh confirmation for every manually started run, including runs started from a saved profile. An automatic Scheduled Run may use Safe Delete only when the user has explicitly granted the profile an Unattended Destructive Authorization in Advanced Mode after reviewing the consequences.

Destructive actions are reviewed per path in the plan and then require one final Execution Confirmation for the complete run, rather than a separate popup for every file.
