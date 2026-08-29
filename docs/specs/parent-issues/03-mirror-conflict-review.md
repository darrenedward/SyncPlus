## Problem Statement

Mirror Sync must keep both peers aligned without inventing an authority. Independent edits, deletions, same-hash files at different paths, and destination naming rules require a clear human decision. A simple “newest wins” rule could destroy valid work.

## Solution

Implement Sync Baselines, bidirectional Mirror planning, explicit deletion evidence, read-only Conflict Review, whole-file Resolution choices, preserved conflict copies, Rename Resolution, Resolution Runs, and Mirror Equality checks.

## User Stories

1. As a Mirror user, I want both peers to remain populated after a successful run, so that Mirror is not confused with moving data.
2. As a Mirror user, I want the first run without a baseline to treat one-sided items as copy candidates, so that absence is not mistaken for deletion.
3. As a Mirror user, I want independent edits at the same path identified as a conflict, so that neither version is silently discarded.
4. As a Mirror user, I want a read-only side-by-side comparison like Git diff, so that I can inspect text differences before choosing.
5. As a Mirror user, I want binary or unreadable files compared through metadata, type, size, and hashes, so that review still works without rendering content.
6. As a Mirror user, I want Keep Peer A, Keep Peer B, Preserve Both, Rename/Preserve for Review, and Defer choices, so that I can choose the correct outcome per path.
7. As a Mirror user, I want deletions to require explicit review and confirmation even when the baseline suggests they were intentional, so that absence never becomes silent deletion permission.
8. As a Mirror user, I want preserved copies to show both original and generated paths in the report, so that I can decide later what to remove.
9. As a Mirror user, I want same-hash files at different paths shown as possible duplicates or renames, so that I can investigate without automatic movement.
10. As a Mirror user, I want unresolved conflicts to keep the run open, so that Complete is unavailable until the peers are truly reconciled.
11. As a Mirror user, I want a Resolution Run to re-analyze current files, so that a stale conflict decision cannot overwrite newer work.
12. As a Mirror user, I want the same read-only review surface for content conflicts, rename candidates, and destination compatibility conflicts, so that the app remains intuitive.

## Implementation Decisions

- Use a persistent Sync Baseline containing only successfully reconciled and verified paths.
- Compare path identity first, then item type and enabled metadata, then content hashes as needed. Hash equality at different paths is evidence only.
- Keep Mirror without an inherent source authority. Deletion propagation requires baseline evidence plus explicit reviewed action and confirmation.
- Model Conflict Review as read-only. The first implementation makes whole-file decisions and does not offer an editable merge editor.
- Generate deterministic, human-readable, collision-safe names for Preserve Both and Rename Resolution.
- Keep preserved copies visible in the Run Report and Review Later state. Removing a preserved copy is a later explicit action; in Mirror, removal must be applied consistently to both peers.
- Use Resolution Runs for all deferred or post-unattended decisions. Re-analyze current state and request fresh confirmation for data changes.
- Do not show the special source-draining Path Risk Warning for Mirror, while still showing ordinary deletion consequences and confirmation.

## Testing Decisions

- Test through the core Mirror planning/resolution seam with generated peer trees and baselines, then verify the final filesystem state.
- Cover first-run one-sided items, baseline deletions, independent edits, metadata-only differences, same-hash different-path files, preserved copies, collisions, skipped items, and Resolution Runs.
- Assert no implicit winner, no automatic rename, no silent deletion, no editable merge side effects, and no Review-Cleared result while any required conflict remains.
- Test the read-only UI boundary with representative text, binary, unreadable, Unicode, and large-file fixtures.
- Test that preserved copies and later removals maintain the Mirror Invariant.

## Out of Scope

- Automatic semantic merges, three-way merge algorithms, SSH-to-SSH Mirror Sync, and logical identity inference from hashes alone.

## Further Notes

Mirror Sync is a separate product mode from One-Way Safe-Delete Sync. This parent must not import source-draining assumptions into Mirror planning.
