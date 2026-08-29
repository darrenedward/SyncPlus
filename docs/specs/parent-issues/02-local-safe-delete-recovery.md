## Problem Statement

Local folders and external drives are where users most need confidence. A transfer that misses one file, loses executable metadata, mishandles a case-insensitive filesystem, or deletes the source before verification can make an application or dataset unusable.

## Solution

Implement local peer support, external-drive detection, destination compatibility checks, essential metadata fidelity, per-item Safe Delete, Verified Replacement, local Trash/recovery, Restore, and final source-draining behavior. The workflow must clearly distinguish Source Drained from Source Not Empty.

## User Stories

1. As a desktop user, I want to select two local folders or an external drive, so that I can synchronize ordinary desktop data.
2. As a desktop user, I want the app to detect when the source or destination is unavailable, so that it does not write to the wrong device.
3. As a desktop user, I want resume to verify the external volume identity, so that a replacement drive at the same mount path cannot receive data accidentally.
4. As a desktop user, I want source and destination overlap rejected before execution, so that a folder cannot sync into itself or recursively include its destination.
5. As a desktop user, I want case, Unicode, reserved-name, invalid-character, and path-length conflicts detected for the destination filesystem, so that files are not silently lost or overwritten.
6. As a desktop user, I want file type, executable permissions, and symlink targets preserved and verified by default, so that transferred applications and scripts remain usable.
7. As a desktop user, I want specialist metadata such as ownership, ACLs, and extended attributes to be explicit Advanced options, so that I understand when the destination must support them.
8. As a Safe Delete user, I want each verified source item moved to recoverable Trash where possible, so that I can restore it if I discover a mistake.
9. As a desktop user, I want the old destination version protected until the new version is verified, so that an interrupted overwrite does not destroy the previous copy.
10. As a desktop user, I want same-filesystem recovery to use an atomic move, so that SyncPlus does not waste space copying data that can be moved safely.
11. As a desktop user, I want cross-filesystem recovery to copy, verify, and then remove the original only when there is enough space, so that recoverability is not falsely claimed.
12. As a desktop user, I want Restore to refuse overwriting a newer or different file, so that recovery cannot destroy newer work.
13. As a desktop user, I want the report to say Source Drained or Source Not Empty and list every reason, so that I know whether exclusions or unresolved files remain.
14. As a desktop user, I want permissions failures to identify the path and required access, so that I can fix ownership or group membership and retry without SyncPlus changing permissions.
15. As a desktop user, I want a sensitive-path warning for one-way source draining but not Mirror Sync, so that legitimate old-server archives remain possible while risky source deletion is made visible.

## Implementation Decisions

- Support local-to-local peers, including removable volumes, with volume identity captured for resumable tasks.
- Use a local filesystem capability adapter for path normalization, type checks, effective access checks, free-space checks, atomic moves, Trash integration, and metadata operations.
- Keep the selected source root itself; remove only settled child items and empty child directories within the Approved Sync Scope.
- Include hidden files by default. Exclusions remove items from the Approved Sync Scope and never imply deletion.
- Apply Path Risk Warnings only to one-way Safe Delete. The warning is advisory, not an allow/deny rule; high-risk paths require stronger confirmation in Advanced Mode.
- Support regular files, directories, and symlinks. Preserve symlinks as links and do not follow them by default. Report unsupported special files.
- Use local operating-system Trash metadata for native Trash. Use a custom recovery folder and sidecar manifest when native Trash is unavailable.
- Never use copy-then-delete when a same-filesystem atomic move is available. Cross-filesystem recovery requires verified copy, sufficient space, and source preservation on failure.
- Use SQLite-backed recovery provenance, including original peer/path, run, time, type, and hash where applicable.

## Testing Decisions

- Test the local peer seam with disposable directories and real filesystem operations, not only mocked file APIs.
- Cover identical files, new files, modified files, executable bits, symlinks, empty directories, exclusions, hidden files, open/growing files, permission failures, insufficient space, drive removal, volume replacement, and path overlap.
- Assert that a destination mismatch, source mutation, failed recovery copy, or unavailable Trash never removes the source.
- Assert Verified Replacement preserves the prior destination on failed transfer, cancellation, or verification.
- Run real external-filesystem tests on at least one case-insensitive/restricted filesystem such as NTFS, FAT32, or exFAT where available.
- Test Restore collisions, provenance, sidecar validation, Source Drained/Source Not Empty reporting, and sensitive-path warnings.

## Out of Scope

- SSH peers, SSH-to-SSH, advanced content merging, hard-link preservation, device nodes, sockets, FIFOs, and automatic ownership/permission repair.

## Further Notes

The local workflow is the reference implementation for source-preservation guarantees. External-drive disconnect and permission tests are release evidence, not optional polish.
