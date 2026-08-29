## Problem Statement

Rsync concepts such as trailing slashes, itemized flags, deletion options, and remote authentication are too technical for a safe default desktop experience. Users also need durable profiles and reports without accidentally copying credentials or changing an active run.

## Solution

Build the Simple/Advanced desktop UI around the core workflow: clear location mapping, plain-language Explainable Actions, plan and Conflict Review panels, progress/results, profiles, cloning, Help, notifications, themes, tray behavior, and explicit confirmation flows.

## User Stories

1. As a new user, I want Simple Mode as the default, so that I see only the controls needed for a safe ordinary run.
2. As an experienced user, I want Advanced Mode remembered across restarts, so that I do not repeatedly configure my preferred view.
3. As a user, I want folder selection to explain whether the folder itself or its contents are copied, so that trailing-slash syntax cannot surprise me.
4. As a user, I want a clear plan before execution, so that I can inspect files, counts, sizes, overwrites, deletions, exclusions, and unresolved items.
5. As a user, I want one final confirmation summarizing destructive consequences, so that I can approve the complete run without repeated per-file popups.
6. As a user, I want the command preview available in Advanced Mode but secrets redacted, so that technical users can inspect execution safely.
7. As a user, I want a read-only Git-like Conflict Review, so that I can decide between peer versions without editing files inside SyncPlus.
8. As a user, I want exclusions entered as patterns and previewed with matching counts, so that I can avoid temporary or unwanted files intentionally.
9. As a user, I want to Clone Profile with both endpoints visible, so that I can create a similar profile without accidentally targeting the same pair.
10. As a user, I want cloning to warn before copying unattended destructive authorization, so that a copied profile does not silently gain deletion permission.
11. As a user, I want profile changes isolated from active runs, so that editing a profile cannot change a run I already approved.
12. As a user, I want reports to remain visible until I remove them, so that I can review completed and unresolved work later.
13. As a user, I want unresolved reports to require a distinct discard action, so that recovery history cannot disappear accidentally.
14. As a user, I want X to hide the app to the tray and Menu → Quit to ask about an active run, so that closing the window does not accidentally interrupt work.
15. As a user, I want concise notifications with the reason and next action, so that missed schedules, permission failures, and review items are actionable.
16. As a user, I want Help to explain what, why, how, when, consequences, and limitations, so that I can use Advanced features responsibly.

## Implementation Decisions

- Keep all safety decisions in the core; UI panels render plans, statuses, and commands rather than implementing policy independently.
- Use Simple Mode for common locations, One-Way non-destructive defaults, exclusions, progress, Help, and results. Advanced Mode exposes validated metadata, transport, performance, schedule, and authorization controls.
- Persist mode preference per OS user. Advanced Mode never bypasses safety invariants.
- Show plain-language mapping and Explainable Actions first. Show the exact generated Process Specification/command only as a redacted Advanced diagnostic.
- Use one final Execution Confirmation per run after per-path plan review. High-risk source scopes require an exact-path confirmation in Advanced Mode.
- Implement Clone Profile as an editable copy requiring at least one changed endpoint. Destructive unattended authorization requires a dedicated copy confirmation; Permanent Removal remains separate.
- Freeze the Profile Snapshot at execution start and show later edits as applying to a future run.
- Keep Run Reports and review states durable. Separate Remove Completed Report from Discard Unresolved Run.
- Use system-tray hide versus explicit Quit semantics. Quit prompts when an active manual run would be stopped; scheduled background work is independent.
- Provide accessible colors, keyboard navigation, text alternatives for status, and clear warnings without relying on color alone.

## Testing Decisions

- Test the UI at the highest boundary available by driving core results through view models/state transitions and a small set of end-to-end interaction tests.
- Test Simple/Advanced mode defaults and persistence, mapping explanations, confirmation contents, redaction, exclusion editing, clone validation, report retention/discard, Help navigation, tray/Quit behavior, and notifications.
- Assert that UI controls cannot bypass core blockers, alter an active Profile Snapshot, hide unresolved work, or enable unattended Permanent Removal without its separate authorization.
- Test read-only Conflict Review with text, binary, unreadable, rename, and destination compatibility cases.
- Test accessibility semantics, keyboard operation, focus order, contrast, and non-color status indicators.
- Prior art is the domain glossary, ADRs, and plan contracts; there is no existing UI implementation to treat as a behavioral oracle.

## Out of Scope

- Editable merge UI, arbitrary command editing, account management, multi-user profiles, cloud services, and mobile clients.

## Further Notes

The UI should be calm and concise even when the underlying safety model is sophisticated. Every important action must answer what will happen, why, when, and what the user can do if it cannot proceed.
