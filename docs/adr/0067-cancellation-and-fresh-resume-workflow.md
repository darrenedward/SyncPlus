---
status: proposed
---

# Coordinate cancellation, interruption, retry, and resume in one run workflow

The core execution workflow owns the boundary between Fresh Analysis, the
durable Action Journal, controlled transfer processes, and Safe Delete. It
persists the complete plan before starting an action, records start and
progress boundaries, and stops launching new actions once cancellation is
requested. The current transfer is terminated through the existing process
group supervisor. Cancellation records a `Cancelled` Action and leaves the
source and any previous destination version preserved.

Incomplete transfer files use a SyncPlus-owned hidden name. Cleanup is the
default policy. **Keep Partial for Resume** is an explicit profile option;
retained files are excluded from Source Inventory, are never treated as
verified content, and remain until the resumed run completes successfully.

An open journal boundary is classified on restart. Ordinary transfer
boundaries become an `Interrupted` Action. Boundaries after Safe Delete proof
or removal starts become Recovery Review because the filesystem outcome may
be ambiguous. Resume does not replay the old plan. It performs Fresh Analysis
against the current peers, creates a new Sync Run, and executes only the
actions still required by that analysis.

Retries are limited by the frozen, validated Retry Policy and apply only to
typed transient transfer failures. Identity changes, verification failures,
policy failures, and unresolved recovery conditions are not retried as if
they were transport failures. Completion Reconciliation remains a separate
follow-up concern and is not implied by this workflow.
