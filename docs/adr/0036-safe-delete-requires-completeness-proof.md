---
status: proposed
---

# Require completeness proof before Safe Delete completion

The catastrophic failure mode of Safe Delete is deleting source data while silently missing an important item. Per-file destination verification is necessary but insufficient, so SyncPlus will treat Safe Delete as a source-draining workflow with a completeness proof.

For each run, SyncPlus will record a Source Inventory after applying the selected Exclusion Rules, including hidden files by default. It will journal each approved action and verify each destination result before removing that item's source. Before the run can become Review-Cleared, it will perform an independent Completion Reconciliation against the current source, destination, inventory, and journal.

Any unexplained in-scope source item, excluded item presented as a deletion candidate, newly appeared item, changed item, failed action, or unverifiable destination keeps the run incomplete and blocks the final **Complete** action. A successful process exit, matching transfer count, or partial per-file result cannot substitute for reconciliation.

Retries resume from the last durable verified action boundary. Completed actions are not replayed, and a resumed or retried action must still pass destination verification before any source removal. The system must preserve the source whenever it cannot prove completeness.
