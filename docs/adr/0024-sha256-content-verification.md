---
status: proposed
---

# Use streamed SHA-256 for content verification

SyncPlus will use streamed SHA-256 digests when it needs cryptographic evidence that regular-file content is byte-identical or that a destination transfer is safe for Verified Removal. Metadata such as size and modification time may be used for fast triage, but metadata equality alone is not sufficient proof.

Equal SHA-256 digests at different paths may be reported as possible duplicates or rename candidates and opened in the same read-only Conflict Review as other reviewable items, but SyncPlus will not infer logical identity, rename, or a deletion from hash equality alone. Hashing must be cancellation-aware and must not read file contents into persistent reports.
