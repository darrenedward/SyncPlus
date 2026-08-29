---
status: proposed
---

# Make the initial conflict review read-only

SyncPlus will provide a read-only side-by-side conflict review with whole-file resolution choices rather than an editable merge editor. This preserves the Git-like inspection experience while keeping the first implementation focused on safe file selection; content editing and three-way merging remain separate future capabilities.

All behavior tests must be written from the intended product contract and safety rules, including the expected behavior of the review and resolution lifecycle, rather than from the current implementation. Verification must include security, error handling, process cleanup, data-protection, and code-quality/compliance checks.
