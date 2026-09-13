---
status: proposed
---

# Explain sync actions in plain language first

Simple Mode will present plain-language action summaries and consequences rather than requiring users to understand rsync flags. Advanced Mode may expose the exact generated command and technical diagnostics for inspection, but all previews and copyable output must redact passwords, private-key material, and other secrets.

Review presents the validated effective configuration before the action map,
including the Sync mode, endpoints, deletion choices, exclusions, and—where
Advanced Mode applies—transfer resilience, metadata, bandwidth, and
unattended consequences. Execution Confirmation repeats the data-changing
choices immediately before a run; a per-run Safe Delete method remains an
explicit choice and never silently falls back from Trash to Permanent Removal.

The Help section will explain each option, why it matters, when to use it, and its limitations. The command preview is diagnostic evidence, not an additional free-form command interface.
