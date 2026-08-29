---
status: proposed
---

# Explain sync actions in plain language first

Simple Mode will present plain-language action summaries and consequences rather than requiring users to understand rsync flags. Advanced Mode may expose the exact generated command and technical diagnostics for inspection, but all previews and copyable output must redact passwords, private-key material, and other secrets.

The Help section will explain each option, why it matters, when to use it, and its limitations. The command preview is diagnostic evidence, not an additional free-form command interface.
