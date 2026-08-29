---
status: proposed
---

# Explain folder mapping without requiring rsync syntax knowledge

Simple Mode will use folder-selection semantics that clearly identify the source root and destination mapping without requiring users to understand rsync trailing slashes. Before execution it will state the resulting operation in plain language, including whether the source folder itself or only its contents will appear at the destination.

Advanced Mode may display the exact path syntax and generated command for inspection. The command preview remains diagnostic and must correspond exactly to the reviewed mapping.
