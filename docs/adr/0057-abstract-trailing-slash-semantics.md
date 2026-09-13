---
status: accepted
---

# Explain folder mapping without requiring rsync syntax knowledge

Simple Mode uses folder-selection semantics that clearly identify the source root and destination mapping without requiring users to understand rsync trailing slashes. The selected destination is the parent for the complete source folder: selecting `/home/user/AI` and `/home/user/Downloads` maps to `/home/user/Downloads/AI`. Before execution it states the resulting operation in plain language. If the source-named child is absent but the selected parent is available, the UI offers explicit creation of that exact child path and rechecks it before analysis.

Advanced Mode may display the exact path syntax and generated command for inspection. The command preview remains diagnostic and must correspond exactly to the reviewed mapping.
