---
status: accepted
---

# Run a non-mutating precheck before confirmation

Every Sync Run will begin with a non-mutating Run Precheck before the change plan can be confirmed or execution can start. The precheck will validate the selected paths and mode, source readability, destination writability, permissions required by the selected deletion method, path overlap, available space, Trash capacity when relevant, and remote capability for SSH peers.

Hard blockers prevent execution and explain the remediation. Warnings are shown distinctly and may require explicit acknowledgement, but SyncPlus will not silently weaken verification, deletion, or conflict-safety rules to make a run proceed. The precheck result is recorded with the run and must be refreshed if material inputs change before execution.
