---
status: proposed
---

# Report whether the approved source scope was drained

Safe Delete reports will state the source-draining result explicitly. **Source Drained** means every approved and included item was successfully handled, destination-verified, and removed from the source. **Source Not Empty** means the source still contains exclusions, newly appeared items, failed actions, or unresolved items.

The report will list the reason and affected paths for Source Not Empty. It must not describe an incomplete or partially scoped run as if the entire source folder had been emptied.
