---
status: proposed
---

# Clean up partial transfers on cancel by default

Cancel will remove partial destination data by default, preserving the source and any prior completed destination version where possible. Users may explicitly choose Keep Partial for Resume for large transfers; retained partial data is hidden, never treated as complete, and is removed after successful completion. Safe Delete remains unavailable until full verification.
