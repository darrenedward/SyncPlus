---
status: proposed
---

# Treat external-drive loss as an interrupted run

If a selected destination is unplugged, unmounted, or otherwise becomes unavailable during execution, SyncPlus will stop affected actions and record an Interrupted Run. Incomplete temporary destination data is removed by default; the user may explicitly choose Keep Partial for Resume when supported. The source remains preserved, and no Safe Delete or Verified Removal is performed for the affected action.

The report remains visible with the completed, interrupted, and remaining scope. After the destination returns, Resume performs a Fresh Analysis and requires fresh confirmation for data-changing actions.
