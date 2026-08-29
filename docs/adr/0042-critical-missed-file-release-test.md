---
status: proposed
---

# Make missed critical files a release-blocking contract test

The v1 contract tests will include a scenario in which an important source item is missed, cannot be verified, or becomes unavailable during a Safe Delete run. The test must assert that SyncPlus preserves the source item, identifies it in the report, prevents the final **Complete** action, and offers safe resume after the condition is corrected.

This test expresses the intended product safety contract rather than the current implementation. A passing transfer count, process exit code, or successful handling of other files must not allow the scenario to pass.
