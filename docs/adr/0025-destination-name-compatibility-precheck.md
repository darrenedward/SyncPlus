---
status: proposed
---

# Detect destination naming incompatibilities before changes

Before execution, SyncPlus will evaluate source paths against the actual destination filesystem and transport naming rules. It will detect collisions caused by case-insensitivity or Unicode normalization, reserved or invalid names, path-length limits, and other restrictions that could cause a source item to fail, overwrite a different item, or become unrepresentable.

Affected actions are blocked until explicitly resolved. SyncPlus will show the conflicting source paths and the destination rule involved. It will not silently rename, overwrite, omit, or continue past a Destination Compatibility Conflict. Any user-approved rename is a visible, separately reviewable action and is listed in the final report.
