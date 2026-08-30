---
status: accepted
---

# Test real external-filesystem compatibility before release

Portable unit tests will cover destination naming rules, but v1 release evidence must also include a real external-filesystem test on at least one case-insensitive or restricted filesystem such as NTFS, FAT32, or exFAT. The test will exercise collisions, unsupported names, and path restrictions through the actual destination precheck.

SyncPlus must detect affected items before file changes and present the exact conflict or remediation. The test must prove that it does not silently overwrite, omit, or rename incompatible files.
