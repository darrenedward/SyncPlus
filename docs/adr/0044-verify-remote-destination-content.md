---
status: proposed
---

# Verify the actual remote destination after SSH transfer

For a local-to-SSH transfer, SyncPlus will obtain a SHA-256 digest of the actual remote destination file after transfer and compare it with the source digest. The verification must use a controlled, safely parameterized remote operation; it must not trust an rsync exit code alone.

If the remote digest cannot be obtained, the remote file cannot be read, or the digest differs, SyncPlus will preserve the source and mark the action unresolved. A remote server is assumed to be the user's trusted peer for the normal verification model; protection against a malicious peer that lies about its digest would require reading the remote bytes back locally and is outside the normal first-release path.
