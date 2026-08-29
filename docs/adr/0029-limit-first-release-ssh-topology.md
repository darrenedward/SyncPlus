---
status: proposed
---

# Limit first-release SSH topology to one remote peer

SyncPlus v1 will support synchronization between one local peer and one SSH peer in either direction. It will not support SSH-to-SSH synchronization in the first release.

This keeps credential handling, host identity approval, remote capability checks, failure recovery, and user explanations within a predictable desktop workflow. SSH-to-SSH can be considered later as a separate capability with its own precheck and recovery design.
