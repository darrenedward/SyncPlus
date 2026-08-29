---
status: proposed
---

# Include SSH peers in the first release

The first release will support local folders, external drives, and SSH peers. SSH support must use the same safety lifecycle as local synchronization: Run Precheck, Fresh Analysis, explicit review and confirmation, cryptographic verification, interruption handling, safe resume, and durable reporting.

SSH-specific safeguards are required for the first release: recommended key authentication, explicit host-fingerprint approval, remote `rsync` capability preflight, validated options instead of raw commands, source preservation on uncertainty, and no silent fallback to a riskier method.
