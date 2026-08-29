---
status: proposed
---

# Require a changed endpoint when cloning a profile

SyncPlus will provide Clone Profile as an editable, pre-filled form that clearly shows the existing source and destination. The cloned profile may retain one endpoint, but it must change at least one endpoint before it can be saved. A profile with the identical source and destination pair will be rejected as a duplicate, regardless of differing optional settings.

Cloning copies validated nonsecret settings and references to keyring entries where applicable. It will not copy, reveal, export, or duplicate saved passwords or private-key material.

If the source profile has an Unattended Destructive Authorization, the Clone Profile wizard will show a clear warning and ask whether to copy that authorization. The user may continue with it, disable it for the clone, or cancel. Unattended Permanent Removal always requires its separate authorization and confirmation.
