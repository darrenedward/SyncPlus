---
status: proposed
---

# Protect saved connection secrets with the desktop keyring

SyncPlus will not store SSH passwords in profiles, history, logs, or command previews. Saved Secrets are optional and should use the desktop OS keyring; private keys remain in their existing user-selected files. An optional App Lock PIN may restrict local access, but a forgotten PIN cannot recover encrypted secrets. PIN Reset removes the encrypted Saved Secrets while preserving nonsecret settings so the user can enter credentials again.

SSH key authentication is the recommended default, but the connection flow should make selecting an existing key straightforward. Password authentication may remain an optional fallback without becoming the default or requiring password storage.
