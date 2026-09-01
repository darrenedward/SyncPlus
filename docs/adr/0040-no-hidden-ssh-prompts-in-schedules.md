---
status: accepted
---

# Require noninteractive SSH credentials for schedules

An automatic Scheduled Run must be able to authenticate to SSH without a hidden or unavailable user prompt. It may use an explicitly configured private key, an available SSH agent, or an explicitly saved secret in the desktop OS keyring according to the profile's authentication settings.

If the selected credential is unavailable, requires a passphrase or password prompt that cannot be fulfilled, or otherwise cannot authenticate noninteractively, SyncPlus will stop the affected operation, preserve the source, record the reason, and notify the user. It will not capture credentials automatically or silently switch to another credential or authentication method.

The scheduler resolves the selected credential in unattended mode and the
shared SSH workflow rejects interactive askpass credentials before backend
work. Host identity and remote capability permits are refreshed immediately
before mutation, with failures recorded as blocked scheduled reports.
