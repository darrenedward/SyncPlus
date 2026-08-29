## Problem Statement

Users need to synchronize a local folder or external drive with an SSH server, but a successful login does not prove that the server has compatible rsync, safe hashing, permissions, recovery, or stable identity. Passwords, host keys, and remote paths also create security risks.

## Solution

Implement local-to-SSH and SSH-to-local peers with key-first authentication, controlled interactive askpass, desktop-keyring integration, explicit host-fingerprint approval, remote rsync/hash/recovery preflight, post-transfer remote verification, friendly diagnostics, and safe structured command construction.

## User Stories

1. As a desktop user, I want to connect to an SSH peer with server, username, port, path, and identity fields, so that I do not need to write shell commands.
2. As a desktop user, I want SSH key authentication recommended first, so that unattended operation does not depend on password prompts.
3. As an interactive user, I want password authentication supported through a controlled prompt, so that existing servers remain usable without putting passwords in commands.
4. As a security-conscious user, I want first-use host fingerprint approval, so that I know which server I am trusting.
5. As a security-conscious user, I want changed fingerprints rejected, so that a man-in-the-middle or replaced server cannot be silently trusted.
6. As a desktop user, I want the app to verify remote rsync capability before mutation, so that a login-only success cannot lead to a partial run.
7. As a desktop user, I want the actual remote destination hashed after transfer, so that rsync exit code alone cannot authorize source removal.
8. As a desktop user, I want missing remote credentials or interactive prompts to stop unattended runs safely, so that the app does not hang or guess another credential.
9. As a desktop user, I want remote paths containing spaces, Unicode, control characters, and shell metacharacters handled as data, so that they cannot inject commands.
10. As a desktop user, I want remote permission and recovery failures explained with the account and path, so that I can fix the server and retry.
11. As a Safe Delete user, I want remote Trash only when a recovery location is verified, so that the app never pretends `rm` is recoverable.
12. As a desktop user, I want local↔SSH supported in both directions but SSH↔SSH excluded from v1, so that the first release remains understandable.

## Implementation Decisions

- Support one local peer and one SSH peer in either direction; do not implement SSH-to-SSH in v1.
- Keep server, username, port, identity, authentication, and remote path as structured fields with validated display and transport representations.
- Use SSH keys as the recommended method. Support interactive passwords through a controlled askpass bridge and store saved secrets only in the desktop keyring.
- Require explicit server-fingerprint approval for new hosts and reject changed fingerprints. Never use automatic `ssh-keyscan` trust.
- Preflight remote SSH connectivity, account permissions, compatible rsync, controlled SHA-256 capability, and configured recovery capability before any mutation.
- Verify actual remote destination content after transfer. If remote hash is unavailable or mismatched, preserve the source and mark the item unresolved.
- Use fixed, controlled remote helper operations with safely encoded paths. No raw remote command field exists.
- Treat remote Trash as available only with a verified recovery location and access. Otherwise stop or require separately authorized Permanent Removal.
- Use friendly, actionable diagnostics for missing rsync, hash tools, permissions, host-key changes, connection refusal, and authentication failures.

## Testing Decisions

- Use a real disposable SSH peer for end-to-end tests, with controlled key, password, missing-tool, permission, and host-fingerprint scenarios.
- Test push and pull, spaces/Unicode/control-character paths, remote source changes, network interruption, retry/resume, hash mismatch, and remote recovery failure.
- Assert no remote mutation occurs when capability, identity, credential, or precheck requirements fail.
- Test secret redaction in previews, reports, logs, notifications, process arguments, and database rows.
- Test malformed remote fields and shell metacharacters at the structured Process Specification seam.
- Test unavailable remote Trash never becomes silent permanent removal.

## Out of Scope

- SSH-to-SSH, rsync daemon URLs, automatic SSH config import, password storage outside the keyring, automatic host trust, and malicious-remote high-assurance read-back verification.

## Further Notes

The normal v1 verification model trusts the configured SSH server to report a truthful remote digest. A future high-assurance mode could read remote bytes back locally, but it must not weaken this parent’s fail-closed behavior.
