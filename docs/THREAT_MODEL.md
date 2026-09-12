# Threat model

## Assets

1. Message content and attachments (none yet) — must be readable only by the sending and receiving devices.
2. Long-term identity keys and ratchet state on devices.
3. Account credentials, second-factor secrets, sessions.
4. Social graph and metadata: who talks to whom, when, how much.
5. Integrity of the audit trail.

## Adversaries

| Adversary | Capability | Outcome |
|---|---|---|
| Network attacker | Observes/modifies traffic between client and server | TLS 1.2+/HSTS at transport; content is additionally E2EE; safety numbers detect key substitution |
| Malicious or compromised server | Full read/write of the database and ability to serve arbitrary key bundles | Cannot read content (no keys), cannot forge messages (AEAD + signed pre-keys), cannot substitute identities without changing the safety number, cannot silently add a device (device-set check + `DeviceListChanged`), cannot re-route ciphertext (conversation id inside the plaintext) |
| Database leak | Offline copy of PostgreSQL | Passwords: Argon2id; refresh tokens: SHA-256 hashes; e-mail/TOTP/titles: AES-256-GCM under a key that is not in the database; ciphertext: useless without device keys; audit log: tamper-evident |
| Credential attacker | Password guessing, credential stuffing, enumeration | Per-IP sliding-window limits on auth endpoints, lockout after 5 failures, uniform error and timing for unknown users, exact-match user lookup only, vague response on e-mail collisions |
| Stolen refresh token | Replays a refresh token after the legitimate client already rotated it | Reuse detection revokes the whole family; the audit log records the event |
| Stolen access token | Uses a still-valid bearer token | Lifetime 10 minutes; "log out everywhere", password change and device revocation invalidate it within seconds via the session cache |
| Lost/stolen device | Attacker has the device's storage | Local state is encrypted under an Argon2id-derived passphrase key; the owner revokes the device from another device, after which peers stop encrypting to it and its tokens are rejected |
| Quantum adversary (future) | Records traffic now, breaks X25519 later | Session keys mix in an ML-KEM-768 shared secret; breaking X25519 alone is insufficient |
| Insider with database write access | Edits or deletes audit rows | Every row commits to the previous hash; `AuditChainVerifier` pinpoints the first broken row |

## Protections by layer

- **Transport**: HTTPS redirect and HSTS (preload) outside development; forwarded headers trusted only from configured proxies; no `Server` header; 20 MiB body limit; strict CSP/COOP/CORP/Referrer-Policy/Permissions-Policy.
- **Authentication**: ES256 JWTs with `typ=at+jwt`, issuer/audience/algorithm pinning, 30 s clock skew; hub authentication accepts the query-string token only on `/hubs/*`.
- **Authorization**: fallback policy requires authentication everywhere; `DeviceBound` policy for key material and envelopes; membership checks return 404 to non-members.
- **Input**: FluentValidation on every command, byte-length checks on every key, signature verification on every uploaded bundle, bounded batch sizes.
- **Storage**: purpose-bound column encryption, blind indexes, salted IP hashes, minimal retention (envelopes deleted on ack, expired ciphertext/tokens/outbox rows purged).
- **Operations**: secrets only from environment/secret stores, development keys clearly marked, chiseled non-root container, read-only filesystem, dropped capabilities, `no-new-privileges`, Trivy and CodeQL in CI, NuGet audit at build time.

## Explicitly not protected

- **Metadata**: the server knows accounts, device counts, conversation membership, message timing and ciphertext sizes (coarsened by padding). Sealed sender and traffic shaping are future work.
- **Compromised endpoint**: malware on a device sees plaintext; nothing on the server can help.
- **Availability**: rate limits mitigate abuse but do not defend against volumetric DDoS; put the API behind a CDN/WAF.
- **Group scaling**: pairwise fan-out means a 256-member group costs up to ~2 500 encryptions per message on the sender.
- **Passphrase quality**: local state security is bounded by the user's passphrase (Argon2id raises the cost, it does not fix weak secrets).

## Residual risks and mitigations to consider before production

- Field-encryption and blind-index keys are single master keys; add a KMS-backed envelope scheme and a rotation procedure (the `v1.` prefix is there to support it).
- The audit chain proves integrity but not availability; ship copies to an append-only external store.
- Add anomaly detection on refresh-token reuse and lockout events (the audit log already provides the signal).
- Add a breached-password screen (e.g. k-anonymity range queries) on registration and password change.
