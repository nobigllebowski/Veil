# ADR 0005 — Credentials, tokens and session revocation

**Status**: accepted

## Decisions

- **Argon2id** (64 MiB, 3 iterations, 4 lanes) in PHC string format. Parameters are parsed from the stored hash,
  so costs can be raised and old hashes are transparently re-hashed at the next successful login.
- **Access tokens**: ES256 JWTs, 10 minutes, `typ=at+jwt`, claims `sub`, `name`, `did`, `sst`, `jti`. The public
  key is published at `/.well-known/jwks.json`.
- **Refresh tokens**: 256-bit random, stored as SHA-256, single-use, grouped in families. Reuse of a consumed token
  revokes the family (detects theft when both the attacker and the victim try to refresh).
- **Immediate revocation**: the `sst` (security stamp) claim and the device id are checked on every request through
  a short-lived HybridCache entry that the mutating handlers invalidate. This keeps stateless-JWT performance
  while making password changes, global logout and device revocation effective at once.
- **TOTP** is optional; each time-step is accepted at most once per user (Redis `SET NX`), secrets are encrypted at rest.

## Consequences

- One cached lookup per authenticated request (local cache 5 s, Redis 30 s).
- Users must re-authenticate after a password change on other devices — the intended behaviour.
