# ADR 0003 — Field-level encryption with blind indexes

**Status**: accepted

## Context

Message content is end-to-end encrypted, but the server still holds account metadata: e-mail addresses,
TOTP secrets and group titles. A database leak must not expose them, yet e-mail uniqueness must remain enforceable.

## Decision

Encrypt those columns with AES-256-GCM through EF Core value converters. Each ciphertext is bound to a purpose
string (`users.email`, `users.totp_secret`, `conversations.title`) as associated data and prefixed with a
format version (`v1.`). For lookups, store an HMAC-SHA256 blind index of the normalised e-mail under a
separate key and put the unique constraint on that column.

## Consequences

- Equality lookups only; no `LIKE`/prefix search on encrypted columns (intentional: no directory enumeration).
- Keys live outside the database (environment/secret store). Rotation requires re-encryption; the version prefix
  and purpose binding make a dual-key migration straightforward.
- Model-level converters mean the encryptor is a singleton captured by the EF model; the key cannot change per request.
