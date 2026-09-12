# ADR 0001 — Hybrid post-quantum key agreement (PQXDH)

**Status**: accepted

## Context

Classical X3DH relies entirely on X25519. Traffic recorded today could be decrypted once a cryptographically
relevant quantum computer exists ("harvest now, decrypt later"). Signal addressed this in 2023 with PQXDH.

## Decision

Implement PQXDH: keep the X25519 agreements for authentication and forward secrecy and mix an ML-KEM-768
shared secret into the HKDF that derives the session key. ML-KEM-768 (FIPS 203, security category 3) is the
consensus choice for a hybrid scheme. Use BouncyCastle's managed implementation so the library runs on every
platform regardless of the OpenSSL version (the .NET 10 `MLKem` type requires OpenSSL 3.5).

## Consequences

- Bundles grow by 1184 bytes and the first message by 1088 bytes; negligible for messaging.
- The KEM pre-key is a rotating last-resort key; one-time PQ pre-keys can be added later without a protocol break because the header already carries the KEM key id.
- The Double Ratchet itself stays classical, as in Signal's current deployment; a PQ ratchet (SPQR-style) is a possible future extension.
