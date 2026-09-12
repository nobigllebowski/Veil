# Security policy

Veil is a portfolio project, but it is built to be reviewed as if it were production software. Reports are welcome.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") or contact the maintainer directly. Include the affected component
(`Veil.Crypto`, API, SDK, deployment), reproduction steps and the impact you believe it has.

You can expect an acknowledgement within a few days and a fix or mitigation plan after triage. Credit is given
in the changelog unless you prefer otherwise.

## Scope

In scope:

- The protocol implementation in `src/Veil.Crypto` (key agreement, ratchet, encodings, padding, safety numbers)
- Authentication, session and device management in the API and application layers
- Data-at-rest protections (field encryption, blind indexes, audit chain)
- The client SDK's session management and encrypted state store
- Deployment defaults (`Dockerfile`, `docker-compose.yml`, CI workflows)

Out of scope: denial of service through resource exhaustion beyond the documented rate limits, issues in
third-party dependencies (report those upstream, but tell us so we can update), and the development-only keys
shipped in `appsettings.Development.json`, which are intentionally public.

## Cryptographic design notes for reviewers

- Constant-time comparisons for every MAC/tag/hash comparison (`CryptographicOperations.FixedTimeEquals`).
- No custom primitives: X25519, Ed25519, ML-KEM-768 and Argon2id come from BouncyCastle; AES-GCM, HKDF, HMAC
  and SHA-2 from the .NET runtime.
- Every signed structure and every KDF input carries a versioned, domain-separating label (`ProtocolConstants`).
- Ratchet state is mutated only after successful authenticated decryption, so forged messages cannot desync sessions.
- Secrets are zeroed after use where the runtime allows (`CryptographicOperations.ZeroMemory`).

See `docs/THREAT_MODEL.md` for the adversary model and known limitations.
