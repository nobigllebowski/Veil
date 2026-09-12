<p align="center">
  <img src="https://img.shields.io/badge/.NET-10.0_LTS-512BD4?logo=dotnet&logoColor=white" alt=".NET 10">
  <img src="https://img.shields.io/badge/C%23-14-239120?logo=csharp&logoColor=white" alt="C# 14">
  <img src="https://img.shields.io/badge/E2EE-PQXDH%20%2B%20Double%20Ratchet-6f42c1" alt="E2EE">
  <img src="https://img.shields.io/badge/post--quantum-ML--KEM--768-0a7f5a" alt="ML-KEM-768">
  <img src="https://img.shields.io/badge/tests-156%20passing-2ea44f" alt="tests">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT">
</p>

<h1 align="center">Veil</h1>
<p align="center"><b>An end-to-end encrypted messenger on .NET 10 whose server is designed to know as little as possible.</b></p>

Veil is a Signal-style secure messaging platform: a hardened ASP.NET Core API, a real-time SignalR hub, a
pure-C# implementation of the **PQXDH** key agreement (X25519 + post-quantum **ML-KEM-768**) and the
**Double Ratchet**, a client SDK, and a terminal client. Message content is encrypted on the sender's device
and decrypted only on the recipient's devices; the server routes ciphertext and deletes it once delivered.

```
┌──────────────┐  PQXDH handshake, Double Ratchet, AES-256-GCM   ┌──────────────┐
│  veil (CLI)  │◄════════════════ end-to-end ════════════════════►│  veil (CLI)  │
│  Client SDK  │                                                  │  Client SDK  │
└──────┬───────┘                                                  └──────┬───────┘
       │ HTTPS · JWT ES256 · SignalR/MessagePack                        │
       ▼                                                                ▼
┌───────────────────────────── Veil.Api ─────────────────────────────────────┐
│ Minimal APIs · rate limiting · security headers · ProblemDetails · OpenAPI │
│ Application (CQRS + validation pipeline) · Domain (DDD aggregates)         │
│ Infrastructure: EF Core 10 + PostgreSQL 17 · Redis 7 · outbox · audit      │
│ stores: public pre-keys, ciphertext envelopes (until acknowledged),        │
│         encrypted e-mail/TOTP/group titles, hash-chained audit log         │
└────────────────────────────────────────────────────────────────────────────┘
```

## Highlights

**Cryptography (`Veil.Crypto`, no server dependencies, 49 tests incl. RFC vectors)**

| Layer | Choice | Why |
|---|---|---|
| Key agreement | **PQXDH**: X25519 ×3/4 DH + ML-KEM-768 encapsulation, HKDF-SHA256 | Authenticated, forward-secret and *harvest-now-decrypt-later* resistant |
| Message keys | **Double Ratchet** (DH ratchet + HMAC-SHA256 symmetric chains) | Forward secrecy + post-compromise security per message |
| AEAD | AES-256-GCM, key + nonce derived per message via HKDF | Authenticated encryption, header bound as associated data |
| Signatures | Ed25519 over domain-separated encodings | Pre-key substitution by a malicious server is detectable |
| Metadata | ISO 7816-4 padding to 160-byte blocks, conversation id inside the ciphertext | Length hiding, no server-side re-routing |
| Verification | 60-digit safety numbers, trust-on-first-use pinning with change alerts | Out-of-band MITM detection |
| Local state | Argon2id-derived key, AES-256-GCM file | Device keys and sessions never rest in the clear |

**Server security**

- Argon2id (64 MiB / 3 / 4) password hashes in PHC format with transparent re-hash on parameter upgrades; timing-equalised login for unknown users; lockout after repeated failures.
- ES256 access tokens (10 min) + opaque, hashed refresh tokens with **rotation and reuse detection** (a replayed token revokes the whole family). Security-stamp and device-revocation checks on every request make "log out everywhere", password changes and device revocation take effect immediately.
- Optional **TOTP** second factor with one-time acceptance per time-step (replay-proof), secrets encrypted at rest.
- **Field-level encryption** (AES-256-GCM, purpose-bound) for e-mail, TOTP secrets and group titles, with an HMAC **blind index** for uniqueness lookups; raw IP addresses are never stored, only salted hashes.
- **Tamper-evident audit log**: every entry commits to the previous entry's hash; writers are serialised with a PostgreSQL advisory lock; an integrity verifier walks the chain.
- Multi-device done right: the server refuses a send that omits any active recipient device and returns the exact diff so the client re-encrypts. One-time pre-keys are consumed with `DELETE … RETURNING … SKIP LOCKED`, never handed out twice.
- Layered rate limiting (per-IP for credentials, per-user for key fetches and lookups), strict CSP/COOP/CORP headers, RFC 9457 problem details, no server header, request body limits, HSTS preload in production.
- Data minimisation workers purge delivered/expired ciphertext, dead tokens and processed outbox rows.

**Engineering**

- .NET 10 LTS, C# 14, Minimal APIs, EF Core 10, Npgsql, SignalR with MessagePack + Redis backplane, HybridCache, OpenTelemetry (traces/metrics/logs), Serilog, .NET Aspire AppHost, Scalar API reference, central package management, analyzers with warnings-as-errors.
- Clean Architecture with vertical slices, a dependency-free CQRS dispatcher with validation/logging behaviors, DDD aggregates raising domain events, a **transactional outbox** (`FOR UPDATE SKIP LOCKED`, at-least-once) feeding real-time notifications.
- 156 tests: crypto known-answer tests, domain rules, handler unit tests, infrastructure services, executable architecture rules (NetArchTest) and end-to-end integration tests against real PostgreSQL and Redis (Testcontainers or CI service containers).
- Chiseled, non-root, read-only container; Compose stack with Caddy TLS; GitHub Actions CI with format/analyzer gates, Trivy image scan, CodeQL and dependency review.

## Repository layout

```
src/
  Veil.Crypto/          PQXDH, Double Ratchet, key bundles, envelopes, safety numbers (pure library)
  Veil.Contracts/       Wire contracts shared by server and SDK
  Veil.Domain/          Aggregates (User, Device, Conversation, MessageEnvelope, RefreshToken), value objects, Result/Error
  Veil.Application/     Use cases (commands/queries), ports, pipeline behaviors, domain event handlers
  Veil.Infrastructure/  EF Core + PostgreSQL, Redis, Argon2id, JWT, TOTP, field encryption, outbox, audit chain, migrations
  Veil.Api/             HTTP host: endpoints, SignalR hub, auth, rate limiting, security headers, OpenAPI
  Veil.ServiceDefaults/ OpenTelemetry, health checks, resilience, service discovery
  Veil.AppHost/         .NET Aspire orchestration (PostgreSQL + Redis + API with one F5)
  Veil.Client.Sdk/      Typed API client, real-time client, E2EE session manager, encrypted state store
  Veil.Client/          Terminal chat client
tests/
  Veil.Crypto.Tests · Veil.Domain.Tests · Veil.Application.Tests · Veil.Infrastructure.Tests
  Veil.Api.IntegrationTests (real PostgreSQL/Redis) · Veil.Architecture.Tests
docs/                   ARCHITECTURE.md · PROTOCOL.md · THREAT_MODEL.md · adr/
```

## Quick start

### Option A — .NET Aspire (recommended for development)

Requires the .NET 10 SDK and Docker (or Podman).

```bash
dotnet run --project src/Veil.AppHost
```

The Aspire dashboard shows PostgreSQL, Redis and the API with logs, traces and metrics. The API applies
migrations on start and serves the interactive API reference at `/scalar/v1`.

### Option B — backing services in Docker, API from the CLI

```bash
docker compose -f docker-compose.dev.yml up -d      # PostgreSQL + Redis with dev credentials
dotnet run --project src/Veil.Api                  # https://localhost:7443
```

### Option C — full stack with TLS

```bash
scripts/generate-secrets.sh > .env                 # random keys, ES256 signing key, DB/Redis passwords
docker compose up --build                          # https://localhost via Caddy (locally-trusted cert)
```

### Chat from two terminals

```bash
dotnet run --project src/Veil.Client -- --server https://localhost:7443 --insecure   # terminal 1: register "alice"
dotnet run --project src/Veil.Client -- --server https://localhost:7443 --insecure   # terminal 2: register "bob"
```

In Alice's terminal: `/chat bob`, then type. Bob sees the message decrypted live; `/safety` prints the
safety number both sides can compare. Local state (identity keys, ratchet sessions) is stored under
`~/.veil/` encrypted with a passphrase you choose.

> `--insecure` only skips validation of the ASP.NET Core development certificate. Run `dotnet dev-certs https --trust` instead where supported.

## Running the tests

```bash
dotnet test --solution Veil.slnx
```

Integration tests start PostgreSQL and Redis through Testcontainers. Without Docker, point them at existing
services:

```bash
export VEIL_TEST_POSTGRES="Host=localhost;Port=5432;Database=veil_test;Username=veil;Password=veil_dev_password"
export VEIL_TEST_REDIS="localhost:6379,defaultDatabase=5"
dotnet test --solution Veil.slnx
```

## API overview

All routes live under `/api/v1`; every response is JSON, every error is an RFC 9457 problem with a stable
`code`. Full reference: `/scalar/v1` (Development or `OpenApi:Enabled=true`).

| Area | Endpoints |
|---|---|
| Auth | `POST auth/register`, `auth/login`, `auth/refresh`, `auth/logout`, `auth/logout-all`, `auth/password`, `auth/totp/{enroll,confirm,disable}` |
| Users | `GET users/me`, `PATCH users/me`, `GET users/by-username/{name}`, `GET users/{id}/prekeys` |
| Devices | `POST devices`, `GET devices`, `DELETE devices/{id}`, `GET/POST devices/me/prekeys`, `PUT devices/me/{signed,kem}-prekey` |
| Conversations | `GET conversations`, `POST conversations/direct`, `POST conversations/group`, `GET conversations/{id}`, members add/remove |
| Messages | `POST messages` (one envelope per recipient device), `GET messages/pending`, `POST messages/ack` |
| Real-time | SignalR hub `/hubs/chat`: `EnvelopeAvailable`, `ConversationChanged`, `DeviceListChanged`, `Typing` |
| Discovery | `/.well-known/jwks.json`, `/.well-known/veil-configuration`, `/health`, `/alive` |

## Configuration

Secrets come from environment variables or a secret store, never from the repository. `appsettings.Development.json`
ships **development-only** keys so the project runs out of the box.

| Setting | Purpose |
|---|---|
| `ConnectionStrings:Postgres`, `ConnectionStrings:Redis` | Backing services |
| `Security:FieldEncryptionKey` | 32-byte base64 master key for column encryption |
| `Security:BlindIndexKey` | 32-byte base64 HMAC key for blind indexes |
| `Security:IpHashSalt` | Salt for IP hashes in audit/token records |
| `Security:JwtSigningKeyPem` | ECDSA P-256 PKCS#8 PEM (required outside Development) |
| `Security:Argon2:*` | Memory/iterations/parallelism (defaults 64 MiB / 3 / 4) |
| `Auth:*` | Token lifetimes, lockout policy, issuer/audience |
| `RateLimiting:*` | Per-minute permits per limiter |
| `Messaging:EnvelopeRetention` | How long undelivered ciphertext is kept (default 30 days) |
| `Database:MigrateOnStartup` | Apply EF migrations on boot |
| `ReverseProxy:*`, `Https:Redirect`, `Cors:AllowedOrigins`, `OpenApi:Enabled` | Deployment topology |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layers, request pipeline, outbox, persistence model
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — the wire protocol and cryptographic construction, step by step
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, adversaries, what is and is not protected
- [docs/adr/](docs/adr/) — architecture decision records
- [SECURITY.md](SECURITY.md) — vulnerability disclosure
- [README.ru.md](README.ru.md) — краткое описание по-русски

## Roadmap

- Sender Keys for large groups (pairwise fan-out is O(devices) today)
- Sealed sender and one-time post-quantum pre-keys
- Attachments (client-side encrypted blobs with server-side opaque storage)
- WebAuthn/passkeys as a second factor, push notifications, a web client

## License

MIT — see [LICENSE](LICENSE).
