# Architecture

Veil follows Clean Architecture with vertical feature slices. Dependencies point inwards and are enforced by
`tests/Veil.Architecture.Tests`.

```
Veil.Api ──► Veil.Application ──► Veil.Domain ──► Veil.Crypto
   │                │
   └──► Veil.Infrastructure ──┘        Veil.Client ──► Veil.Client.Sdk ──► Veil.Contracts + Veil.Crypto
```

| Project | Responsibility | Depends on |
|---|---|---|
| `Veil.Crypto` | Protocol primitives and constructions. No I/O, no server concepts. | BouncyCastle |
| `Veil.Contracts` | Request/response records of the HTTP API and hub notifications. | — |
| `Veil.Domain` | Aggregates, value objects, invariants, domain events, `Result`/`Error`. | `Veil.Crypto` (to validate uploaded key bundles) |
| `Veil.Application` | Commands/queries and their handlers, validators, ports (repositories, security services, real-time), pipeline behaviors. | `Veil.Domain`, `Veil.Contracts`, FluentValidation |
| `Veil.Infrastructure` | Adapters: EF Core/PostgreSQL, Redis, Argon2id, JWT, TOTP, field encryption, outbox, audit chain, maintenance. | `Veil.Application` |
| `Veil.Api` | Composition root and HTTP/SignalR surface. | everything above |

## Request pipeline

```
HTTP ─► exception handler ─► forwarded headers ─► HSTS/HTTPS ─► security headers ─► request logging
     ─► CORS ─► rate limiter ─► authentication (JWT + stamp/device check) ─► authorization ─► endpoint
                                                                                              │
                                        ISender.Send(command) ◄───────────────────────────────┘
                                              │
                          LoggingBehavior ─► ValidationBehavior ─► handler ─► repositories ─► SaveChanges
                                                                                       │
                                                       OutboxInterceptor (events → outbox rows) + AuditChainInterceptor
```

Endpoints map request contracts to commands and translate `Result` into HTTP: `Validation → 400`,
`NotFound → 404`, `Conflict → 409`, `Unauthorized → 401`, `Forbidden → 403`, plus a `code` extension and,
for device-set conflicts, a `mismatches` array.

The dispatcher (`Sender`) resolves `IRequestHandler<TRequest,TResponse>` from DI and wraps it in the registered
`IPipelineBehavior`s. It is ~60 lines, has no external dependency and is cached per request type.

## Persistence model

| Table | Notes |
|---|---|
| `users` | `email` encrypted (AES-256-GCM, purpose `users.email`), `email_blind_index` unique HMAC, `totp_secret` encrypted, `security_stamp`, lockout fields, `xmin` concurrency token |
| `devices` | Public identity keys, current signed pre-key and KEM pre-key with signatures, `revoked_at` |
| `one_time_pre_keys` | Consumed with `DELETE … RETURNING … FOR UPDATE SKIP LOCKED` |
| `refresh_tokens` | SHA-256 of the token, `family_id`, `used_at`, `revoked_at`, salted IP hash |
| `conversations` / `conversation_members` | Direct chats have a unique `direct_key`; group `title` encrypted |
| `message_envelopes` | Ciphertext per recipient device, deleted on acknowledgement or after `Messaging:EnvelopeRetention` |
| `audit_entries` | Hash chain: `hash = SHA256(prev ‖ time ‖ action ‖ actor ‖ ip_hash ‖ detail)` |
| `outbox_messages` | Serialised domain events with attempts/last error (dead-lettered after `Outbox:MaxAttempts`) |
| `data_protection_keys` | ASP.NET Core Data Protection key ring |

Naming is snake_case (EFCore.NamingConventions); primary keys are UUIDv7 for index locality.

## Transactional outbox and real-time delivery

1. Aggregates raise domain events (`EnvelopeStored`, `ConversationCreated`, `MemberAdded`, `DeviceRevoked`, …).
2. `OutboxInterceptor` serialises them into `outbox_messages` in the same `SaveChanges` transaction and clears them from the aggregate.
3. `OutboxProcessor` (a `BackgroundService`) wakes on commit or every `Outbox:PollingInterval`, claims a batch with `FOR UPDATE SKIP LOCKED` (safe with several API instances) and dispatches to `IDomainEventHandler<T>` implementations.
4. The real-time handlers push routing-only notifications through `IHubContext<ChatHub, IChatClient>` to SignalR groups `user:{id}` and `device:{id}`; a Redis backplane fans out across instances.
5. Clients react by pulling `GET /messages/pending`, decrypting locally and acknowledging.

Delivery is at-least-once; handlers are idempotent because the notification is just a hint to pull.

## Audit chain

`HashChainAuditor` adds `AuditEntry` rows to the unit of work with placeholder hashes. At commit time
`AuditChainInterceptor` opens a transaction if none exists, takes `pg_advisory_xact_lock`, reads the latest
hash and links the new rows in order. Because the lock is transaction-scoped, concurrent commits are strictly
serialised and the chain can never fork. `AuditChainVerifier` re-walks the table and reports the first broken row.

`detail` is stored as `text` (not `jsonb`) and timestamps are truncated to microseconds before hashing, so the
bytes that are hashed are exactly the bytes PostgreSQL returns.

## Session validity

Access tokens carry `sub`, `did` (device) and `sst` (security stamp). On every request the JWT handler checks
the signature and lifetime and then `ISessionValidator` confirms the stamp is current and the device is active
through `HybridCache` (5 s local / 30 s Redis). The handlers that change these facts invalidate the cache, so
password changes, "log out everywhere" and device revocation take effect immediately on the node that performed
them and within seconds elsewhere.

## Observability

`Veil.ServiceDefaults` wires OpenTelemetry tracing (ASP.NET Core, HttpClient, Npgsql, the `Veil.Application`
activity source), metrics (ASP.NET Core, HTTP, runtime) and logs, exported over OTLP when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set. Serilog writes compact JSON in production; logs never contain payloads,
passwords, tokens or raw IP addresses. Health: `/alive` (liveness) and `/health` (PostgreSQL + Redis readiness).
