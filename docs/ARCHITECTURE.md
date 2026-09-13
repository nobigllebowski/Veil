# Architecture

Veil follows Clean Architecture with vertical feature slices. Dependencies point inwards and are enforced by
`tests/Veil.Architecture.Tests`.

```
Veil.Api ──► Veil.Application ──► Veil.Domain ──► Veil.Crypto
   │                │
   ├──► Veil.Infrastructure ──┘        Veil.Client (terminal) ──┐
   │                                                            ├──► Veil.Client.Sdk ──► Veil.Contracts + Veil.Crypto
   └──► Veil.Web (Blazor WebAssembly, served as static files) ──┘
```

| Project | Responsibility | Depends on |
|---|---|---|
| `Veil.Crypto` | Protocol primitives and constructions. No I/O, no server concepts. | BouncyCastle |
| `Veil.Contracts` | Request/response records of the HTTP API and hub notifications. | — |
| `Veil.Domain` | Aggregates, value objects, invariants, domain events, `Result`/`Error`. | `Veil.Crypto` (to validate uploaded key bundles) |
| `Veil.Application` | Commands/queries and their handlers, validators, ports (repositories, security services, real-time), pipeline behaviors. | `Veil.Domain`, `Veil.Contracts`, FluentValidation |
| `Veil.Infrastructure` | Adapters: EF Core/PostgreSQL, Redis, Argon2id, JWT, TOTP, field encryption, outbox, audit chain, maintenance. | `Veil.Application` |
| `Veil.Api` | Composition root, HTTP/SignalR surface and host of the web client's static files. | everything above, `Veil.Web` |
| `Veil.Client.Sdk` | Typed API client, real-time client, `VeilMessenger` (sessions, history, receipts) and the encrypted state store contract. | `Veil.Contracts`, `Veil.Crypto` |
| `Veil.Web` | Blazor WebAssembly messenger UI. Pages and components only; all protocol logic is the SDK running in the browser. | `Veil.Client.Sdk` |
| `Veil.Client` | Terminal client over the same SDK. | `Veil.Client.Sdk` |

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

## Single-instance mode

When `ConnectionStrings:Redis` is empty the infrastructure registers in-memory implementations of the presence
tracker and the TOTP replay guard, HybridCache runs without an L2 and SignalR runs without a backplane. This is
the development default; a deployment with more than one API instance must configure Redis, otherwise presence
and replay protection are per-process and hub messages do not cross instances.

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

## Web client

`Veil.Web` is a Blazor WebAssembly application referenced by `Veil.Api`, which serves it with
`UseBlazorFrameworkFiles` + static files and a fallback route to `index.html` for every path outside
`/api`, `/hubs`, `/health`, `/alive`, `/openapi`, `/scalar` and `/.well-known`. One process, one origin: the
client calls the API with relative URLs, so CORS is not involved (`UseCors` is added only when
`Cors:AllowedOrigins` names an external client).

- **Crypto in the browser.** The client references `Veil.Client.Sdk` and therefore `Veil.Crypto`; PQXDH, the
  Double Ratchet, Ed25519 and Argon2id run in WebAssembly. `AesGcm` is not available in the browser runtime,
  so the AEAD falls back to BouncyCastle's GCM implementation when `AesGcm.IsSupported` is false. The
  BouncyCastle assembly is rooted for the trimmer.
- **Local state.** `BrowserStateStore` implements the SDK's `IClientStateStore` over `localStorage`. The state
  (identity keys, signed/one-time pre-keys, ratchet sessions, pinned identities, decrypted history, refresh
  token) is serialised and encrypted with AES-256-GCM (AAD `Veil_BrowserState_v1`) under a key derived from
  the account password with Argon2id (24 MiB, 2 iterations). The key is kept in `sessionStorage` only, so a
  reload keeps the session while a closed tab returns to the unlock screen. Sign-out can wipe the state.
- **Session.** `AppSession` is the single scoped state holder: it drives registration/login (device
  registration or device-bound login + refresh-token rotation), conversation and history state, presence,
  typing, toasts and browser notifications, and raises `Changed` so pages and components re-render. The
  SignalR connection uses the JSON protocol in the browser (`RealtimeClient(useMessagePack: false)`) and the
  access token is passed as a query parameter on hub paths only.
- **Headers.** `SecurityHeadersMiddleware` distinguishes the UI surface from the API: the UI gets a CSP that
  allows `'wasm-unsafe-eval'` for the .NET runtime, `'unsafe-inline'` styles (Blazor's error UI), same-origin
  connections including WebSockets, and no frames, objects or third-party hosts; API responses keep
  `no-store`.
- **Tests.** `tests/Veil.Web.E2ETests` starts the built API as a child process on a free port with a fresh
  `veil_e2e` database and no Redis, then drives two Chromium contexts through Playwright: register, start a
  chat, exchange messages, observe delivery ticks, compare safety numbers and survive a reload.

