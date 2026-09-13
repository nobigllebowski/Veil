# ADR 0007 — Blazor WebAssembly client hosted by the API

**Status**: accepted

## Context

Veil needed a user-facing client beyond the terminal. The hard constraint is end-to-end encryption: the server
must never see plaintext or private keys, so the client must run the protocol (PQXDH, Double Ratchet) itself.
The existing `Veil.Crypto` and `Veil.Client.Sdk` are pure C#; reimplementing them in TypeScript would create a
second implementation to keep in sync and to audit.

## Decision

The web client is a **Blazor WebAssembly** application (`Veil.Web`) that reuses `Veil.Client.Sdk` and
`Veil.Crypto` unchanged in the browser. `Veil.Api` references it and serves it as static files from the same
origin with a fallback route to `index.html`; API routes, hubs and health endpoints are excluded from the
fallback. Local state is encrypted in `localStorage` under an Argon2id-derived key that lives in
`sessionStorage`. `AesGcm` is unavailable in the browser runtime, so the AEAD uses BouncyCastle's GCM there.

## Consequences

- One protocol implementation, one set of known-answer tests, one audit surface.
- One deployable unit and one origin: no CORS, cookies or token exchange across hosts; the CSP can stay strict
  (`'self'` plus `'wasm-unsafe-eval'`).
- The first load downloads the .NET runtime (a few MB, cached and Brotli-compressed on publish); acceptable for
  a messenger that is kept open. Argon2id in WebAssembly is slower than native, so the browser profile uses
  24 MiB / 2 iterations instead of the server's 64 MiB / 3.
- Browser storage is not a secure enclave: an XSS would expose the unlocked state, which is why the CSP forbids
  inline and third-party scripts, and why the derived key is not persisted beyond the tab.
- The user journey is covered by a Playwright test that drives the real client against the real API.
