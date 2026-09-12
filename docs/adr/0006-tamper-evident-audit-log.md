# ADR 0006 — Tamper-evident audit log

**Status**: accepted

## Context

Security-relevant events (logins, lockouts, token reuse, device changes, key fetches) must be recorded in a way
that later edits or deletions are detectable, even by someone with database write access.

## Decision

Each `audit_entries` row stores `previous_hash` and `hash = SHA-256(previous_hash ‖ occurred_at ‖ action ‖
actor ‖ ip_hash ‖ detail)`. Rows are linked at commit time by an interceptor that serialises writers with a
transaction-scoped PostgreSQL advisory lock, so concurrent commits cannot fork the chain. `detail` is `text`
and timestamps are truncated to microseconds so the hashed bytes equal the stored bytes. A verifier walks the
chain and reports the first inconsistent row.

## Consequences

- Audit writes are serialised (one short critical section per commit); acceptable for the volume involved.
- Deleting the tail of the log is not detectable by the chain alone; anchor the latest hash externally for that.
