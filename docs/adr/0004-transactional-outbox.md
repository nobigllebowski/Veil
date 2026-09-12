# ADR 0004 — Transactional outbox for domain events

**Status**: accepted

## Context

Real-time notifications must be sent only for state changes that were actually committed, and must survive
process crashes between commit and publish. Publishing directly from handlers is neither atomic nor durable.

## Decision

Aggregates raise domain events; a `SaveChangesInterceptor` writes them to `outbox_messages` in the same
transaction. A background processor claims batches with `FOR UPDATE SKIP LOCKED` (multi-instance safe),
dispatches to `IDomainEventHandler<T>` implementations and marks rows processed; failures are retried up to a
limit and then dead-lettered with the error kept for inspection. An in-process signal wakes the processor
immediately after a commit so latency stays low without aggressive polling.

## Consequences

- At-least-once delivery: handlers are idempotent (they only push "there is something to pull" hints).
- One extra insert per event and a background worker; both negligible at this scale.
- Explicit transactions conflict with EF's retrying execution strategy, so connection retries are not enabled.
