# ADR 0002 — Own CQRS dispatcher instead of MediatR

**Status**: accepted

## Context

The application layer needs a way to route commands/queries to handlers and wrap them with cross-cutting
behaviours (validation, logging). MediatR is the common choice, but it moved to a commercial licence for many
uses and pulls in more than this project needs.

## Decision

Implement `ISender` in ~60 lines: handlers are resolved from DI by request type, `IPipelineBehavior`s are
composed in registration order, wrappers are cached per request type. FluentValidation provides validators;
`ValidationBehavior` converts failures into typed `Result` errors instead of exceptions.

## Consequences

- Zero licensing questions and no reflection-heavy startup scanning beyond a single assembly scan.
- Behaviours must return `Result`/`Result<T>`; the `ResultFactory` builds the right failure shape.
- No notifications/streams; domain events use the outbox instead, which is the better fit for a server.
