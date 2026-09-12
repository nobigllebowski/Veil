using Veil.Domain.Common;

namespace Veil.Application.Abstractions.Events;

/// <summary>Reacts to a domain event delivered through the transactional outbox (at-least-once; must be idempotent).</summary>
public interface IDomainEventHandler<in TEvent> where TEvent : IDomainEvent
{
    Task HandleAsync(TEvent domainEvent, CancellationToken cancellationToken);
}
