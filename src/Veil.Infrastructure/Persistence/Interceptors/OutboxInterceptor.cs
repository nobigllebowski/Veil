using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Veil.Domain.Common;
using Veil.Infrastructure.Outbox;

namespace Veil.Infrastructure.Persistence.Interceptors;

/// <summary>
/// Converts the domain events raised by tracked aggregates into outbox rows inside the same transaction, so an
/// event is published if and only if the state change that produced it was committed.
/// </summary>
internal sealed class OutboxInterceptor(OutboxSignal signal) : SaveChangesInterceptor
{
    public static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is VeilDbContext context)
        {
            context.OutboxRowsPending = Enqueue(context);
        }

        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        if (eventData.Context is VeilDbContext context)
        {
            context.OutboxRowsPending = Enqueue(context);
        }

        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is VeilDbContext { OutboxRowsPending: true } context)
        {
            context.OutboxRowsPending = false;
            signal.Notify();
        }

        return base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    private static bool Enqueue(VeilDbContext context)
    {
        var aggregates = context.ChangeTracker.Entries<AggregateRoot>()
            .Where(e => e.Entity.DomainEvents.Count > 0)
            .Select(e => e.Entity)
            .ToList();

        if (aggregates.Count == 0)
        {
            return false;
        }

        var messages = aggregates
            .SelectMany(a => a.DomainEvents)
            .Select(e => new OutboxMessage(e.EventId, e.GetType().FullName!, JsonSerializer.Serialize(e, e.GetType(), SerializerOptions), e.OccurredAt))
            .ToList();

        foreach (var aggregate in aggregates)
        {
            aggregate.ClearDomainEvents();
        }

        context.OutboxMessages.AddRange(messages);
        return true;
    }
}

/// <summary>Lets the in-process outbox worker wake up immediately after a commit instead of waiting for the next poll.</summary>
public sealed class OutboxSignal : IDisposable
{
    private readonly SemaphoreSlim _semaphore = new(0, 1);

    public void Dispose() => _semaphore.Dispose();

    public void Notify()
    {
        if (_semaphore.CurrentCount == 0)
        {
            try
            {
                _semaphore.Release();
            }
            catch (SemaphoreFullException)
            {
                // Already signalled.
            }
        }
    }

    public Task WaitAsync(TimeSpan timeout, CancellationToken cancellationToken) => _semaphore.WaitAsync(timeout, cancellationToken);
}
