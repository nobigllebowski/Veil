using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Veil.Application.Abstractions.Events;
using Veil.Domain.Common;
using Veil.Infrastructure.Options;
using Veil.Infrastructure.Persistence;
using Veil.Infrastructure.Persistence.Interceptors;

namespace Veil.Infrastructure.Outbox;

/// <summary>
/// Polls the outbox (or wakes on commit), claims a batch with <c>FOR UPDATE SKIP LOCKED</c> so several API instances
/// can run concurrently, and dispatches each event to its handlers. Delivery is at-least-once.
/// </summary>
public sealed class OutboxProcessor(
    IServiceScopeFactory scopeFactory,
    OutboxSignal signal,
    IOptions<OutboxOptions> options,
    TimeProvider time,
    ILogger<OutboxProcessor> logger) : BackgroundService
{
    private static readonly Dictionary<string, Type> EventTypes = typeof(IDomainEvent).Assembly
        .GetTypes()
        .Where(t => t is { IsAbstract: false, IsInterface: false } && typeof(IDomainEvent).IsAssignableFrom(t))
        .ToDictionary(t => t.FullName!, t => t);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Outbox processor started (poll {Interval}, batch {Batch})", options.Value.PollingInterval, options.Value.BatchSize);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var processed = await ProcessBatchAsync(stoppingToken);
                if (processed == options.Value.BatchSize)
                {
                    continue; // more work is likely waiting
                }

                await signal.WaitAsync(options.Value.PollingInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Outbox batch failed; retrying after the polling interval");
                await Task.Delay(options.Value.PollingInterval, stoppingToken);
            }
        }
    }

    internal async Task<int> ProcessBatchAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<VeilDbContext>();

        await using var transaction = await context.Database.BeginTransactionAsync(cancellationToken);
        var batch = await context.OutboxMessages
            .FromSql($"SELECT * FROM outbox_messages WHERE processed_at IS NULL ORDER BY occurred_at LIMIT {options.Value.BatchSize} FOR UPDATE SKIP LOCKED")
            .ToListAsync(cancellationToken);

        if (batch.Count == 0)
        {
            await transaction.RollbackAsync(cancellationToken);
            return 0;
        }

        foreach (var message in batch)
        {
            var now = time.GetUtcNow();
            try
            {
                await DispatchAsync(scope.ServiceProvider, message, cancellationToken);
                message.MarkProcessed(now);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Outbox message {MessageId} of type {Type} failed (attempt {Attempt})", message.Id, message.Type, message.Attempts + 1);
                message.MarkFailed(ex.ToString(), options.Value.MaxAttempts, now);
            }
        }

        await context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return batch.Count;
    }

    private static async Task DispatchAsync(IServiceProvider provider, OutboxMessage message, CancellationToken cancellationToken)
    {
        if (!EventTypes.TryGetValue(message.Type, out var eventType))
        {
            throw new InvalidOperationException($"Unknown domain event type '{message.Type}'.");
        }

        var domainEvent = JsonSerializer.Deserialize(message.Payload, eventType, OutboxInterceptor.SerializerOptions)
            ?? throw new InvalidOperationException($"Outbox payload for {message.Id} deserialised to null.");

        var handlerType = typeof(IDomainEventHandler<>).MakeGenericType(eventType);
        var handleMethod = handlerType.GetMethod(nameof(IDomainEventHandler<IDomainEvent>.HandleAsync))!;

        foreach (var handler in provider.GetServices(handlerType))
        {
            await (Task)handleMethod.Invoke(handler, [domainEvent, cancellationToken])!;
        }
    }
}
