using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Veil.Infrastructure.Persistence;

namespace Veil.Infrastructure.Maintenance;

/// <summary>Data-minimisation worker: purges expired ciphertext, dead refresh tokens and processed outbox rows.</summary>
public sealed class MaintenanceService(IServiceScopeFactory scopeFactory, TimeProvider time, ILogger<MaintenanceService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan TokenGrace = TimeSpan.FromDays(7);
    private static readonly TimeSpan OutboxRetention = TimeSpan.FromDays(7);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken);
                await timer.WaitForNextTickAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Maintenance run failed");
            }
        }
    }

    internal async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<VeilDbContext>();
        var now = time.GetUtcNow();

        var envelopes = await context.MessageEnvelopes.Where(e => e.ExpiresAt < now).ExecuteDeleteAsync(cancellationToken);
        var tokens = await context.RefreshTokens.Where(t => t.ExpiresAt < now - TokenGrace || (t.RevokedAt != null && t.RevokedAt < now - TokenGrace)).ExecuteDeleteAsync(cancellationToken);
        var outbox = await context.OutboxMessages.Where(o => o.ProcessedAt != null && o.ProcessedAt < now - OutboxRetention && o.LastError == null).ExecuteDeleteAsync(cancellationToken);

        if (envelopes + tokens + outbox > 0)
        {
            logger.LogInformation("Maintenance purged {Envelopes} envelopes, {Tokens} refresh tokens, {Outbox} outbox rows", envelopes, tokens, outbox);
        }
    }
}
