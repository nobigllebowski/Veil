using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Veil.Domain.Audit;

namespace Veil.Infrastructure.Persistence.Interceptors;

/// <summary>
/// Links new audit entries into the hash chain. Writers are serialised with a transaction-scoped advisory lock so
/// two concurrent commits can never fork the chain. If no transaction is open the interceptor opens one around
/// SaveChanges so the lock is held until the entries are committed.
/// </summary>
internal sealed class AuditChainInterceptor : SaveChangesInterceptor
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private const long AdvisoryLockKey = 0x5645494C_41554449; // "VEIL" "AUDI"

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is VeilDbContext context)
        {
            await ChainAsync(context, cancellationToken);
        }

        return await base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        if (eventData.Context is VeilDbContext context && HasPendingEntries(context))
        {
            throw new InvalidOperationException("Audit entries must be saved with SaveChangesAsync.");
        }

        return base.SavingChanges(eventData, result);
    }

    public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is VeilDbContext { OwnedAuditTransaction: { } transaction } context)
        {
            context.OwnedAuditTransaction = null;
            await transaction.CommitAsync(cancellationToken);
            await transaction.DisposeAsync();
        }

        return await base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    public override async Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is VeilDbContext { OwnedAuditTransaction: { } transaction } context)
        {
            context.OwnedAuditTransaction = null;
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
        }

        await base.SaveChangesFailedAsync(eventData, cancellationToken);
    }

    public static string ComputeHash(string previousHash, DateTimeOffset occurredAt, string action, Guid? actorUserId, string? ipHash, string? detail)
    {
        var canonical = string.Join('\n',
            previousHash,
            occurredAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            action,
            actorUserId?.ToString("D") ?? string.Empty,
            ipHash ?? string.Empty,
            detail ?? string.Empty);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static bool HasPendingEntries(VeilDbContext context) =>
        context.ChangeTracker.Entries<AuditEntry>().Any(e => e.State == EntityState.Added);

    private static async Task ChainAsync(VeilDbContext context, CancellationToken cancellationToken)
    {
        var pending = context.ChangeTracker.Entries<AuditEntry>()
            .Where(e => e.State == EntityState.Added)
            .Select(e => e.Entity)
            .OrderBy(e => e.OccurredAt)
            .ToList();

        if (pending.Count == 0)
        {
            return;
        }

        if (context.Database.CurrentTransaction is null)
        {
            context.OwnedAuditTransaction = await context.Database.BeginTransactionAsync(cancellationToken);
        }

        await context.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({AdvisoryLockKey})", cancellationToken);

        var previous = await context.AuditEntries
            .AsNoTracking()
            .OrderByDescending(a => a.Sequence)
            .Select(a => a.Hash)
            .FirstOrDefaultAsync(cancellationToken) ?? GenesisHash;

        foreach (var entry in pending)
        {
            var hash = ComputeHash(previous, entry.OccurredAt, entry.Action, entry.ActorUserId, entry.IpHash, entry.Detail);
            context.Entry(entry).Property(e => e.PreviousHash).CurrentValue = previous;
            context.Entry(entry).Property(e => e.Hash).CurrentValue = hash;
            previous = hash;
        }
    }
}
