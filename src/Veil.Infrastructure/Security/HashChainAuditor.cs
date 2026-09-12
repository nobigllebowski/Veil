using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Veil.Application.Abstractions.Security;
using Veil.Domain.Audit;
using Veil.Infrastructure.Persistence;
using Veil.Infrastructure.Persistence.Interceptors;

namespace Veil.Infrastructure.Security;

/// <summary>Adds audit entries to the current unit of work; hashes are assigned at commit time by <see cref="AuditChainInterceptor"/>.</summary>
public sealed class HashChainAuditor(VeilDbContext context, IClientContext client, TimeProvider time) : IAuditor
{
    public Task RecordAsync(string action, Guid? actorUserId, object? detail, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        var json = detail is null ? null : JsonSerializer.Serialize(detail, OutboxInterceptor.SerializerOptions);
        var entry = new AuditEntry(0, TruncateToMicroseconds(time.GetUtcNow()), action, actorUserId, client.IpHash, json, AuditChainInterceptor.GenesisHash, AuditChainInterceptor.GenesisHash);
        context.AuditEntries.Add(entry);
        return Task.CompletedTask;
    }

    /// <summary>PostgreSQL stores microseconds; hashing must see exactly what will be read back.</summary>
    private static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value) =>
        new(value.Ticks - (value.Ticks % 10), value.Offset);
}

/// <summary>Walks the audit table and confirms every hash links to the previous row.</summary>
public sealed class AuditChainVerifier(IDbContextFactory<VeilDbContext> contextFactory)
{
    public async Task<AuditChainReport> VerifyAsync(CancellationToken cancellationToken)
    {
        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);
        var previous = AuditChainInterceptor.GenesisHash;
        long checkedRows = 0;

        await foreach (var entry in context.AuditEntries.AsNoTracking().OrderBy(a => a.Sequence).AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            var expected = AuditChainInterceptor.ComputeHash(previous, entry.OccurredAt, entry.Action, entry.ActorUserId, entry.IpHash, entry.Detail);
            if (entry.PreviousHash != previous || entry.Hash != expected)
            {
                return new AuditChainReport(false, checkedRows, entry.Sequence);
            }

            previous = entry.Hash;
            checkedRows++;
        }

        return new AuditChainReport(true, checkedRows, null);
    }
}

public sealed record AuditChainReport(bool IsIntact, long CheckedRows, long? FirstBrokenSequence);
