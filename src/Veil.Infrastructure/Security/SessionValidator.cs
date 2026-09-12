using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Hybrid;
using Veil.Application.Abstractions.Security;
using Veil.Infrastructure.Persistence;

namespace Veil.Infrastructure.Security;

/// <summary>
/// Per-request checks that a bearer token is still honoured: the user's security stamp must match the token and
/// the device it is bound to must not be revoked. Cached briefly and invalidated eagerly, so revocation is
/// immediate on the node that performed it and at most a few seconds late elsewhere.
/// </summary>
public interface ISessionValidator : ISessionCache
{
    Task<bool> IsStampCurrentAsync(Guid userId, int stamp, CancellationToken cancellationToken);
    Task<bool> IsDeviceActiveAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken);
}

public sealed class SessionValidator(HybridCache cache, IDbContextFactory<VeilDbContext> contextFactory) : ISessionValidator
{
    private static readonly HybridCacheEntryOptions Entry = new()
    {
        Expiration = TimeSpan.FromSeconds(30),
        LocalCacheExpiration = TimeSpan.FromSeconds(5),
    };

    public async Task<bool> IsStampCurrentAsync(Guid userId, int stamp, CancellationToken cancellationToken)
    {
        var current = await cache.GetOrCreateAsync(
            StampKey(userId),
            userId,
            async (id, ct) =>
            {
                await using var context = await contextFactory.CreateDbContextAsync(ct);
                return await context.Users.AsNoTracking().Where(u => u.Id == id).Select(u => (int?)u.SecurityStamp).FirstOrDefaultAsync(ct) ?? -1;
            },
            Entry,
            cancellationToken: cancellationToken);

        return current == stamp;
    }

    public async Task<bool> IsDeviceActiveAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken)
    {
        var owner = await cache.GetOrCreateAsync(
            DeviceKey(deviceId),
            deviceId,
            async (id, ct) =>
            {
                await using var context = await contextFactory.CreateDbContextAsync(ct);
                return await context.Devices.AsNoTracking().Where(d => d.Id == id && d.RevokedAt == null).Select(d => (Guid?)d.UserId).FirstOrDefaultAsync(ct) ?? Guid.Empty;
            },
            Entry,
            cancellationToken: cancellationToken);

        return owner == userId;
    }

    public Task InvalidateUserAsync(Guid userId, CancellationToken cancellationToken) => cache.RemoveAsync(StampKey(userId), cancellationToken).AsTask();

    public Task InvalidateDeviceAsync(Guid deviceId, CancellationToken cancellationToken) => cache.RemoveAsync(DeviceKey(deviceId), cancellationToken).AsTask();

    private static string StampKey(Guid userId) => $"session:stamp:{userId:N}";

    private static string DeviceKey(Guid deviceId) => $"session:device:{deviceId:N}";
}
