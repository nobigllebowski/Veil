using StackExchange.Redis;
using Veil.Application.Abstractions.Realtime;

namespace Veil.Infrastructure.Realtime;

/// <summary>Presence backed by per-user Redis sets of connection ids with a TTL refreshed by client heartbeats.</summary>
public sealed class RedisPresenceService(IConnectionMultiplexer redis) : IPresenceService, IPresenceTracker
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(3);

    public async Task<IReadOnlySet<Guid>> GetOnlineUsersAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken)
    {
        if (userIds.Count == 0)
        {
            return new HashSet<Guid>();
        }

        var database = redis.GetDatabase();
        var ids = userIds.Distinct().ToArray();
        var checks = ids.Select(id => database.KeyExistsAsync(Key(id))).ToArray();
        var results = await Task.WhenAll(checks);
        return ids.Where((_, i) => results[i]).ToHashSet();
    }

    public async Task ConnectedAsync(Guid userId, string connectionId, CancellationToken cancellationToken)
    {
        var database = redis.GetDatabase();
        var key = Key(userId);
        await database.SetAddAsync(key, connectionId);
        await database.KeyExpireAsync(key, Ttl);
    }

    public Task HeartbeatAsync(Guid userId, CancellationToken cancellationToken) =>
        redis.GetDatabase().KeyExpireAsync(Key(userId), Ttl);

    public async Task DisconnectedAsync(Guid userId, string connectionId, CancellationToken cancellationToken)
    {
        var database = redis.GetDatabase();
        var key = Key(userId);
        await database.SetRemoveAsync(key, connectionId);
        if (await database.SetLengthAsync(key) == 0)
        {
            await database.KeyDeleteAsync(key);
        }
    }

    private static RedisKey Key(Guid userId) => $"presence:user:{userId:N}";
}

/// <summary>Write side of presence, driven by the real-time hub.</summary>
public interface IPresenceTracker
{
    Task ConnectedAsync(Guid userId, string connectionId, CancellationToken cancellationToken);
    Task HeartbeatAsync(Guid userId, CancellationToken cancellationToken);
    Task DisconnectedAsync(Guid userId, string connectionId, CancellationToken cancellationToken);
}
