using System.Collections.Concurrent;
using Veil.Application.Abstractions.Realtime;

namespace Veil.Infrastructure.Realtime;

/// <summary>Presence for single-instance deployments (no Redis): connection ids per user with a heartbeat deadline.</summary>
public sealed class InMemoryPresenceService(TimeProvider time) : IPresenceService, IPresenceTracker
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(3);
    private readonly ConcurrentDictionary<Guid, Entry> _users = new();

    public Task<IReadOnlySet<Guid>> GetOnlineUsersAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        IReadOnlySet<Guid> online = userIds.Where(id => _users.TryGetValue(id, out var entry) && entry.IsOnline(now)).ToHashSet();
        return Task.FromResult(online);
    }

    public Task ConnectedAsync(Guid userId, string connectionId, CancellationToken cancellationToken)
    {
        var entry = _users.GetOrAdd(userId, _ => new Entry());
        entry.Add(connectionId, time.GetUtcNow() + Ttl);
        return Task.CompletedTask;
    }

    public Task HeartbeatAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (_users.TryGetValue(userId, out var entry))
        {
            entry.Touch(time.GetUtcNow() + Ttl);
        }

        return Task.CompletedTask;
    }

    public Task DisconnectedAsync(Guid userId, string connectionId, CancellationToken cancellationToken)
    {
        if (_users.TryGetValue(userId, out var entry) && entry.Remove(connectionId))
        {
            _users.TryRemove(userId, out _);
        }

        return Task.CompletedTask;
    }

    private sealed class Entry
    {
        private readonly HashSet<string> _connections = new(StringComparer.Ordinal);
        private readonly Lock _lock = new();
        private DateTimeOffset _deadline;

        public void Add(string connectionId, DateTimeOffset deadline)
        {
            lock (_lock)
            {
                _connections.Add(connectionId);
                _deadline = deadline;
            }
        }

        public void Touch(DateTimeOffset deadline)
        {
            lock (_lock)
            {
                _deadline = deadline;
            }
        }

        /// <returns><c>true</c> when no connections remain.</returns>
        public bool Remove(string connectionId)
        {
            lock (_lock)
            {
                _connections.Remove(connectionId);
                return _connections.Count == 0;
            }
        }

        public bool IsOnline(DateTimeOffset now)
        {
            lock (_lock)
            {
                return _connections.Count > 0 && _deadline > now;
            }
        }
    }
}
