using System.Collections.Concurrent;
using System.Globalization;
using StackExchange.Redis;

namespace Veil.Infrastructure.Security;

/// <summary>Records which TOTP time-steps a user has already consumed so an observed code cannot be replayed.</summary>
public interface ITotpReplayGuard
{
    /// <returns><c>true</c> if the step was not used before and is now marked as used.</returns>
    Task<bool> TryConsumeAsync(Guid userId, long timeStep, TimeSpan retention, CancellationToken cancellationToken);
}

/// <summary>Multi-instance guard: an atomic <c>SET NX EX</c> in Redis.</summary>
public sealed class RedisTotpReplayGuard(IConnectionMultiplexer redis) : ITotpReplayGuard
{
    public Task<bool> TryConsumeAsync(Guid userId, long timeStep, TimeSpan retention, CancellationToken cancellationToken) =>
        redis.GetDatabase().StringSetAsync($"totp:used:{userId:N}:{timeStep.ToString(CultureInfo.InvariantCulture)}", "1", retention, When.NotExists);
}

/// <summary>Single-instance guard for development and tests: an in-process table with lazy expiry.</summary>
public sealed class InMemoryTotpReplayGuard(TimeProvider time) : ITotpReplayGuard
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);

    public Task<bool> TryConsumeAsync(Guid userId, long timeStep, TimeSpan retention, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        foreach (var (key, expires) in _used)
        {
            if (expires <= now)
            {
                _used.TryRemove(key, out _);
            }
        }

        return Task.FromResult(_used.TryAdd($"{userId:N}:{timeStep.ToString(CultureInfo.InvariantCulture)}", now + retention));
    }
}
