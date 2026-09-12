using Veil.Domain.Users;

namespace Veil.Application.Abstractions.Security;

public enum PasswordVerification
{
    Failed = 0,
    Success = 1,
    SuccessRehashNeeded = 2,
}

/// <summary>Memory-hard password hashing (Argon2id). Verification is constant-time.</summary>
public interface IPasswordHasher
{
    string Hash(string password);
    PasswordVerification Verify(string password, string hash);

    /// <summary>Performs a full verification against a dummy hash so "unknown user" and "wrong password" take the same time.</summary>
    void MitigateTiming(string password);
}

public sealed record AccessToken(string Token, DateTimeOffset ExpiresAt);

/// <summary>Issues short-lived signed access tokens bound to a user (and optionally a device).</summary>
public interface IAccessTokenIssuer
{
    AccessToken Issue(User user, Guid? deviceId);
}

/// <summary>Generates high-entropy opaque refresh tokens and their storage hashes.</summary>
public interface IRefreshTokenGenerator
{
    (string Token, string Hash) Generate();
    string Hash(string token);
}

/// <summary>Time-based one-time passwords (RFC 6238) for optional second-factor authentication.</summary>
public interface ITotpProvider
{
    string GenerateSecret();
    string BuildOtpAuthUri(string issuer, string account, string secret);

    /// <summary>Verifies a code and guarantees each time-step is accepted at most once per user (replay protection).</summary>
    Task<bool> VerifyAsync(Guid userId, string secret, string code, CancellationToken cancellationToken);
}

/// <summary>
/// Drops cached session facts so that a security-stamp change (password change, global logout) or a device
/// revocation is enforced on the very next request instead of when the access token expires.
/// </summary>
public interface ISessionCache
{
    Task InvalidateUserAsync(Guid userId, CancellationToken cancellationToken);
    Task InvalidateDeviceAsync(Guid deviceId, CancellationToken cancellationToken);
}

/// <summary>Keyed hash used to index encrypted columns without revealing their content.</summary>
public interface IBlindIndexer
{
    string Compute(string normalizedValue);
}

/// <summary>Appends an entry to the tamper-evident audit log within the current unit of work.</summary>
public interface IAuditor
{
    Task RecordAsync(string action, Guid? actorUserId, object? detail, CancellationToken cancellationToken);
}

/// <summary>Request-scoped facts about the caller's transport.</summary>
public interface IClientContext
{
    string? IpAddress { get; }
    string? IpHash { get; }
    string? UserAgent { get; }
}

/// <summary>Identity established by the authentication layer for the current request.</summary>
public interface ICurrentUser
{
    bool IsAuthenticated { get; }
    Guid UserId { get; }
    Guid? DeviceId { get; }
}

public static class CurrentUserExtensions
{
    public static Guid RequireDeviceId(this ICurrentUser user) =>
        user.DeviceId ?? throw new InvalidOperationException("A device-bound session is required.");
}
