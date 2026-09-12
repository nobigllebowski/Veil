using Veil.Domain.Common;

namespace Veil.Domain.Auth;

/// <summary>
/// Opaque refresh token stored as a SHA-256 hash. Tokens rotate on every use and belong to a family; presenting an
/// already-used token is treated as theft and revokes the entire family.
/// </summary>
public sealed class RefreshToken : Entity
{
    private RefreshToken()
    {
    }

    private RefreshToken(Guid id, Guid userId, Guid? deviceId, string tokenHash, Guid familyId, DateTimeOffset now, DateTimeOffset expiresAt, string? ipHash)
        : base(id)
    {
        UserId = userId;
        DeviceId = deviceId;
        TokenHash = tokenHash;
        FamilyId = familyId;
        CreatedAt = now;
        ExpiresAt = expiresAt;
        CreatedFromIpHash = ipHash;
    }

    public Guid UserId { get; private set; }
    public Guid? DeviceId { get; private set; }
    public string TokenHash { get; private set; } = null!;
    public Guid FamilyId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? UsedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public string? CreatedFromIpHash { get; private set; }

    public bool IsExpired(DateTimeOffset now) => ExpiresAt <= now;
    public bool IsUsed => UsedAt is not null;
    public bool IsRevoked => RevokedAt is not null;
    public bool IsActive(DateTimeOffset now) => !IsUsed && !IsRevoked && !IsExpired(now);

    public static RefreshToken Issue(Guid userId, Guid? deviceId, string tokenHash, Guid familyId, DateTimeOffset now, TimeSpan lifetime, string? ipHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);
        return new RefreshToken(NewId(), userId, deviceId, tokenHash, familyId, now, now + lifetime, ipHash);
    }

    public void MarkUsed(DateTimeOffset now) => UsedAt ??= now;

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
}

public static class AuthErrors
{
    public static readonly Error InvalidCredentials = Error.Unauthorized("auth.invalid_credentials", "Invalid username or password.");
    public static readonly Error AccountLocked = Error.Unauthorized("auth.account_locked", "Account is temporarily locked after too many failed attempts.");
    public static readonly Error TotpRequired = Error.Unauthorized("auth.totp_required", "A two-factor code is required.");
    public static readonly Error TotpInvalid = Error.Unauthorized("auth.totp_invalid", "The two-factor code is invalid.");
    public static readonly Error InvalidRefreshToken = Error.Unauthorized("auth.invalid_refresh_token", "The refresh token is invalid or expired.");
    public static readonly Error RefreshTokenReuse = Error.Unauthorized("auth.refresh_token_reuse", "Refresh token reuse detected; all sessions in this family were revoked.");
    public static readonly Error PasswordTooWeak = Error.Validation("auth.password_too_weak", "Password must be 12-128 characters and not a commonly used password.");
    public static readonly Error DeviceRequired = Error.Forbidden("auth.device_required", "This operation requires a device-bound session.");
}
