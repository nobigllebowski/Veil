using Veil.Domain.Common;

namespace Veil.Domain.Users;

/// <summary>An account. Holds only what the server must know: credentials, contact e-mail (encrypted at rest) and profile.</summary>
public sealed class User : AggregateRoot
{
    public const int DisplayNameMaxLength = 64;

    private User()
    {
    }

    private User(Guid id, Username username, string displayName, EmailAddress email, string emailBlindIndex, string passwordHash, DateTimeOffset now)
        : base(id)
    {
        Username = username;
        DisplayName = displayName;
        Email = email;
        EmailBlindIndex = emailBlindIndex;
        PasswordHash = passwordHash;
        CreatedAt = now;
    }

    public Username Username { get; private set; } = null!;
    public string DisplayName { get; private set; } = null!;
    public EmailAddress Email { get; private set; } = null!;

    /// <summary>Keyed HMAC of the e-mail, so uniqueness and lookups work without decrypting the column.</summary>
    public string EmailBlindIndex { get; private set; } = null!;

    public string PasswordHash { get; private set; } = null!;
    public string? TotpSecret { get; private set; }
    public bool TotpEnabled { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? LastLoginAt { get; private set; }
    public int FailedLoginAttempts { get; private set; }
    public DateTimeOffset? LockedUntil { get; private set; }

    /// <summary>Incremented on every credential change; embedded in tokens so they are invalidated when the password changes.</summary>
    public int SecurityStamp { get; private set; }

    public static Result<User> Register(Username username, string? displayName, EmailAddress email, string emailBlindIndex, string passwordHash, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(emailBlindIndex);
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordHash);

        var name = string.IsNullOrWhiteSpace(displayName) ? username.Value : displayName.Trim();
        if (name.Length > DisplayNameMaxLength)
        {
            return UserErrors.DisplayNameInvalid;
        }

        var user = new User(NewId(), username, name, email, emailBlindIndex, passwordHash, now);
        user.Raise(new UserRegistered(user.Id, now));
        return user;
    }

    public bool IsLockedOut(DateTimeOffset now) => LockedUntil is { } until && until > now;

    public void RecordSuccessfulLogin(DateTimeOffset now)
    {
        FailedLoginAttempts = 0;
        LockedUntil = null;
        LastLoginAt = now;
    }

    /// <summary>Returns true when this failure triggered a lockout.</summary>
    public bool RecordFailedLogin(DateTimeOffset now, int maxAttempts, TimeSpan lockoutDuration)
    {
        FailedLoginAttempts++;
        if (FailedLoginAttempts < maxAttempts)
        {
            return false;
        }

        FailedLoginAttempts = 0;
        LockedUntil = now + lockoutDuration;
        Raise(new UserLockedOut(Id, LockedUntil.Value, now));
        return true;
    }

    public Result UpdateDisplayName(string? displayName)
    {
        var name = displayName?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > DisplayNameMaxLength)
        {
            return UserErrors.DisplayNameInvalid;
        }

        DisplayName = name;
        return Result.Success();
    }

    public void ChangePassword(string newPasswordHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newPasswordHash);
        PasswordHash = newPasswordHash;
        SecurityStamp++;
    }

    /// <summary>Bumps the security stamp so every outstanding access token becomes invalid.</summary>
    public void InvalidateSessions() => SecurityStamp++;

    public void RehashPassword(string newPasswordHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newPasswordHash);
        PasswordHash = newPasswordHash;
    }

    public Result BeginTotpEnrollment(string encryptedSecret)
    {
        if (TotpEnabled)
        {
            return UserErrors.TotpAlreadyEnabled;
        }

        TotpSecret = encryptedSecret;
        return Result.Success();
    }

    public Result ConfirmTotpEnrollment()
    {
        if (TotpEnabled)
        {
            return UserErrors.TotpAlreadyEnabled;
        }

        if (TotpSecret is null)
        {
            return UserErrors.TotpNotPending;
        }

        TotpEnabled = true;
        SecurityStamp++;
        return Result.Success();
    }

    public Result DisableTotp()
    {
        if (!TotpEnabled)
        {
            return UserErrors.TotpNotEnabled;
        }

        TotpEnabled = false;
        TotpSecret = null;
        SecurityStamp++;
        return Result.Success();
    }
}

public sealed record UserRegistered(Guid UserId, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);

public sealed record UserLockedOut(Guid UserId, DateTimeOffset LockedUntil, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);
