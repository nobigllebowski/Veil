namespace Veil.Domain.Audit;

/// <summary>
/// Tamper-evident audit record. Each entry commits to the hash of the previous entry, forming a chain: deleting or
/// editing any row breaks verification of every row after it.
/// </summary>
public sealed class AuditEntry
{
    private AuditEntry()
    {
    }

    public AuditEntry(long sequence, DateTimeOffset occurredAt, string action, Guid? actorUserId, string? ipHash, string? detail, string previousHash, string hash)
    {
        Sequence = sequence;
        OccurredAt = occurredAt;
        Action = action;
        ActorUserId = actorUserId;
        IpHash = ipHash;
        Detail = detail;
        PreviousHash = previousHash;
        Hash = hash;
    }

    public long Sequence { get; private set; }
    public DateTimeOffset OccurredAt { get; private set; }
    public string Action { get; private set; } = null!;
    public Guid? ActorUserId { get; private set; }
    public string? IpHash { get; private set; }
    public string? Detail { get; private set; }
    public string PreviousHash { get; private set; } = null!;
    public string Hash { get; private set; } = null!;
}

public static class AuditActions
{
    public const string UserRegistered = "user.registered";
    public const string LoginSucceeded = "auth.login.succeeded";
    public const string LoginFailed = "auth.login.failed";
    public const string AccountLocked = "auth.account.locked";
    public const string TokenRefreshed = "auth.token.refreshed";
    public const string TokenReuseDetected = "auth.token.reuse_detected";
    public const string LoggedOut = "auth.logout";
    public const string PasswordChanged = "auth.password.changed";
    public const string TotpEnabled = "auth.totp.enabled";
    public const string TotpDisabled = "auth.totp.disabled";
    public const string DeviceRegistered = "device.registered";
    public const string DeviceRevoked = "device.revoked";
    public const string PreKeysUploaded = "device.prekeys.uploaded";
    public const string PreKeyBundleFetched = "keys.bundle.fetched";
    public const string ConversationCreated = "conversation.created";
    public const string MemberAdded = "conversation.member.added";
    public const string MemberRemoved = "conversation.member.removed";
}
