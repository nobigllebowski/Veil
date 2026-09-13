namespace Veil.Contracts;

public sealed record UserProfile(Guid Id, string Username, string DisplayName, DateTimeOffset CreatedAt, bool TotpEnabled);

public sealed record PublicUser(Guid Id, string Username, string DisplayName);

public sealed record TokenPair(string AccessToken, DateTimeOffset AccessTokenExpiresAt, string RefreshToken, DateTimeOffset RefreshTokenExpiresAt, Guid? DeviceId);

public sealed record DeviceSummary(Guid Id, string Name, DateTimeOffset CreatedAt, DateTimeOffset LastActiveAt, bool IsCurrent, int OneTimePreKeysRemaining);

public sealed record DeviceRegistration(Guid DeviceId, TokenPair Tokens);

public sealed record IdentityKeysDto(byte[] SigningKey, byte[] DhKey, byte[] DhKeySignature);

public sealed record PreKeyBundleDto(
    Guid UserId,
    Guid DeviceId,
    IdentityKeysDto Identity,
    uint SignedPreKeyId,
    byte[] SignedPreKey,
    byte[] SignedPreKeySignature,
    uint KemPreKeyId,
    byte[] KemPreKey,
    byte[] KemPreKeySignature,
    uint? OneTimePreKeyId,
    byte[]? OneTimePreKey);

public sealed record MemberDto(Guid UserId, string Username, string DisplayName, string Role, IReadOnlyList<Guid> DeviceIds);

public sealed record ConversationSummary(Guid Id, string Type, string? Title, DateTimeOffset CreatedAt, IReadOnlyList<MemberDto> Members);

public sealed record PendingEnvelopeDto(Guid Id, Guid ConversationId, Guid SenderUserId, Guid SenderDeviceId, byte[] Payload, DateTimeOffset SentAt);

public sealed record TotpEnrollment(string Secret, string OtpAuthUri);

public sealed record SendReceipt(int Stored, IReadOnlyList<Guid> EnvelopeIds);

public sealed record DeviceSetMismatch(Guid UserId, IReadOnlyList<Guid> MissingDeviceIds, IReadOnlyList<Guid> StaleDeviceIds);

public sealed record CountResponse(int Count);

public sealed record PresenceResponse(IReadOnlyList<Guid> OnlineUserIds);

/// <summary>RFC 9457 problem details as emitted by the API, including Veil's <c>code</c> extension.</summary>
public sealed record ApiProblem(
    string? Type,
    string? Title,
    int? Status,
    string? Detail,
    string? Instance,
    string? Code,
    string? TraceId,
    IReadOnlyDictionary<string, string[]>? Errors,
    IReadOnlyList<DeviceSetMismatch>? Mismatches);

/// <summary>Real-time notifications pushed over the <c>/hubs/chat</c> SignalR hub.</summary>
public sealed record EnvelopeAvailableNotification(Guid EnvelopeId, Guid ConversationId, Guid SenderUserId, DateTimeOffset SentAt);

public sealed record ConversationChangedNotification(Guid ConversationId, string Change, Guid? UserId);

public sealed record TypingNotification(Guid ConversationId, Guid UserId);

public sealed record PresenceNotification(Guid UserId, bool IsOnline);
