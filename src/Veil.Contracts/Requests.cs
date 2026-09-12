namespace Veil.Contracts;

public sealed record RegisterRequest(string Username, string Email, string Password, string? DisplayName);

public sealed record LoginRequest(string Username, string Password, string? TotpCode, Guid? DeviceId);

public sealed record RefreshRequest(string RefreshToken);

public sealed record LogoutRequest(string? RefreshToken);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record ConfirmTotpRequest(string Code);

public sealed record DisableTotpRequest(string Password, string Code);

public sealed record UpdateProfileRequest(string DisplayName);

public sealed record OneTimePreKeyUpload(uint KeyId, byte[] PublicKey);

public sealed record RegisterDeviceRequest(
    string Name,
    IdentityKeysDto Identity,
    uint SignedPreKeyId,
    byte[] SignedPreKey,
    byte[] SignedPreKeySignature,
    uint KemPreKeyId,
    byte[] KemPreKey,
    byte[] KemPreKeySignature,
    IReadOnlyList<OneTimePreKeyUpload> OneTimePreKeys);

public sealed record UploadOneTimePreKeysRequest(IReadOnlyList<OneTimePreKeyUpload> Keys);

public sealed record RotatePreKeyRequest(uint KeyId, byte[] PublicKey, byte[] Signature);

public sealed record CreateDirectConversationRequest(Guid OtherUserId);

public sealed record CreateGroupConversationRequest(string Title, IReadOnlyList<Guid> MemberIds);

public sealed record AddMemberRequest(Guid UserId);

public sealed record OutgoingEnvelope(Guid RecipientUserId, Guid RecipientDeviceId, byte[] Payload);

public sealed record SendEnvelopesRequest(Guid ConversationId, IReadOnlyList<OutgoingEnvelope> Envelopes);

public sealed record AcknowledgeRequest(IReadOnlyList<Guid> EnvelopeIds);
