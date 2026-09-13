using System.Text.Json;
using System.Text.Json.Serialization;
using Veil.Crypto.Keys;
using Veil.Crypto.Protocol;

namespace Veil.Client.Sdk;

/// <summary>
/// Everything a device needs across restarts: identity and pre-keys, per-peer ratchet sessions, pinned peer
/// identities and the refresh token. Always persisted through an encrypting <see cref="IClientStateStore"/>.
/// </summary>
public sealed class ClientState
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    public int Version { get; set; } = 1;
    public string ServerUrl { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public Guid? DeviceId { get; set; }
    public string? DeviceName { get; set; }
    public string? RefreshToken { get; set; }
    public DeviceKeyStoreState? Keys { get; set; }

    /// <summary>Ratchet sessions keyed by "userId:deviceId".</summary>
    public Dictionary<string, PeerSessionState> Sessions { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Trust-on-first-use pins: identity fingerprint (hex) per remote device.</summary>
    public Dictionary<string, string> PinnedIdentities { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Decrypted conversation history keyed by conversation id. The server never keeps delivered ciphertext, so this is the only copy.</summary>
    public Dictionary<string, List<StoredMessage>> History { get; set; } = new(StringComparer.Ordinal);

    /// <summary>When the user last opened each conversation; drives unread counters.</summary>
    public Dictionary<string, DateTimeOffset> LastRead { get; set; } = new(StringComparer.Ordinal);

    public static string PeerKey(Guid userId, Guid deviceId) => $"{userId:N}:{deviceId:N}";

    public byte[] Serialize() => JsonSerializer.SerializeToUtf8Bytes(this, Json);

    public static ClientState Deserialize(ReadOnlySpan<byte> json) =>
        JsonSerializer.Deserialize<ClientState>(json, Json) ?? throw new InvalidOperationException("Client state is empty.");
}

public enum MessageStatus
{
    /// <summary>Accepted by the server, not yet confirmed by any recipient device.</summary>
    Sent = 1,

    /// <summary>At least one recipient device decrypted it and sent a receipt.</summary>
    Delivered = 2,

    /// <summary>Received from a peer.</summary>
    Received = 3,
}

/// <summary>One decrypted message in local history.</summary>
public sealed class StoredMessage
{
    public Guid Id { get; set; }
    public Guid ConversationId { get; set; }
    public Guid SenderUserId { get; set; }
    public string Body { get; set; } = string.Empty;
    public DateTimeOffset SentAt { get; set; }
    public bool Outgoing { get; set; }
    public MessageStatus Status { get; set; }
    public int DeliveredDevices { get; set; }
}

/// <summary>Persistence port for <see cref="ClientState"/>. Implementations must encrypt at rest.</summary>
public interface IClientStateStore
{
    Task<ClientState?> LoadAsync(CancellationToken cancellationToken = default);
    Task SaveAsync(ClientState state, CancellationToken cancellationToken = default);
}

/// <summary>Non-persistent store for tests and throw-away sessions.</summary>
public sealed class InMemoryClientStateStore : IClientStateStore
{
    private byte[]? _blob;

    public Task<ClientState?> LoadAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_blob is null ? null : ClientState.Deserialize(_blob));

    public Task SaveAsync(ClientState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        _blob = state.Serialize();
        return Task.CompletedTask;
    }
}
