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

    public static string PeerKey(Guid userId, Guid deviceId) => $"{userId:N}:{deviceId:N}";

    public byte[] Serialize() => JsonSerializer.SerializeToUtf8Bytes(this, Json);

    public static ClientState Deserialize(ReadOnlySpan<byte> json) =>
        JsonSerializer.Deserialize<ClientState>(json, Json) ?? throw new InvalidOperationException("Client state is empty.");
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
