using System.Text.Json;
using Veil.Contracts;
using Veil.Crypto;
using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;
using Veil.Crypto.Protocol;

namespace Veil.Client.Sdk;

/// <summary>Plaintext structure carried inside every envelope. Binding the conversation id prevents the server from re-routing ciphertext.</summary>
public sealed record ChatMessage(string Type, Guid ConversationId, string Body, DateTimeOffset SentAt)
{
    public const string TextType = "text";
}

public sealed record IncomingMessage(Guid EnvelopeId, Guid ConversationId, Guid SenderUserId, Guid SenderDeviceId, ChatMessage Message, DateTimeOffset ReceivedAt);

public sealed record IdentityChange(Guid UserId, Guid DeviceId, string PreviousFingerprint, string NewFingerprint);

/// <summary>
/// End-to-end encryption session manager for one device. Owns the private keys, establishes PQXDH sessions
/// from pre-key bundles, fans out ciphertext to every device in a conversation and decrypts incoming envelopes.
/// The server only ever sees what this class hands to <see cref="VeilApiClient"/>.
/// </summary>
public sealed class VeilMessenger : IDisposable
{
    private const int OneTimePreKeyLowWatermark = 20;
    private const int OneTimePreKeyBatch = 50;

    private readonly VeilApiClient _api;
    private readonly ClientState _state;
    private readonly IClientStateStore _store;
    private readonly Dictionary<string, PeerSession> _sessions = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DeviceKeyStore? _keys;

    public VeilMessenger(VeilApiClient api, ClientState state, IClientStateStore store)
    {
        _api = api;
        _state = state;
        _store = store;

        if (state.Keys is not null)
        {
            _keys = DeviceKeyStore.Import(state.Keys);
        }

        if (state.RefreshToken is not null)
        {
            api.UseRefreshToken(state.RefreshToken, state.DeviceId);
        }

        api.TokensChanged += tokens =>
        {
            _state.RefreshToken = tokens.RefreshToken;
            _state.DeviceId ??= tokens.DeviceId;
        };
    }

    /// <summary>Policy for a peer device whose identity key changed since it was pinned.</summary>
    public bool RejectChangedIdentities { get; set; }

    public event Action<IdentityChange>? IdentityChanged;

    public ClientState State => _state;
    public bool HasDevice => _state.DeviceId is not null && _keys is not null;
    public IdentityPublicKeys? Identity => _keys?.Identity.Public;

    /// <summary>Generates fresh key material, publishes it and binds the session to the new device.</summary>
    public async Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (HasDevice)
            {
                throw new InvalidOperationException("This client already has a registered device.");
            }

            var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: OneTimePreKeyBatch * 2);
            var oneTime = keys.Export().OneTimePreKeys.Select(k => new OneTimePreKeyUpload(k.Id, X25519.DerivePublicKey(k.PrivateKey))).ToList();
            var registration = await _api.RegisterDeviceAsync(deviceName, keys.ExportPublicKeys(), oneTime, ct);

            _keys = keys;
            _state.Keys = keys.Export();
            _state.DeviceId = registration.DeviceId;
            _state.DeviceName = deviceName;
            _state.RefreshToken = registration.Tokens.RefreshToken;
            await PersistAsync(ct);
            return registration;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Encrypts <paramref name="text"/> separately for every device of every member and sends the batch.</summary>
    public async Task<SendReceipt> SendTextAsync(Guid conversationId, string text, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        await _gate.WaitAsync(ct);
        try
        {
            RequireDevice();
            var message = new ChatMessage(ChatMessage.TextType, conversationId, text, DateTimeOffset.UtcNow);
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(message, ClientState.Json);

            var conversation = await _api.GetConversationAsync(conversationId, ct);
            var envelopes = await EncryptForConversationAsync(conversation, plaintext, ct);

            try
            {
                var receipt = await _api.SendEnvelopesAsync(conversationId, envelopes, ct);
                await PersistAsync(ct);
                return receipt;
            }
            catch (VeilApiException ex) when (ex.IsDeviceSetMismatch)
            {
                // A member added or revoked a device between our lookup and the send: drop stale sessions, re-encrypt once.
                foreach (var mismatch in ex.Problem?.Mismatches ?? [])
                {
                    foreach (var stale in mismatch.StaleDeviceIds)
                    {
                        ForgetSession(mismatch.UserId, stale);
                    }
                }

                conversation = await _api.GetConversationAsync(conversationId, ct);
                envelopes = await EncryptForConversationAsync(conversation, plaintext, ct);
                var receipt = await _api.SendEnvelopesAsync(conversationId, envelopes, ct);
                await PersistAsync(ct);
                return receipt;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Fetches, decrypts and acknowledges everything waiting for this device.</summary>
    public async Task<IReadOnlyList<IncomingMessage>> PullAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            RequireDevice();
            var received = new List<IncomingMessage>();
            var processed = new List<Guid>();
            var consumedPreKey = false;

            IReadOnlyList<PendingEnvelopeDto> pending;
            do
            {
                pending = await _api.FetchPendingAsync(ct);
                foreach (var item in pending)
                {
                    processed.Add(item.Id);
                    try
                    {
                        var (message, usedPreKey) = Decrypt(item);
                        consumedPreKey |= usedPreKey;
                        if (message.ConversationId != item.ConversationId)
                        {
                            Warn($"Envelope {item.Id} was routed to conversation {item.ConversationId} but was written for {message.ConversationId}; dropped.");
                            continue;
                        }

                        received.Add(new IncomingMessage(item.Id, item.ConversationId, item.SenderUserId, item.SenderDeviceId, message, DateTimeOffset.UtcNow));
                    }
                    catch (CryptoException ex)
                    {
                        Warn($"Could not decrypt envelope {item.Id} from {item.SenderUserId:N}/{item.SenderDeviceId:N}: {ex.Message}");
                    }
                }

                if (processed.Count > 0)
                {
                    await _api.AcknowledgeAsync(processed, ct);
                    processed.Clear();
                }
            }
            while (pending.Count > 0);

            if (consumedPreKey)
            {
                await ReplenishOneTimePreKeysCoreAsync(ct);
            }

            await PersistAsync(ct);
            return received;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ReplenishOneTimePreKeysAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            RequireDevice();
            await ReplenishOneTimePreKeysCoreAsync(ct);
            await PersistAsync(ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Safety number to compare out-of-band with a peer for one of their devices.</summary>
    public string SafetyNumberWith(string remoteUsername, IdentityPublicKeys remoteIdentity)
    {
        RequireDevice();
        return SafetyNumber.Compute(_keys!.Identity.Public, _state.Username, remoteIdentity, remoteUsername);
    }

    public IdentityPublicKeys? KnownIdentityOf(Guid userId, Guid deviceId) =>
        _sessions.TryGetValue(ClientState.PeerKey(userId, deviceId), out var session) ? session.RemoteIdentity
        : _state.Sessions.TryGetValue(ClientState.PeerKey(userId, deviceId), out var stored) ? stored.RemoteIdentity
        : null;

    public event Action<string>? Warning;

    public void Dispose()
    {
        _keys?.Dispose();
        _gate.Dispose();
    }

    private async Task<List<OutgoingEnvelope>> EncryptForConversationAsync(ConversationSummary conversation, byte[] plaintext, CancellationToken ct)
    {
        var envelopes = new List<OutgoingEnvelope>();
        foreach (var member in conversation.Members)
        {
            Dictionary<Guid, PreKeyBundleDto>? bundles = null;
            foreach (var deviceId in member.DeviceIds)
            {
                if (deviceId == _state.DeviceId)
                {
                    continue;
                }

                var session = GetSession(member.UserId, deviceId);
                if (session is null)
                {
                    bundles ??= (await _api.GetPreKeyBundlesAsync(member.UserId, ct)).ToDictionary(b => b.DeviceId);
                    if (!bundles.TryGetValue(deviceId, out var bundle))
                    {
                        continue; // device disappeared; the server will tell us if it still expects it
                    }

                    session = Establish(member.UserId, bundle);
                }

                envelopes.Add(new OutgoingEnvelope(member.UserId, deviceId, session.Encrypt(plaintext)));
            }
        }

        return envelopes;
    }

    private PeerSession Establish(Guid userId, PreKeyBundleDto dto)
    {
        var identity = new IdentityPublicKeys(dto.Identity.SigningKey, dto.Identity.DhKey, dto.Identity.DhKeySignature);
        CheckPinnedIdentity(userId, dto.DeviceId, identity);

        var bundle = new PreKeyBundle(identity, dto.SignedPreKeyId, dto.SignedPreKey, dto.SignedPreKeySignature, dto.KemPreKeyId, dto.KemPreKey, dto.KemPreKeySignature, dto.OneTimePreKeyId, dto.OneTimePreKey);
        var session = PeerSession.Initiate(_keys!.Identity, bundle);
        _sessions[ClientState.PeerKey(userId, dto.DeviceId)] = session;
        return session;
    }

    private (ChatMessage Message, bool UsedPreKey) Decrypt(PendingEnvelopeDto item)
    {
        var keys = _keys ?? throw new InvalidOperationException("No device keys.");
        var envelope = Envelope.Decode(item.Payload);
        var key = ClientState.PeerKey(item.SenderUserId, item.SenderDeviceId);
        var session = GetSession(item.SenderUserId, item.SenderDeviceId);
        byte[] plaintext;
        var usedPreKey = false;

        if (envelope.Type == EnvelopeType.PreKeyMessage)
        {
            var header = envelope.PreKeyHeader!;
            if (session is not null && session.InitiatorEphemeralKey is not null && session.InitiatorEphemeralKey.AsSpan().SequenceEqual(header.EphemeralKey))
            {
                // Same handshake we already completed; the peer simply has not seen our reply yet.
                plaintext = session.Decrypt(envelope);
            }
            else
            {
                CheckPinnedIdentity(item.SenderUserId, item.SenderDeviceId, header.InitiatorIdentity);
                (session, plaintext) = PeerSession.Respond(keys, envelope);
                _sessions[key] = session;
                _state.Keys = keys.Export();
                usedPreKey = true;
            }
        }
        else
        {
            if (session is null)
            {
                throw new SessionException("No session with this device; the peer must send a pre-key message first.");
            }

            plaintext = session.Decrypt(envelope);
        }

        var message = JsonSerializer.Deserialize<ChatMessage>(plaintext, ClientState.Json)
            ?? throw new MalformedMessageException("Empty chat message.");
        CryptoBytes.Zero(plaintext);
        return (message, usedPreKey);
    }

    private void CheckPinnedIdentity(Guid userId, Guid deviceId, IdentityPublicKeys identity)
    {
        var key = ClientState.PeerKey(userId, deviceId);
        var fingerprint = CryptoBytes.ToHex(identity.Fingerprint());
        if (_state.PinnedIdentities.TryGetValue(key, out var pinned))
        {
            if (pinned == fingerprint)
            {
                return;
            }

            IdentityChanged?.Invoke(new IdentityChange(userId, deviceId, pinned, fingerprint));
            if (RejectChangedIdentities)
            {
                throw new InvalidSignatureException($"Identity key of device {deviceId:N} changed; refusing to continue until verified.");
            }
        }

        _state.PinnedIdentities[key] = fingerprint;
    }

    private PeerSession? GetSession(Guid userId, Guid deviceId)
    {
        var key = ClientState.PeerKey(userId, deviceId);
        if (_sessions.TryGetValue(key, out var live))
        {
            return live;
        }

        if (_state.Sessions.TryGetValue(key, out var stored))
        {
            var imported = PeerSession.Import(stored);
            _sessions[key] = imported;
            return imported;
        }

        return null;
    }

    private void ForgetSession(Guid userId, Guid deviceId)
    {
        var key = ClientState.PeerKey(userId, deviceId);
        _sessions.Remove(key);
        _state.Sessions.Remove(key);
    }

    private async Task ReplenishOneTimePreKeysCoreAsync(CancellationToken ct)
    {
        var remaining = await _api.GetOneTimePreKeyCountAsync(ct);
        if (remaining >= OneTimePreKeyLowWatermark || _keys is null)
        {
            return;
        }

        var batch = _keys.GenerateOneTimePreKeys(OneTimePreKeyBatch);
        await _api.UploadOneTimePreKeysAsync(batch.Select(k => new OneTimePreKeyUpload(k.Id, k.KeyPair.PublicKey)).ToList(), ct);
        _state.Keys = _keys.Export();
    }

    private async Task PersistAsync(CancellationToken ct)
    {
        foreach (var (key, session) in _sessions)
        {
            _state.Sessions[key] = session.Export();
        }

        if (_keys is not null)
        {
            _state.Keys = _keys.Export();
        }

        await _store.SaveAsync(_state, ct);
    }

    private void RequireDevice()
    {
        if (!HasDevice)
        {
            throw new InvalidOperationException("Register a device before sending or receiving messages.");
        }
    }

    private void Warn(string message) => Warning?.Invoke(message);
}
