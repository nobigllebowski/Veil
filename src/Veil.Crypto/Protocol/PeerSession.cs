using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;

namespace Veil.Crypto.Protocol;

/// <summary>
/// A complete end-to-end encrypted channel with one remote device: PQXDH handshake state plus the Double Ratchet.
/// Applies length padding and produces/consumes wire <see cref="Envelope"/>s.
/// </summary>
public sealed class PeerSession
{
    private readonly RatchetSession _ratchet;
    private PreKeyHeader? _pendingPreKeyHeader;

    private PeerSession(RatchetSession ratchet, IdentityPublicKeys remoteIdentity, PreKeyHeader? pendingPreKeyHeader, byte[]? initiatorEphemeralKey)
    {
        _ratchet = ratchet;
        RemoteIdentity = remoteIdentity;
        _pendingPreKeyHeader = pendingPreKeyHeader;
        InitiatorEphemeralKey = initiatorEphemeralKey;
    }

    public IdentityPublicKeys RemoteIdentity { get; }

    /// <summary>For responder sessions: the ephemeral key of the handshake that created this session (detects duplicate pre-key messages).</summary>
    public byte[]? InitiatorEphemeralKey { get; }

    /// <summary>True while the initiator still attaches the handshake header (until the peer's first reply arrives).</summary>
    public bool IsHandshakePending => _pendingPreKeyHeader is not null;

    public bool CanSend => _ratchet.CanSend;

    /// <summary>Alice: create a session towards a remote device from its pre-key bundle.</summary>
    public static PeerSession Initiate(IdentityKeyPair localIdentity, PreKeyBundle remoteBundle)
    {
        var handshake = Pqxdh.Initiate(localIdentity, remoteBundle);
        var ratchet = RatchetSession.InitializeAsInitiator(handshake.SharedSecret, handshake.ResponderRatchetKey, handshake.AssociatedData);
        CryptoBytes.Zero(handshake.SharedSecret);
        return new PeerSession(ratchet, remoteBundle.Identity, handshake.Header, null);
    }

    /// <summary>Bob: create a session from an incoming pre-key envelope and decrypt its payload in one step.</summary>
    public static (PeerSession Session, byte[] Plaintext) Respond(DeviceKeyStore localKeys, Envelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (envelope.Type != EnvelopeType.PreKeyMessage || envelope.PreKeyHeader is null)
        {
            throw new SessionException("A session can only be created from a pre-key message.");
        }

        var handshake = Pqxdh.Respond(localKeys, envelope.PreKeyHeader);
        var ratchet = RatchetSession.InitializeAsResponder(handshake.SharedSecret, handshake.OwnRatchetKeyPair, handshake.AssociatedData);
        CryptoBytes.Zero(handshake.SharedSecret);

        var session = new PeerSession(ratchet, envelope.PreKeyHeader.InitiatorIdentity, null, envelope.PreKeyHeader.EphemeralKey);
        var plaintext = session.DecryptCore(envelope.Message);
        return (session, plaintext);
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        var padded = Padding.Pad(plaintext);
        var message = _ratchet.Encrypt(padded);
        CryptoBytes.Zero(padded);

        var envelope = _pendingPreKeyHeader is null
            ? new Envelope(EnvelopeType.Message, null, message)
            : new Envelope(EnvelopeType.PreKeyMessage, _pendingPreKeyHeader, message);
        return envelope.Encode();
    }

    public byte[] Decrypt(Envelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var plaintext = DecryptCore(envelope.Message);

        // Any authenticated message from the peer proves it holds the session: stop re-sending the handshake.
        _pendingPreKeyHeader = null;
        return plaintext;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> envelopeBytes) => Decrypt(Envelope.Decode(envelopeBytes));

    public PeerSessionState Export() => new(_ratchet.Export(), RemoteIdentity, _pendingPreKeyHeader?.Encode(), InitiatorEphemeralKey);

    public static PeerSession Import(PeerSessionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new PeerSession(
            RatchetSession.Import(state.Ratchet),
            state.RemoteIdentity,
            state.PendingPreKeyHeader is null ? null : PreKeyHeader.Decode(state.PendingPreKeyHeader),
            state.InitiatorEphemeralKey);
    }

    private byte[] DecryptCore(RatchetMessage message)
    {
        var padded = _ratchet.Decrypt(message);
        var plaintext = Padding.Unpad(padded);
        CryptoBytes.Zero(padded);
        return plaintext;
    }
}

/// <summary>Serializable snapshot of a <see cref="PeerSession"/>. Contains secrets: store encrypted only.</summary>
public sealed record PeerSessionState(RatchetSessionState Ratchet, IdentityPublicKeys RemoteIdentity, byte[]? PendingPreKeyHeader, byte[]? InitiatorEphemeralKey);
