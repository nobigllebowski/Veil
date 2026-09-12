using Veil.Crypto.Primitives;

namespace Veil.Crypto.Protocol;

/// <summary>
/// Double Ratchet (Signal specification) with AES-256-GCM message encryption. Provides forward secrecy
/// (compromise of current keys does not reveal past messages) and post-compromise security (a compromise is
/// healed as soon as a fresh DH ratchet step completes).
/// </summary>
/// <remarks>
/// Every mutation happens on a working copy that is committed only after authenticated decryption succeeds,
/// so a forged or corrupted message can never desynchronise the session.
/// </remarks>
public sealed class RatchetSession
{
    private static readonly byte[] ZeroSalt = new byte[ProtocolConstants.MessageKeySize];
    private static readonly byte[] MessageKeySeed = [0x01];
    private static readonly byte[] ChainKeySeed = [0x02];

    private State _state;

    private RatchetSession(State state)
    {
        _state = state;
    }

    public byte[] AssociatedData => _state.AssociatedData;
    public uint SendCount => _state.SendCount;
    public uint ReceiveCount => _state.ReceiveCount;
    public int SkippedKeyCount => _state.Skipped.Count;
    public bool CanSend => _state.ChainKeySend is not null;

    /// <summary>Initialises the side that performed the handshake (Alice). Alice can send immediately.</summary>
    public static RatchetSession InitializeAsInitiator(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> remoteRatchetPublicKey, ReadOnlySpan<byte> associatedData)
    {
        CryptoBytes.RequireLength(sharedSecret, ProtocolConstants.RootKeySize, nameof(sharedSecret));
        CryptoBytes.RequireLength(remoteRatchetPublicKey, ProtocolConstants.X25519KeySize, nameof(remoteRatchetPublicKey));

        var dhSelf = X25519.GenerateKeyPair();
        var remote = remoteRatchetPublicKey.ToArray();
        var (rootKey, chainKeySend) = KdfRoot(sharedSecret, X25519.Agree(dhSelf.PrivateKey, remote));

        return new RatchetSession(new State
        {
            DhSelf = dhSelf,
            DhRemote = remote,
            RootKey = rootKey,
            ChainKeySend = chainKeySend,
            ChainKeyReceive = null,
            AssociatedData = associatedData.ToArray(),
        });
    }

    /// <summary>Initialises the side whose signed pre-key was used (Bob). Bob can send only after receiving Alice's first message.</summary>
    public static RatchetSession InitializeAsResponder(ReadOnlySpan<byte> sharedSecret, X25519KeyPair ownRatchetKeyPair, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(ownRatchetKeyPair);
        CryptoBytes.RequireLength(sharedSecret, ProtocolConstants.RootKeySize, nameof(sharedSecret));

        return new RatchetSession(new State
        {
            DhSelf = X25519KeyPair.From([.. ownRatchetKeyPair.PrivateKey], [.. ownRatchetKeyPair.PublicKey]),
            DhRemote = null,
            RootKey = sharedSecret.ToArray(),
            ChainKeySend = null,
            ChainKeyReceive = null,
            AssociatedData = associatedData.ToArray(),
        });
    }

    public RatchetMessage Encrypt(ReadOnlySpan<byte> plaintext)
    {
        if (_state.ChainKeySend is null)
        {
            throw new SessionException("Cannot send before the first message from the peer has been received.");
        }

        var (nextChainKey, messageKey) = KdfChain(_state.ChainKeySend);
        var header = new RatchetHeader(_state.DhSelf.PublicKey, _state.PreviousSendCount, _state.SendCount);
        var headerBytes = header.Encode();

        var ciphertext = EncryptWithMessageKey(messageKey, plaintext, CryptoBytes.Concat(_state.AssociatedData, headerBytes));

        CryptoBytes.Zero(_state.ChainKeySend);
        _state.ChainKeySend = nextChainKey;
        _state.SendCount++;
        CryptoBytes.Zero(messageKey);

        return new RatchetMessage(header, ciphertext);
    }

    public byte[] Decrypt(RatchetMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var headerBytes = message.Header.Encode();
        var associated = CryptoBytes.Concat(_state.AssociatedData, headerBytes);

        // 1. Out-of-order message whose key was already derived?
        var skippedId = SkippedKeyId(message.Header.DhPublicKey, message.Header.MessageNumber);
        if (_state.Skipped.TryGetValue(skippedId, out var skippedKey))
        {
            var plaintextFromSkipped = DecryptWithMessageKey(skippedKey, message.Ciphertext, associated);
            _state.Skipped.Remove(skippedId);
            _state.SkippedOrder.Remove(skippedId);
            CryptoBytes.Zero(skippedKey);
            return plaintextFromSkipped;
        }

        // 2. Work on a copy; commit only if the AEAD tag verifies.
        var working = _state.Clone();

        if (working.DhRemote is null || !working.DhRemote.AsSpan().SequenceEqual(message.Header.DhPublicKey))
        {
            SkipMessageKeys(working, message.Header.PreviousChainLength);
            DhRatchet(working, message.Header.DhPublicKey);
        }

        SkipMessageKeys(working, message.Header.MessageNumber);

        var (nextChainKey, messageKey) = KdfChain(working.ChainKeyReceive!);
        var plaintext = DecryptWithMessageKey(messageKey, message.Ciphertext, associated);
        CryptoBytes.Zero(messageKey);

        working.ChainKeyReceive = nextChainKey;
        working.ReceiveCount++;

        _state.DisposeIfReplaced(working);
        _state = working;
        return plaintext;
    }

    /// <summary>Snapshots the session. Arrays are copied so later ratchet steps cannot zero the exported material.</summary>
    public RatchetSessionState Export() => new(
        [.. _state.DhSelf.PrivateKey],
        [.. _state.DhSelf.PublicKey],
        _state.DhRemote is null ? null : [.. _state.DhRemote],
        [.. _state.RootKey],
        _state.ChainKeySend is null ? null : [.. _state.ChainKeySend],
        _state.ChainKeyReceive is null ? null : [.. _state.ChainKeyReceive],
        _state.SendCount,
        _state.ReceiveCount,
        _state.PreviousSendCount,
        [.. _state.AssociatedData],
        _state.SkippedOrder.Select(id => new SkippedMessageKeyState([.. id.DhPublicKey], id.MessageNumber, [.. _state.Skipped[id]])).ToList());

    public static RatchetSession Import(RatchetSessionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var restored = new State
        {
            DhSelf = X25519KeyPair.From(state.DhSelfPrivateKey, state.DhSelfPublicKey),
            DhRemote = state.DhRemotePublicKey,
            RootKey = state.RootKey,
            ChainKeySend = state.ChainKeySend,
            ChainKeyReceive = state.ChainKeyReceive,
            SendCount = state.SendCount,
            ReceiveCount = state.ReceiveCount,
            PreviousSendCount = state.PreviousSendCount,
            AssociatedData = state.AssociatedData,
        };

        foreach (var skipped in state.SkippedMessageKeys)
        {
            var id = SkippedKeyId(skipped.DhPublicKey, skipped.MessageNumber);
            restored.Skipped[id] = skipped.MessageKey;
            restored.SkippedOrder.Add(id);
        }

        return new RatchetSession(restored);
    }

    private static void DhRatchet(State state, byte[] remotePublicKey)
    {
        state.PreviousSendCount = state.SendCount;
        state.SendCount = 0;
        state.ReceiveCount = 0;
        state.DhRemote = remotePublicKey;

        var (rootAfterReceive, chainKeyReceive) = KdfRoot(state.RootKey, X25519.Agree(state.DhSelf.PrivateKey, state.DhRemote));
        state.ChainKeyReceive = chainKeyReceive;

        state.DhSelf = X25519.GenerateKeyPair();
        var (rootAfterSend, chainKeySend) = KdfRoot(rootAfterReceive, X25519.Agree(state.DhSelf.PrivateKey, state.DhRemote));
        state.RootKey = rootAfterSend;
        state.ChainKeySend = chainKeySend;
    }

    private static void SkipMessageKeys(State state, uint until)
    {
        if (state.ReceiveCount + ProtocolConstants.MaxSkippedMessageKeys < until)
        {
            throw new SessionException($"Message would require skipping more than {ProtocolConstants.MaxSkippedMessageKeys} keys.");
        }

        if (state.ChainKeyReceive is null)
        {
            return;
        }

        while (state.ReceiveCount < until)
        {
            var (nextChainKey, messageKey) = KdfChain(state.ChainKeyReceive);
            var id = SkippedKeyId(state.DhRemote!, state.ReceiveCount);
            state.Skipped[id] = messageKey;
            state.SkippedOrder.Add(id);
            state.ChainKeyReceive = nextChainKey;
            state.ReceiveCount++;

            while (state.SkippedOrder.Count > ProtocolConstants.MaxStoredSkippedKeys)
            {
                var oldest = state.SkippedOrder[0];
                state.SkippedOrder.RemoveAt(0);
                if (state.Skipped.Remove(oldest, out var evicted))
                {
                    CryptoBytes.Zero(evicted);
                }
            }
        }
    }

    private static (byte[] RootKey, byte[] ChainKey) KdfRoot(ReadOnlySpan<byte> rootKey, byte[] dhOutput)
    {
        var derived = Kdf.Hkdf(dhOutput, rootKey, ProtocolConstants.RootKdfInfo, ProtocolConstants.RootKeySize + ProtocolConstants.ChainKeySize);
        CryptoBytes.Zero(dhOutput);
        return (derived[..ProtocolConstants.RootKeySize], derived[ProtocolConstants.RootKeySize..]);
    }

    private static (byte[] NextChainKey, byte[] MessageKey) KdfChain(ReadOnlySpan<byte> chainKey) =>
        (Kdf.Hmac(chainKey, ChainKeySeed), Kdf.Hmac(chainKey, MessageKeySeed));

    private static (byte[] Key, byte[] Nonce) ExpandMessageKey(ReadOnlySpan<byte> messageKey)
    {
        var expanded = Kdf.Hkdf(messageKey, ZeroSalt, ProtocolConstants.MessageKeysInfo, ProtocolConstants.AeadKeySize + ProtocolConstants.AeadNonceSize);
        return (expanded[..ProtocolConstants.AeadKeySize], expanded[ProtocolConstants.AeadKeySize..]);
    }

    private static byte[] EncryptWithMessageKey(byte[] messageKey, ReadOnlySpan<byte> plaintext, byte[] associatedData)
    {
        var (key, nonce) = ExpandMessageKey(messageKey);
        var ciphertext = Aead.Encrypt(key, nonce, plaintext, associatedData);
        CryptoBytes.Zero(key);
        return ciphertext;
    }

    private static byte[] DecryptWithMessageKey(byte[] messageKey, byte[] ciphertext, byte[] associatedData)
    {
        var (key, nonce) = ExpandMessageKey(messageKey);
        try
        {
            return Aead.Decrypt(key, nonce, ciphertext, associatedData);
        }
        finally
        {
            CryptoBytes.Zero(key);
        }
    }

    private static SkippedKey SkippedKeyId(byte[] dhPublicKey, uint messageNumber) => new(dhPublicKey, messageNumber);

    private readonly record struct SkippedKey(byte[] DhPublicKey, uint MessageNumber)
    {
        public bool Equals(SkippedKey other) =>
            MessageNumber == other.MessageNumber && DhPublicKey.AsSpan().SequenceEqual(other.DhPublicKey);

        public override int GetHashCode() =>
            HashCode.Combine(MessageNumber, BitConverter.ToInt32(DhPublicKey, 0));
    }

    private sealed class State
    {
        public required X25519KeyPair DhSelf { get; set; }
        public byte[]? DhRemote { get; set; }
        public required byte[] RootKey { get; set; }
        public byte[]? ChainKeySend { get; set; }
        public byte[]? ChainKeyReceive { get; set; }
        public uint SendCount { get; set; }
        public uint ReceiveCount { get; set; }
        public uint PreviousSendCount { get; set; }
        public required byte[] AssociatedData { get; init; }
        public Dictionary<SkippedKey, byte[]> Skipped { get; } = new();
        public List<SkippedKey> SkippedOrder { get; } = [];

        public State Clone()
        {
            var clone = new State
            {
                DhSelf = X25519KeyPair.From([.. DhSelf.PrivateKey], [.. DhSelf.PublicKey]),
                DhRemote = DhRemote is null ? null : [.. DhRemote],
                RootKey = [.. RootKey],
                ChainKeySend = ChainKeySend is null ? null : [.. ChainKeySend],
                ChainKeyReceive = ChainKeyReceive is null ? null : [.. ChainKeyReceive],
                SendCount = SendCount,
                ReceiveCount = ReceiveCount,
                PreviousSendCount = PreviousSendCount,
                AssociatedData = AssociatedData,
            };

            foreach (var id in SkippedOrder)
            {
                clone.Skipped[id] = [.. Skipped[id]];
                clone.SkippedOrder.Add(id);
            }

            return clone;
        }

        public void DisposeIfReplaced(State replacement)
        {
            if (!ReferenceEquals(DhSelf, replacement.DhSelf))
            {
                DhSelf.Dispose();
            }

            CryptoBytes.Zero(RootKey);
            if (ChainKeySend is not null)
            {
                CryptoBytes.Zero(ChainKeySend);
            }

            if (ChainKeyReceive is not null)
            {
                CryptoBytes.Zero(ChainKeyReceive);
            }
        }
    }
}

/// <summary>Serializable snapshot of a <see cref="RatchetSession"/>. Contains secrets: store encrypted only.</summary>
public sealed record RatchetSessionState(
    byte[] DhSelfPrivateKey,
    byte[] DhSelfPublicKey,
    byte[]? DhRemotePublicKey,
    byte[] RootKey,
    byte[]? ChainKeySend,
    byte[]? ChainKeyReceive,
    uint SendCount,
    uint ReceiveCount,
    uint PreviousSendCount,
    byte[] AssociatedData,
    List<SkippedMessageKeyState> SkippedMessageKeys);

public sealed record SkippedMessageKeyState(byte[] DhPublicKey, uint MessageNumber, byte[] MessageKey);
