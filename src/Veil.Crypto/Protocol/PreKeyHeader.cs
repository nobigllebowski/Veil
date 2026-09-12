using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;

namespace Veil.Crypto.Protocol;

/// <summary>
/// Handshake material the initiator attaches to messages until the responder replies. Lets the responder
/// reconstruct the PQXDH shared secret from its own private keys.
/// </summary>
public sealed record PreKeyHeader(
    IdentityPublicKeys InitiatorIdentity,
    byte[] EphemeralKey,
    uint SignedPreKeyId,
    uint? OneTimePreKeyId,
    uint KemPreKeyId,
    byte[] KemCiphertext)
{
    public const int EncodedSize =
        ProtocolConstants.Ed25519PublicKeySize + ProtocolConstants.X25519KeySize + ProtocolConstants.Ed25519SignatureSize +
        ProtocolConstants.X25519KeySize + sizeof(uint) + 1 + sizeof(uint) + sizeof(uint) + ProtocolConstants.MlKem768CiphertextSize;

    public byte[] Encode()
    {
        CryptoBytes.RequireLength(InitiatorIdentity.SigningKey, ProtocolConstants.Ed25519PublicKeySize, nameof(InitiatorIdentity));
        CryptoBytes.RequireLength(InitiatorIdentity.DhKey, ProtocolConstants.X25519KeySize, nameof(InitiatorIdentity));
        CryptoBytes.RequireLength(InitiatorIdentity.DhKeySignature, ProtocolConstants.Ed25519SignatureSize, nameof(InitiatorIdentity));
        CryptoBytes.RequireLength(EphemeralKey, ProtocolConstants.X25519KeySize, nameof(EphemeralKey));
        CryptoBytes.RequireLength(KemCiphertext, ProtocolConstants.MlKem768CiphertextSize, nameof(KemCiphertext));

        return CryptoBytes.Concat(
            InitiatorIdentity.SigningKey,
            InitiatorIdentity.DhKey,
            InitiatorIdentity.DhKeySignature,
            EphemeralKey,
            CryptoBytes.UInt32BigEndian(SignedPreKeyId),
            [OneTimePreKeyId.HasValue ? (byte)1 : (byte)0],
            CryptoBytes.UInt32BigEndian(OneTimePreKeyId ?? 0),
            CryptoBytes.UInt32BigEndian(KemPreKeyId),
            KemCiphertext);
    }

    public static PreKeyHeader Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length != EncodedSize)
        {
            throw new MalformedMessageException("Pre-key header has an invalid length.");
        }

        var reader = new SpanReader(data);
        var signingKey = reader.Read(ProtocolConstants.Ed25519PublicKeySize);
        var dhKey = reader.Read(ProtocolConstants.X25519KeySize);
        var dhSignature = reader.Read(ProtocolConstants.Ed25519SignatureSize);
        var ephemeral = reader.Read(ProtocolConstants.X25519KeySize);
        var signedPreKeyId = reader.ReadUInt32();
        var hasOneTime = reader.ReadByte() == 1;
        var oneTimeId = reader.ReadUInt32();
        var kemId = reader.ReadUInt32();
        var kemCiphertext = reader.Read(ProtocolConstants.MlKem768CiphertextSize);

        return new PreKeyHeader(
            new IdentityPublicKeys(signingKey, dhKey, dhSignature),
            ephemeral,
            signedPreKeyId,
            hasOneTime ? oneTimeId : null,
            kemId,
            kemCiphertext);
    }

    private ref struct SpanReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _offset;

        public byte[] Read(int length)
        {
            var slice = _data.Slice(_offset, length).ToArray();
            _offset += length;
            return slice;
        }

        public uint ReadUInt32() => CryptoBytes.ReadUInt32BigEndian(Read(sizeof(uint)));

        public byte ReadByte() => _data[_offset++];
    }
}
