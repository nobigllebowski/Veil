using Veil.Crypto.Primitives;

namespace Veil.Crypto.Protocol;

/// <summary>Double Ratchet message header: the sender's current ratchet public key and chain counters.</summary>
public sealed record RatchetHeader(byte[] DhPublicKey, uint PreviousChainLength, uint MessageNumber)
{
    public byte[] Encode()
    {
        CryptoBytes.RequireLength(DhPublicKey, ProtocolConstants.X25519KeySize, nameof(DhPublicKey));
        return CryptoBytes.Concat(DhPublicKey, CryptoBytes.UInt32BigEndian(PreviousChainLength), CryptoBytes.UInt32BigEndian(MessageNumber));
    }

    public static RatchetHeader Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length != ProtocolConstants.RatchetHeaderSize)
        {
            throw new MalformedMessageException("Ratchet header has an invalid length.");
        }

        return new RatchetHeader(
            data[..ProtocolConstants.X25519KeySize].ToArray(),
            CryptoBytes.ReadUInt32BigEndian(data.Slice(ProtocolConstants.X25519KeySize, sizeof(uint))),
            CryptoBytes.ReadUInt32BigEndian(data.Slice(ProtocolConstants.X25519KeySize + sizeof(uint), sizeof(uint))));
    }
}

/// <summary>An encrypted Double Ratchet message: authenticated header plus AEAD ciphertext.</summary>
public sealed record RatchetMessage(RatchetHeader Header, byte[] Ciphertext);
