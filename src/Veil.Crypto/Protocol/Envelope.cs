namespace Veil.Crypto.Protocol;

public enum EnvelopeType : byte
{
    /// <summary>Carries a <see cref="PreKeyHeader"/> so the recipient can establish the session.</summary>
    PreKeyMessage = 0x01,

    /// <summary>Regular message for an established session.</summary>
    Message = 0x02,
}

/// <summary>
/// The opaque blob the server stores and forwards. Layout:
/// <c>version(1) || type(1) || [pre-key header] || ratchet header(40) || ciphertext</c>.
/// The server never parses beyond the length; it has no key to do anything else.
/// </summary>
public sealed record Envelope(EnvelopeType Type, PreKeyHeader? PreKeyHeader, RatchetMessage Message)
{
    public byte[] Encode()
    {
        var header = Message.Header.Encode();
        var preKey = PreKeyHeader?.Encode() ?? [];
        var buffer = new byte[2 + preKey.Length + header.Length + Message.Ciphertext.Length];
        buffer[0] = ProtocolConstants.Version;
        buffer[1] = (byte)Type;
        preKey.CopyTo(buffer, 2);
        header.CopyTo(buffer, 2 + preKey.Length);
        Message.Ciphertext.CopyTo(buffer, 2 + preKey.Length + header.Length);
        return buffer;
    }

    public static Envelope Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2 + ProtocolConstants.RatchetHeaderSize + ProtocolConstants.AeadTagSize)
        {
            throw new MalformedMessageException("Envelope is too short.");
        }

        if (data[0] != ProtocolConstants.Version)
        {
            throw new MalformedMessageException($"Unsupported protocol version {data[0]}.");
        }

        var type = (EnvelopeType)data[1];
        var offset = 2;
        PreKeyHeader? preKey = null;

        switch (type)
        {
            case EnvelopeType.PreKeyMessage:
                if (data.Length < offset + PreKeyHeader.EncodedSize + ProtocolConstants.RatchetHeaderSize + ProtocolConstants.AeadTagSize)
                {
                    throw new MalformedMessageException("Pre-key envelope is too short.");
                }

                preKey = PreKeyHeader.Decode(data.Slice(offset, PreKeyHeader.EncodedSize));
                offset += PreKeyHeader.EncodedSize;
                break;
            case EnvelopeType.Message:
                break;
            default:
                throw new MalformedMessageException($"Unknown envelope type {data[1]}.");
        }

        var header = RatchetHeader.Decode(data.Slice(offset, ProtocolConstants.RatchetHeaderSize));
        offset += ProtocolConstants.RatchetHeaderSize;
        var ciphertext = data[offset..].ToArray();

        return new Envelope(type, preKey, new RatchetMessage(header, ciphertext));
    }
}
