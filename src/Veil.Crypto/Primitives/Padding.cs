namespace Veil.Crypto.Primitives;

/// <summary>
/// ISO/IEC 7816-4 padding to a fixed block size. Hides exact plaintext lengths from anyone observing ciphertext
/// sizes (the server included). Always adds at least one byte.
/// </summary>
public static class Padding
{
    private const byte Marker = 0x80;

    public static byte[] Pad(ReadOnlySpan<byte> plaintext, int blockSize = ProtocolConstants.PaddingBlockSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        var paddedLength = ((plaintext.Length + 1 + blockSize - 1) / blockSize) * blockSize;
        var padded = new byte[paddedLength];
        plaintext.CopyTo(padded);
        padded[plaintext.Length] = Marker;
        return padded;
    }

    public static byte[] Unpad(ReadOnlySpan<byte> padded)
    {
        var i = padded.Length - 1;
        while (i >= 0 && padded[i] == 0)
        {
            i--;
        }

        if (i < 0 || padded[i] != Marker)
        {
            throw new MalformedMessageException("Invalid padding.");
        }

        return padded[..i].ToArray();
    }
}
