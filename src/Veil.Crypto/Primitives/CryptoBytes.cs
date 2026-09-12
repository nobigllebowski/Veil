using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;

namespace Veil.Crypto.Primitives;

/// <summary>Small helpers for byte handling that keep security-sensitive operations in one audited place.</summary>
public static class CryptoBytes
{
    public static byte[] Random(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>Constant-time equality; never use <c>SequenceEqual</c> for secrets or MACs.</summary>
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        CryptographicOperations.FixedTimeEquals(left, right);

    public static void Zero(Span<byte> buffer) => CryptographicOperations.ZeroMemory(buffer);

    public static byte[] Concat(params ReadOnlySpan<byte[]> parts)
    {
        var total = 0;
        foreach (var p in parts)
        {
            total += p.Length;
        }

        var result = new byte[total];
        var offset = 0;
        foreach (var p in parts)
        {
            p.CopyTo(result.AsSpan(offset));
            offset += p.Length;
        }

        return result;
    }

    public static byte[] UInt32BigEndian(uint value)
    {
        var buffer = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        return buffer;
    }

    public static uint ReadUInt32BigEndian(ReadOnlySpan<byte> source) => BinaryPrimitives.ReadUInt32BigEndian(source);

    public static string ToHex(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(data);

    public static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    public static string ToBase64Url(ReadOnlySpan<byte> data) => Base64Url.EncodeToString(data);

    public static byte[] FromBase64Url(string value) => Base64Url.DecodeFromChars(value);

    internal static void RequireLength(ReadOnlySpan<byte> value, int expected, string name)
    {
        if (value.Length != expected)
        {
            throw new ArgumentException($"{name} must be exactly {expected} bytes but was {value.Length}.", name);
        }
    }
}
