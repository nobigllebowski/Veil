using System.Security.Cryptography;

namespace Veil.Crypto.Primitives;

/// <summary>Key derivation primitives: HKDF-SHA256 (RFC 5869) and HMAC-SHA256.</summary>
public static class Kdf
{
    public static byte[] Hkdf(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int outputLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputLength);
        var output = new byte[outputLength];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, output, salt, info);
        return output;
    }

    public static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACSHA256.HashData(key, data);

    public static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    public static byte[] Sha512(ReadOnlySpan<byte> data) => SHA512.HashData(data);
}
