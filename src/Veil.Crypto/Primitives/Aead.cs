using System.Security.Cryptography;

namespace Veil.Crypto.Primitives;

/// <summary>AES-256-GCM authenticated encryption. Output layout: ciphertext || 16-byte tag.</summary>
public static class Aead
{
    public static byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        CryptoBytes.RequireLength(key, ProtocolConstants.AeadKeySize, nameof(key));
        CryptoBytes.RequireLength(nonce, ProtocolConstants.AeadNonceSize, nameof(nonce));

        var output = new byte[plaintext.Length + ProtocolConstants.AeadTagSize];
        using var aes = new AesGcm(key, ProtocolConstants.AeadTagSize);
        aes.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length), associatedData);
        return output;
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextWithTag, ReadOnlySpan<byte> associatedData)
    {
        CryptoBytes.RequireLength(key, ProtocolConstants.AeadKeySize, nameof(key));
        CryptoBytes.RequireLength(nonce, ProtocolConstants.AeadNonceSize, nameof(nonce));

        if (ciphertextWithTag.Length < ProtocolConstants.AeadTagSize)
        {
            throw new DecryptionFailedException("Ciphertext shorter than authentication tag.");
        }

        var ciphertext = ciphertextWithTag[..^ProtocolConstants.AeadTagSize];
        var tag = ciphertextWithTag[^ProtocolConstants.AeadTagSize..];
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, ProtocolConstants.AeadTagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            CryptoBytes.Zero(plaintext);
            throw new DecryptionFailedException("Authentication tag mismatch.", ex);
        }

        return plaintext;
    }
}
