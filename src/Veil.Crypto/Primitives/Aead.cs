using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Veil.Crypto.Primitives;

/// <summary>
/// AES-256-GCM authenticated encryption. Output layout: ciphertext || 16-byte tag.
/// Uses the platform implementation where available and BouncyCastle's managed GCM elsewhere (browser WebAssembly),
/// so the same protocol code runs on the server, on desktops and inside Blazor.
/// </summary>
public static class Aead
{
    private static readonly bool UsePlatform = AesGcm.IsSupported;

    public static byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        CryptoBytes.RequireLength(key, ProtocolConstants.AeadKeySize, nameof(key));
        CryptoBytes.RequireLength(nonce, ProtocolConstants.AeadNonceSize, nameof(nonce));

        if (!UsePlatform)
        {
            return RunManaged(forEncryption: true, key, nonce, plaintext, associatedData);
        }

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

        if (!UsePlatform)
        {
            return RunManaged(forEncryption: false, key, nonce, ciphertextWithTag, associatedData);
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

    private static byte[] RunManaged(bool forEncryption, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, ReadOnlySpan<byte> associatedData)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key.ToArray()), ProtocolConstants.AeadTagSize * 8, nonce.ToArray(), associatedData.ToArray()));

        var inputBytes = input.ToArray();
        var output = new byte[cipher.GetOutputSize(inputBytes.Length)];
        try
        {
            var written = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, output, 0);
            written += cipher.DoFinal(output, written);
            return written == output.Length ? output : output[..written];
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException ex)
        {
            CryptoBytes.Zero(output);
            throw new DecryptionFailedException("Authentication tag mismatch.", ex);
        }
    }
}
