using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Veil.Infrastructure.Options;

namespace Veil.Infrastructure.Security;

/// <summary>Column-level encryption port. Ciphertexts are bound to a purpose so values cannot be swapped between columns.</summary>
public interface IFieldEncryptor
{
    string Protect(string plaintext, string purpose);
    string Unprotect(string ciphertext, string purpose);
}

/// <summary>
/// AES-256-GCM with a random 96-bit nonce per value. Format: <c>v1.&lt;base64url(nonce || ciphertext || tag)&gt;</c>.
/// The version prefix allows a future key rotation / algorithm migration without a big-bang re-encryption.
/// </summary>
public sealed class AesGcmFieldEncryptor : IFieldEncryptor, IDisposable
{
    private const string Version = "v1.";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;

    public AesGcmFieldEncryptor(IOptions<SecurityOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _key = DecodeKey(options.Value.FieldEncryptionKey, nameof(SecurityOptions.FieldEncryptionKey));
    }

    public string Protect(string plaintext, string purpose)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var output = new byte[NonceSize + plain.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plain, output.AsSpan(NonceSize, plain.Length), output.AsSpan(NonceSize + plain.Length, TagSize), Encoding.UTF8.GetBytes(purpose));
        return Version + Base64Url.EncodeToString(output);
    }

    public string Unprotect(string ciphertext, string purpose)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (!ciphertext.StartsWith(Version, StringComparison.Ordinal))
        {
            throw new CryptographicException("Unknown field-encryption format version.");
        }

        var data = Base64Url.DecodeFromChars(ciphertext.AsSpan(Version.Length));
        if (data.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Field ciphertext is too short.");
        }

        var plain = new byte[data.Length - NonceSize - TagSize];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(data.AsSpan(0, NonceSize), data.AsSpan(NonceSize, plain.Length), data.AsSpan(NonceSize + plain.Length, TagSize), plain, Encoding.UTF8.GetBytes(purpose));
        return Encoding.UTF8.GetString(plain);
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);

    internal static byte[] DecodeKey(string base64, string name)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"{name} must be base64.", ex);
        }

        if (key.Length != 32)
        {
            throw new InvalidOperationException($"{name} must decode to exactly 32 bytes.");
        }

        return key;
    }
}
