using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Veil.Application.Abstractions.Security;
using Veil.Infrastructure.Options;

namespace Veil.Infrastructure.Security;

/// <summary>HMAC-SHA256 blind index: deterministic for equality lookups, useless without the key.</summary>
public sealed class HmacBlindIndexer : IBlindIndexer, IDisposable
{
    private readonly byte[] _key;

    public HmacBlindIndexer(IOptions<SecurityOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _key = AesGcmFieldEncryptor.DecodeKey(options.Value.BlindIndexKey, nameof(SecurityOptions.BlindIndexKey));
    }

    public string Compute(string normalizedValue)
    {
        ArgumentNullException.ThrowIfNull(normalizedValue);
        return Base64Url.EncodeToString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(normalizedValue)));
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
