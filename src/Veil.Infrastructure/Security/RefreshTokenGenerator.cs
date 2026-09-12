using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Veil.Application.Abstractions.Security;

namespace Veil.Infrastructure.Security;

/// <summary>256-bit random refresh tokens. Only the SHA-256 of a token is persisted, so a database leak yields nothing usable.</summary>
public sealed class RefreshTokenGenerator : IRefreshTokenGenerator
{
    public (string Token, string Hash) Generate()
    {
        var token = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        return (token, Hash(token));
    }

    public string Hash(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        return Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }
}
