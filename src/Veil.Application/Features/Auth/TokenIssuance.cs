using Microsoft.Extensions.Options;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Options;
using Veil.Contracts;
using Veil.Domain.Auth;
using Veil.Domain.Users;

namespace Veil.Application.Features.Auth;

/// <summary>Issues an access token plus a fresh refresh token and stores the latter's hash.</summary>
internal sealed class TokenIssuance(
    IAccessTokenIssuer accessTokens,
    IRefreshTokenGenerator refreshTokens,
    IRefreshTokenRepository refreshTokenRepository,
    IClientContext client,
    TimeProvider time,
    IOptions<AuthOptions> options)
{
    public TokenPair Issue(User user, Guid? deviceId, Guid? familyId = null)
    {
        var now = time.GetUtcNow();
        var access = accessTokens.Issue(user, deviceId);
        var (refreshToken, hash) = refreshTokens.Generate();
        var stored = RefreshToken.Issue(user.Id, deviceId, hash, familyId ?? Guid.CreateVersion7(), now, options.Value.RefreshTokenLifetime, client.IpHash);
        refreshTokenRepository.Add(stored);

        return new TokenPair(access.Token, access.ExpiresAt, refreshToken, stored.ExpiresAt, deviceId);
    }
}
