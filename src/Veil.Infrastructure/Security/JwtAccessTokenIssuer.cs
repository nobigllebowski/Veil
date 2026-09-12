using System.Globalization;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Veil.Application.Abstractions.Security;
using Veil.Application.Options;
using Veil.Domain.Users;

namespace Veil.Infrastructure.Security;

public static class VeilClaims
{
    public const string DeviceId = "did";
    public const string SecurityStamp = "sst";
}

/// <summary>Short-lived ES256 JWTs. No PII beyond the username; the security stamp lets the server revoke early.</summary>
public sealed class JwtAccessTokenIssuer(ISigningKeyProvider keys, IOptions<AuthOptions> options, TimeProvider time) : IAccessTokenIssuer
{
    private static readonly JsonWebTokenHandler Handler = new() { SetDefaultTimesOnTokenCreation = false };

    public AccessToken Issue(User user, Guid? deviceId)
    {
        ArgumentNullException.ThrowIfNull(user);
        var now = time.GetUtcNow();
        var expires = now + options.Value.AccessTokenLifetime;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Name, user.Username.Value),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString()),
            new(VeilClaims.SecurityStamp, user.SecurityStamp.ToString(CultureInfo.InvariantCulture)),
        };

        if (deviceId is { } did)
        {
            claims.Add(new Claim(VeilClaims.DeviceId, did.ToString()));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(keys.SigningKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "at+jwt",
        };

        return new AccessToken(Handler.CreateToken(descriptor), expires);
    }
}
