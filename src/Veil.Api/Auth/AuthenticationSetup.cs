using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Veil.Application.Options;
using Veil.Infrastructure.Security;

namespace Veil.Api.Auth;

internal static class AuthPolicies
{
    /// <summary>Requires a token issued for a registered device (needed for anything that touches key material or envelopes).</summary>
    public const string DeviceBound = "DeviceBound";
}

internal static class AuthenticationSetup
{
    public static IServiceCollection AddVeilAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<ISigningKeyProvider, IOptions<AuthOptions>>((jwt, keys, auth) =>
            {
                jwt.MapInboundClaims = false;
                jwt.SaveToken = false;
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = auth.Value.Issuer,
                    ValidAudience = auth.Value.Audience,
                    IssuerSigningKey = keys.ValidationKey,
                    ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                    ValidTypes = ["at+jwt"],
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = JwtRegisteredClaimNames.Name,
                };

                jwt.Events = new JwtBearerEvents
                {
                    // SignalR's browser transports cannot set headers: accept the token from the query string on hub paths only.
                    OnMessageReceived = context =>
                    {
                        var accessToken = context.Request.Query["access_token"];
                        if (!string.IsNullOrEmpty(accessToken) && context.HttpContext.Request.Path.StartsWithSegments("/hubs", StringComparison.OrdinalIgnoreCase))
                        {
                            context.Token = accessToken;
                        }

                        return Task.CompletedTask;
                    },

                    // Reject tokens whose security stamp is stale (password changed, "log out everywhere") or whose device was revoked.
                    OnTokenValidated = async context =>
                    {
                        var userId = CurrentUser.TryGetUserId(context.Principal);
                        var stampClaim = context.Principal?.FindFirst(VeilClaims.SecurityStamp)?.Value;
                        if (userId is null || !int.TryParse(stampClaim, out var stamp))
                        {
                            context.Fail("Token is missing required claims.");
                            return;
                        }

                        var validator = context.HttpContext.RequestServices.GetRequiredService<ISessionValidator>();
                        if (!await validator.IsStampCurrentAsync(userId.Value, stamp, context.HttpContext.RequestAborted))
                        {
                            context.Fail("Token has been revoked.");
                            return;
                        }

                        if (CurrentUser.TryGetDeviceId(context.Principal) is { } deviceId &&
                            !await validator.IsDeviceActiveAsync(userId.Value, deviceId, context.HttpContext.RequestAborted))
                        {
                            context.Fail("Device has been revoked.");
                        }
                    },
                };
            });

        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy(AuthPolicies.DeviceBound, policy => policy.RequireAuthenticatedUser().RequireClaim(VeilClaims.DeviceId));

        return services;
    }
}
