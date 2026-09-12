using Veil.Crypto;
using Veil.Infrastructure.Security;

namespace Veil.Api.Endpoints;

internal static class WellKnownEndpoints
{
    public static WebApplication MapWellKnownEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/.well-known").WithTags("Discovery").AllowAnonymous();

        group.MapGet("/jwks.json", (ISigningKeyProvider keys) => Results.Ok(new { keys = new[] { keys.PublicJwk } }))
            .WithSummary("Public keys for verifying access tokens.");

        group.MapGet("/veil-configuration", () => Results.Ok(new
        {
            protocolVersion = ProtocolConstants.Version,
            keyAgreement = "PQXDH (X25519 + ML-KEM-768, HKDF-SHA256)",
            ratchet = "Double Ratchet (X25519, HMAC-SHA256 chains, AES-256-GCM)",
            signatures = "Ed25519",
            paddingBlockSize = ProtocolConstants.PaddingBlockSize,
            maxEnvelopeBytes = Veil.Domain.Messages.MessageEnvelope.MaxPayloadBytes,
            realtimeHub = "/hubs/chat",
        }))
            .WithSummary("Protocol parameters clients must agree on.");

        return app;
    }
}
