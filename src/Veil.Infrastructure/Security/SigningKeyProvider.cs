using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Veil.Infrastructure.Options;

namespace Veil.Infrastructure.Security;

/// <summary>Holds the ECDSA P-256 key pair used for ES256 access tokens and exposes the public half as a JWK.</summary>
public interface ISigningKeyProvider
{
    ECDsaSecurityKey SigningKey { get; }
    ECDsaSecurityKey ValidationKey { get; }
    JsonWebKey PublicJwk { get; }
}

public sealed class SigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly ECDsa _privateKey;
    private readonly ECDsa _publicKey;

    public SigningKeyProvider(IOptions<SecurityOptions> options, IHostEnvironment environment, ILogger<SigningKeyProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(environment);

        var pem = options.Value.JwtSigningKeyPem;
        if (string.IsNullOrWhiteSpace(pem))
        {
            if (!environment.IsDevelopment())
            {
                throw new InvalidOperationException("Security:JwtSigningKeyPem is required outside Development.");
            }

            logger.LogWarning("No JWT signing key configured; generating an ephemeral ES256 key. Tokens will not survive a restart.");
            _privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }
        else
        {
            _privateKey = ECDsa.Create();
            _privateKey.ImportFromPem(pem);
            if (_privateKey.KeySize != 256)
            {
                throw new InvalidOperationException("The JWT signing key must be an ECDSA P-256 key.");
            }
        }

        _publicKey = ECDsa.Create(_privateKey.ExportParameters(includePrivateParameters: false));
        var keyId = options.Value.JwtSigningKeyId;
        SigningKey = new ECDsaSecurityKey(_privateKey) { KeyId = keyId };
        ValidationKey = new ECDsaSecurityKey(_publicKey) { KeyId = keyId };
        PublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ValidationKey);
        PublicJwk.Use = "sig";
        PublicJwk.Alg = SecurityAlgorithms.EcdsaSha256;
    }

    public ECDsaSecurityKey SigningKey { get; }
    public ECDsaSecurityKey ValidationKey { get; }
    public JsonWebKey PublicJwk { get; }

    public void Dispose()
    {
        _privateKey.Dispose();
        _publicKey.Dispose();
    }
}
