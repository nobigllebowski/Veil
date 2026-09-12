using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Veil.Application.Abstractions.Security;
using Veil.Application.Options;
using Veil.Domain.Users;
using Veil.Infrastructure.Options;
using Veil.Infrastructure.Persistence.Interceptors;
using Veil.Infrastructure.Security;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Veil.Infrastructure.Tests;

internal static class TestOptions
{
    public static IOptions<SecurityOptions> Security(Action<SecurityOptions>? configure = null)
    {
        var options = new SecurityOptions
        {
            FieldEncryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            BlindIndexKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            IpHashSalt = "unit-test-salt-value",
            Argon2 = new Argon2Options { MemoryKiB = 8 * 1024, Iterations = 1, Parallelism = 1 },
        };
        configure?.Invoke(options);
        return MsOptions.Create(options);
    }
}

public class Argon2PasswordHasherTests
{
    private readonly Argon2PasswordHasher _hasher = new(TestOptions.Security());

    [Fact]
    public void Produces_phc_strings_and_verifies()
    {
        var hash = _hasher.Hash("correct-horse-battery-staple");

        hash.ShouldStartWith("$argon2id$v=19$m=8192,t=1,p=1$");
        _hasher.Verify("correct-horse-battery-staple", hash).ShouldBe(PasswordVerification.Success);
        _hasher.Verify("Correct-horse-battery-staple", hash).ShouldBe(PasswordVerification.Failed);
        _hasher.Hash("correct-horse-battery-staple").ShouldNotBe(hash, "salts must be random");
    }

    [Fact]
    public void Flags_hashes_made_with_weaker_parameters_for_rehash()
    {
        var weaker = new Argon2PasswordHasher(TestOptions.Security(o => o.Argon2.Iterations = 1));
        var stronger = new Argon2PasswordHasher(TestOptions.Security(o => o.Argon2.Iterations = 2));

        var hash = weaker.Hash("correct-horse-battery-staple");

        stronger.Verify("correct-horse-battery-staple", hash).ShouldBe(PasswordVerification.SuccessRehashNeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData("plaintext")]
    [InlineData("$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA")]
    [InlineData("$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$!!!$aGFzaA")]
    public void Malformed_hashes_never_verify(string hash) =>
        _hasher.Verify("anything-at-all", hash).ShouldBe(PasswordVerification.Failed);

    [Fact]
    public void Timing_mitigation_runs_a_real_verification() =>
        Should.NotThrow(() => _hasher.MitigateTiming("whatever"));
}

public class AesGcmFieldEncryptorTests
{
    [Fact]
    public void Round_trips_and_binds_purpose()
    {
        using var encryptor = new AesGcmFieldEncryptor(TestOptions.Security());
        var ciphertext = encryptor.Protect("alice@example.com", "users.email");

        ciphertext.ShouldStartWith("v1.");
        encryptor.Unprotect(ciphertext, "users.email").ShouldBe("alice@example.com");
        Should.Throw<CryptographicException>(() => encryptor.Unprotect(ciphertext, "users.totp_secret"));
        encryptor.Protect("alice@example.com", "users.email").ShouldNotBe(ciphertext, "nonces must be random");
    }

    [Fact]
    public void Rejects_wrong_key_and_garbage()
    {
        using var a = new AesGcmFieldEncryptor(TestOptions.Security());
        using var b = new AesGcmFieldEncryptor(TestOptions.Security());
        var ciphertext = a.Protect("secret", "p");

        Should.Throw<CryptographicException>(() => b.Unprotect(ciphertext, "p"));
        Should.Throw<CryptographicException>(() => a.Unprotect("v9.abc", "p"));
        Should.Throw<CryptographicException>(() => a.Unprotect("v1.AAAA", "p"));
    }

    [Fact]
    public void Requires_a_32_byte_key()
    {
        Should.Throw<InvalidOperationException>(() => new AesGcmFieldEncryptor(TestOptions.Security(o => o.FieldEncryptionKey = Convert.ToBase64String(new byte[16]))));
        Should.Throw<InvalidOperationException>(() => new AesGcmFieldEncryptor(TestOptions.Security(o => o.FieldEncryptionKey = "not base64!")));
    }
}

public class HmacBlindIndexerTests
{
    [Fact]
    public void Is_deterministic_per_key()
    {
        var options = TestOptions.Security();
        using var a = new HmacBlindIndexer(options);
        using var b = new HmacBlindIndexer(TestOptions.Security());

        a.Compute("alice@example.com").ShouldBe(a.Compute("alice@example.com"));
        a.Compute("alice@example.com").ShouldNotBe(a.Compute("bob@example.com"));
        a.Compute("alice@example.com").ShouldNotBe(b.Compute("alice@example.com"));
    }
}

public class RefreshTokenGeneratorTests
{
    [Fact]
    public void Generates_high_entropy_tokens_with_matching_hashes()
    {
        var generator = new RefreshTokenGenerator();
        var (token, hash) = generator.Generate();

        token.Length.ShouldBeGreaterThanOrEqualTo(43);
        generator.Hash(token).ShouldBe(hash);
        generator.Generate().Token.ShouldNotBe(token);
    }
}

public class JwtAccessTokenIssuerTests
{
    private static SigningKeyProvider NewKeys(bool development, string? pem = null)
    {
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(development ? Environments.Development : Environments.Production);
        return new SigningKeyProvider(TestOptions.Security(o => o.JwtSigningKeyPem = pem), env, NullLogger<SigningKeyProvider>.Instance);
    }

    [Fact]
    public async Task Issues_es256_tokens_that_validate_against_the_public_jwk()
    {
        using var keys = NewKeys(development: true);
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var options = MsOptions.Create(new AuthOptions());
        var issuer = new JwtAccessTokenIssuer(keys, options, time);
        var user = User.Register(Username.Create("alice").Value, null, EmailAddress.Create("a@b.co").Value, "i", "h", time.GetUtcNow()).Value;
        user.ChangePassword("h2");
        var deviceId = Guid.NewGuid();

        var token = issuer.Issue(user, deviceId);

        token.ExpiresAt.ShouldBe(time.GetUtcNow().AddMinutes(10));
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(token.Token);
        jwt.Alg.ShouldBe("ES256");
        jwt.Kid.ShouldBe("veil-es256-1");
        jwt.Typ.ShouldBe("at+jwt");
        jwt.GetClaim("sub").Value.ShouldBe(user.Id.ToString());
        jwt.GetClaim(VeilClaims.DeviceId).Value.ShouldBe(deviceId.ToString());
        jwt.GetClaim(VeilClaims.SecurityStamp).Value.ShouldBe("1");
        jwt.Claims.ShouldNotContain(c => c.Type == "email");

        var validation = await handler.ValidateTokenAsync(token.Token, new TokenValidationParameters
        {
            ValidIssuer = options.Value.Issuer,
            ValidAudience = options.Value.Audience,
            IssuerSigningKey = JsonWebKey.Create(System.Text.Json.JsonSerializer.Serialize(keys.PublicJwk)),
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidTypes = ["at+jwt"],
            LifetimeValidator = (_, _, _, _) => true,
        });

        validation.IsValid.ShouldBeTrue(validation.Exception?.ToString());
    }

    [Fact]
    public void Production_requires_a_configured_key_and_accepts_pem()
    {
        Should.Throw<InvalidOperationException>(() => NewKeys(development: false));

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var keys = NewKeys(development: false, ecdsa.ExportPkcs8PrivateKeyPem());
        keys.PublicJwk.Crv.ShouldBe("P-256");

        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Should.Throw<InvalidOperationException>(() => NewKeys(development: false, wrongCurve.ExportPkcs8PrivateKeyPem()));
    }
}

public class AuditChainHashTests
{
    [Fact]
    public void Hash_is_deterministic_and_sensitive_to_every_field()
    {
        var at = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var actor = Guid.NewGuid();
        var baseline = AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at, "a", actor, "ip", "{}");

        AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at, "a", actor, "ip", "{}").ShouldBe(baseline);
        AuditChainInterceptor.ComputeHash("ff", at, "a", actor, "ip", "{}").ShouldNotBe(baseline);
        AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at.AddSeconds(1), "a", actor, "ip", "{}").ShouldNotBe(baseline);
        AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at, "b", actor, "ip", "{}").ShouldNotBe(baseline);
        AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at, "a", null, "ip", "{}").ShouldNotBe(baseline);
        AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at, "a", actor, null, "{}").ShouldNotBe(baseline);
        AuditChainInterceptor.ComputeHash(AuditChainInterceptor.GenesisHash, at, "a", actor, "ip", null).ShouldNotBe(baseline);
        baseline.Length.ShouldBe(64);
    }
}
