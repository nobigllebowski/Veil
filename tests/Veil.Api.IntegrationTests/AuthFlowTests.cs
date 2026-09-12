using System.Net;
using System.Net.Http.Json;
using OtpNet;
using Veil.Client.Sdk;
using Veil.Contracts;
using Veil.Infrastructure.Security;

namespace Veil.Api.IntegrationTests;

[Collection(ApiCollection.Name)]
public class AuthFlowTests(VeilApiFactory factory)
{
    [Fact]
    public async Task Register_login_and_read_profile()
    {
        using var persona = await TestPersona.CreateAsync(factory, "auth", registerDevice: false);

        var me = await persona.Api.GetMeAsync();

        me.Username.ShouldBe(persona.Username);
        me.TotpEnabled.ShouldBeFalse();
        persona.Api.DeviceId.ShouldBeNull();
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_look_identical()
    {
        using var persona = await TestPersona.CreateAsync(factory, "auth", registerDevice: false);
        var anonymous = factory.CreateApiClient();

        var wrongPassword = await Should.ThrowAsync<VeilApiException>(() => anonymous.LoginAsync(persona.Username, "definitely-not-the-password"));
        var unknownUser = await Should.ThrowAsync<VeilApiException>(() => anonymous.LoginAsync("nobody" + Guid.NewGuid().ToString("N")[..8], "definitely-not-the-password"));

        wrongPassword.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        unknownUser.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        wrongPassword.Code.ShouldBe("auth.invalid_credentials");
        unknownUser.Code.ShouldBe("auth.invalid_credentials");
    }

    [Fact]
    public async Task Refresh_rotates_and_reuse_kills_the_family()
    {
        using var persona = await TestPersona.CreateAsync(factory, "auth", registerDevice: false);
        var first = persona.Api.RefreshToken!;

        var rotated = await persona.Api.RefreshAsync();
        rotated.RefreshToken.ShouldNotBe(first);

        // Replay the consumed token: theft detected, the whole family (including the rotated token) dies.
        var replay = factory.CreateApiClient();
        replay.UseRefreshToken(first, null);
        var reuse = await Should.ThrowAsync<VeilApiException>(() => replay.RefreshAsync());
        reuse.Code.ShouldBe("auth.refresh_token_reuse");

        var victim = factory.CreateApiClient();
        victim.UseRefreshToken(rotated.RefreshToken, null);
        var revoked = await Should.ThrowAsync<VeilApiException>(() => victim.RefreshAsync());
        revoked.Code.ShouldBe("auth.invalid_refresh_token");
    }

    [Fact]
    public async Task Logout_everywhere_invalidates_live_access_tokens_immediately()
    {
        using var persona = await TestPersona.CreateAsync(factory, "auth", registerDevice: false);
        var accessToken = persona.Api.AccessToken!;
        var refreshToken = persona.Api.RefreshToken!;

        await persona.Api.LogoutEverywhereAsync();

        using var raw = factory.CreateClient();
        raw.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);
        var response = await raw.GetAsync(new Uri("/api/v1/users/me", UriKind.Relative));
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var refresh = await raw.PostAsJsonAsync(new Uri("/api/v1/auth/refresh", UriKind.Relative), new RefreshRequest(refreshToken));
        refresh.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Password_change_revokes_other_sessions_and_returns_new_tokens()
    {
        using var persona = await TestPersona.CreateAsync(factory, "auth", registerDevice: false);
        var other = factory.CreateApiClient();
        await other.LoginAsync(persona.Username, TestPersona.Password);

        var tokens = await persona.Api.ChangePasswordAsync(TestPersona.Password, "an-entirely-new-passphrase");
        tokens.AccessToken.ShouldNotBeNullOrEmpty();

        (await persona.Api.GetMeAsync()).Username.ShouldBe(persona.Username);
        var stale = await Should.ThrowAsync<VeilApiException>(() => other.GetMeAsync());
        stale.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var relogin = factory.CreateApiClient();
        await Should.ThrowAsync<VeilApiException>(() => relogin.LoginAsync(persona.Username, TestPersona.Password));
        (await relogin.LoginAsync(persona.Username, "an-entirely-new-passphrase")).AccessToken.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task Totp_enrollment_enforces_second_factor_and_blocks_code_replay()
    {
        using var persona = await TestPersona.CreateAsync(factory, "totp", registerDevice: false);

        var enrollment = await persona.Api.BeginTotpEnrollmentAsync();
        enrollment.OtpAuthUri.ShouldStartWith("otpauth://totp/Veil:");
        var totp = new Totp(Base32Encoding.ToBytes(enrollment.Secret));

        await persona.Api.ConfirmTotpAsync(totp.ComputeTotp());
        (await persona.Api.GetMeAsync()).TotpEnabled.ShouldBeTrue();

        var fresh = factory.CreateApiClient();
        var required = await Should.ThrowAsync<VeilApiException>(() => fresh.LoginAsync(persona.Username, TestPersona.Password));
        required.Code.ShouldBe("auth.totp_required");

        // The confirmation already consumed the current time-step; a replayed code must be refused.
        var replay = await Should.ThrowAsync<VeilApiException>(() => fresh.LoginAsync(persona.Username, TestPersona.Password, totp.ComputeTotp()));
        replay.Code.ShouldBe("auth.totp_invalid");

        // A code for the next time-step is inside the verification window and still unused.
        var nextStep = totp.ComputeTotp(DateTime.UtcNow.AddSeconds(30));
        (await fresh.LoginAsync(persona.Username, TestPersona.Password, nextStep)).AccessToken.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task Account_locks_after_repeated_failures()
    {
        using var persona = await TestPersona.CreateAsync(factory, "lock", registerDevice: false);
        var attacker = factory.CreateApiClient();

        VeilApiException? last = null;
        for (var i = 0; i < 5; i++)
        {
            last = await Should.ThrowAsync<VeilApiException>(() => attacker.LoginAsync(persona.Username, $"guess-number-{i}-wrong"));
        }

        last!.Code.ShouldBe("auth.account_locked");
        var locked = await Should.ThrowAsync<VeilApiException>(() => attacker.LoginAsync(persona.Username, TestPersona.Password));
        locked.Code.ShouldBe("auth.account_locked");
    }

    [Fact]
    public async Task Audit_chain_stays_intact_across_concurrent_writes()
    {
        var personas = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => TestPersona.CreateAsync(factory, "audit", registerDevice: false)));
        await Task.WhenAll(personas.Select(p => p.Api.RefreshAsync()));

        var report = await factory.GetService<AuditChainVerifier>().VerifyAsync(CancellationToken.None);

        report.IsIntact.ShouldBeTrue($"chain broken at {report.FirstBrokenSequence}");
        report.CheckedRows.ShouldBeGreaterThanOrEqualTo(16);
        foreach (var p in personas)
        {
            p.Dispose();
        }
    }

    [Fact]
    public async Task Jwks_publishes_the_es256_verification_key()
    {
        using var raw = factory.CreateClient();
        var jwks = await raw.GetFromJsonAsync<System.Text.Json.JsonElement>(new Uri("/.well-known/jwks.json", UriKind.Relative));

        var key = jwks.GetProperty("keys")[0];
        key.GetProperty("kty").GetString().ShouldBe("EC");
        key.GetProperty("crv").GetString().ShouldBe("P-256");
        key.GetProperty("alg").GetString().ShouldBe("ES256");
        key.TryGetProperty("d", out _).ShouldBeFalse("private scalar must never be published");
    }
}
