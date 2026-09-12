using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Features.Auth;
using Veil.Application.Options;
using Veil.Domain.Auth;
using Veil.Domain.Devices;
using Veil.Domain.Users;

namespace Veil.Application.Tests;

/// <summary>Shared fakes for auth handler tests.</summary>
internal sealed class AuthFixture
{
    public readonly IUserRepository Users = Substitute.For<IUserRepository>();
    public readonly IDeviceRepository Devices = Substitute.For<IDeviceRepository>();
    public readonly IRefreshTokenRepository RefreshTokens = Substitute.For<IRefreshTokenRepository>();
    public readonly IPasswordHasher Hasher = Substitute.For<IPasswordHasher>();
    public readonly ITotpProvider Totp = Substitute.For<ITotpProvider>();
    public readonly IAccessTokenIssuer AccessTokens = Substitute.For<IAccessTokenIssuer>();
    public readonly IRefreshTokenGenerator Generator = Substitute.For<IRefreshTokenGenerator>();
    public readonly IClientContext Client = Substitute.For<IClientContext>();
    public readonly IAuditor Auditor = Substitute.For<IAuditor>();
    public readonly IUnitOfWork UnitOfWork = Substitute.For<IUnitOfWork>();
    public readonly FakeTimeProvider Time = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    public readonly IOptions<AuthOptions> Options = Microsoft.Extensions.Options.Options.Create(new AuthOptions { MaxFailedLoginAttempts = 3, LockoutDuration = TimeSpan.FromMinutes(15) });

    public AuthFixture()
    {
        AccessTokens.Issue(Arg.Any<User>(), Arg.Any<Guid?>()).Returns(ci => new AccessToken("access", Time.GetUtcNow().AddMinutes(10)));
        Generator.Generate().Returns(("refresh", "refresh-hash"));
        Generator.Hash(Arg.Any<string>()).Returns(ci => ci.Arg<string>() + "-hash");
        Client.IpHash.Returns("iphash");
    }

    public TokenIssuance Issuance => new(AccessTokens, Generator, RefreshTokens, Client, Time, Options);

    public User Alice(string hash = "hash")
    {
        var user = User.Register(Username.Create("alice").Value, "Alice", EmailAddress.Create("alice@example.com").Value, "idx", hash, Time.GetUtcNow()).Value;
        Users.GetByUsernameAsync(Arg.Is<Username>(u => u.Value == "alice"), Arg.Any<CancellationToken>()).Returns(user);
        Users.GetByIdAsync(user.Id, Arg.Any<CancellationToken>()).Returns(user);
        return user;
    }
}

public class LoginCommandHandlerTests
{
    private readonly AuthFixture _f = new();

    private LoginCommandHandler Handler => new(_f.Users, _f.Devices, _f.Hasher, _f.Totp, _f.Issuance, _f.Auditor, _f.UnitOfWork, _f.Time, _f.Options);

    [Fact]
    public async Task Unknown_user_gets_generic_error_and_timing_mitigation()
    {
        var result = await Handler.Handle(new LoginCommand("nobody", "password-password", null, null), CancellationToken.None);

        result.Error.ShouldBe(AuthErrors.InvalidCredentials);
        _f.Hasher.Received(1).MitigateTiming("password-password");
        _f.Hasher.DidNotReceive().Verify(Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Wrong_password_counts_towards_lockout()
    {
        var alice = _f.Alice();
        _f.Hasher.Verify(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerification.Failed);

        (await Handler.Handle(new LoginCommand("alice", "bad-password-1", null, null), CancellationToken.None)).Error.ShouldBe(AuthErrors.InvalidCredentials);
        (await Handler.Handle(new LoginCommand("alice", "bad-password-2", null, null), CancellationToken.None)).Error.ShouldBe(AuthErrors.InvalidCredentials);
        (await Handler.Handle(new LoginCommand("alice", "bad-password-3", null, null), CancellationToken.None)).Error.ShouldBe(AuthErrors.AccountLocked);

        alice.IsLockedOut(_f.Time.GetUtcNow()).ShouldBeTrue();
        _f.Hasher.Verify(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerification.Success);
        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", null, null), CancellationToken.None)).Error.ShouldBe(AuthErrors.AccountLocked);

        _f.Time.Advance(TimeSpan.FromMinutes(16));
        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", null, null), CancellationToken.None)).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public async Task Successful_login_issues_tokens_and_stores_refresh_hash()
    {
        var alice = _f.Alice();
        _f.Hasher.Verify("correct-password-now", "hash").Returns(PasswordVerification.Success);

        var result = await Handler.Handle(new LoginCommand("alice", "correct-password-now", null, null), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        result.Value.AccessToken.ShouldBe("access");
        result.Value.RefreshToken.ShouldBe("refresh");
        result.Value.DeviceId.ShouldBeNull();
        _f.RefreshTokens.Received(1).Add(Arg.Is<RefreshToken>(t => t.TokenHash == "refresh-hash" && t.UserId == alice.Id));
        await _f.UnitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Outdated_hash_is_upgraded_on_login()
    {
        var alice = _f.Alice("old-hash");
        _f.Hasher.Verify("correct-password-now", "old-hash").Returns(PasswordVerification.SuccessRehashNeeded);
        _f.Hasher.Hash("correct-password-now").Returns("new-hash");

        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", null, null), CancellationToken.None)).IsSuccess.ShouldBeTrue();

        alice.PasswordHash.ShouldBe("new-hash");
    }

    [Fact]
    public async Task Totp_is_enforced_when_enabled()
    {
        var alice = _f.Alice();
        alice.BeginTotpEnrollment("secret");
        alice.ConfirmTotpEnrollment();
        _f.Hasher.Verify(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerification.Success);
        _f.Totp.VerifyAsync(alice.Id, "secret", "123456", Arg.Any<CancellationToken>()).Returns(true);
        _f.Totp.VerifyAsync(alice.Id, "secret", "000000", Arg.Any<CancellationToken>()).Returns(false);

        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", null, null), CancellationToken.None)).Error.ShouldBe(AuthErrors.TotpRequired);
        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", "000000", null), CancellationToken.None)).Error.ShouldBe(AuthErrors.TotpInvalid);
        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", "123456", null), CancellationToken.None)).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public async Task Device_bound_login_requires_an_active_device_of_the_user()
    {
        var alice = _f.Alice();
        _f.Hasher.Verify(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerification.Success);
        var deviceId = Guid.NewGuid();
        _f.Devices.GetActiveAsync(alice.Id, deviceId, Arg.Any<CancellationToken>()).Returns((Device?)null);

        (await Handler.Handle(new LoginCommand("alice", "correct-password-now", null, deviceId), CancellationToken.None)).Error.ShouldBe(DeviceErrors.NotFound);
    }
}

public class RefreshSessionCommandHandlerTests
{
    private readonly AuthFixture _f = new();

    private RefreshSessionCommandHandler Handler => new(_f.RefreshTokens, _f.Generator, _f.Users, _f.Devices, _f.Issuance, _f.Auditor, _f.UnitOfWork, _f.Time);

    [Fact]
    public async Task Unknown_token_is_rejected()
    {
        _f.RefreshTokens.GetByHashAsync("nope-hash", Arg.Any<CancellationToken>()).Returns((RefreshToken?)null);
        (await Handler.Handle(new RefreshSessionCommand("nope"), CancellationToken.None)).Error.ShouldBe(AuthErrors.InvalidRefreshToken);
    }

    [Fact]
    public async Task Rotation_marks_old_token_used_and_keeps_the_family()
    {
        var alice = _f.Alice();
        var family = Guid.NewGuid();
        var existing = RefreshToken.Issue(alice.Id, null, "old-hash", family, _f.Time.GetUtcNow(), TimeSpan.FromDays(30), null);
        _f.RefreshTokens.GetByHashAsync("old-hash", Arg.Any<CancellationToken>()).Returns(existing);

        var result = await Handler.Handle(new RefreshSessionCommand("old"), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        existing.IsUsed.ShouldBeTrue();
        _f.RefreshTokens.Received(1).Add(Arg.Is<RefreshToken>(t => t.FamilyId == family && t.TokenHash == "refresh-hash"));
    }

    [Fact]
    public async Task Reuse_revokes_the_whole_family()
    {
        var alice = _f.Alice();
        var family = Guid.NewGuid();
        var used = RefreshToken.Issue(alice.Id, null, "old-hash", family, _f.Time.GetUtcNow(), TimeSpan.FromDays(30), null);
        used.MarkUsed(_f.Time.GetUtcNow());
        _f.RefreshTokens.GetByHashAsync("old-hash", Arg.Any<CancellationToken>()).Returns(used);

        var result = await Handler.Handle(new RefreshSessionCommand("old"), CancellationToken.None);

        result.Error.ShouldBe(AuthErrors.RefreshTokenReuse);
        await _f.RefreshTokens.Received(1).RevokeFamilyAsync(family, Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
        _f.RefreshTokens.DidNotReceive().Add(Arg.Any<RefreshToken>());
    }

    [Fact]
    public async Task Expired_token_is_rejected_without_side_effects()
    {
        var alice = _f.Alice();
        var expired = RefreshToken.Issue(alice.Id, null, "old-hash", Guid.NewGuid(), _f.Time.GetUtcNow().AddDays(-31), TimeSpan.FromDays(30), null);
        _f.RefreshTokens.GetByHashAsync("old-hash", Arg.Any<CancellationToken>()).Returns(expired);

        (await Handler.Handle(new RefreshSessionCommand("old"), CancellationToken.None)).Error.ShouldBe(AuthErrors.InvalidRefreshToken);
        _f.RefreshTokens.DidNotReceive().Add(Arg.Any<RefreshToken>());
    }
}

public class RegisterCommandHandlerTests
{
    private readonly AuthFixture _f = new();
    private readonly IBlindIndexer _indexer = Substitute.For<IBlindIndexer>();

    private RegisterCommandHandler Handler => new(_f.Users, _f.Hasher, _indexer, _f.Auditor, _f.UnitOfWork, _f.Time);

    [Fact]
    public async Task Registers_a_new_user()
    {
        _indexer.Compute("alice@example.com").Returns("idx");
        _f.Hasher.Hash("correct-horse-battery-staple").Returns("hash");

        var result = await Handler.Handle(new RegisterCommand("Alice", "Alice@Example.com", "correct-horse-battery-staple", null), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        result.Value.Username.ShouldBe("alice");
        _f.Users.Received(1).Add(Arg.Is<User>(u => u.EmailBlindIndex == "idx" && u.PasswordHash == "hash"));
    }

    [Fact]
    public async Task Weak_or_username_containing_password_is_rejected()
    {
        (await Handler.Handle(new RegisterCommand("alice", "a@b.co", "password1234", null), CancellationToken.None)).Error.ShouldBe(AuthErrors.PasswordTooWeak);
        (await Handler.Handle(new RegisterCommand("alice", "a@b.co", "alice-is-the-best-user", null), CancellationToken.None)).Error.ShouldBe(AuthErrors.PasswordTooWeak);
    }

    [Fact]
    public async Task Taken_username_is_reported_but_taken_email_is_not_confirmed()
    {
        _f.Users.UsernameExistsAsync(Arg.Is<Username>(u => u.Value == "alice"), Arg.Any<CancellationToken>()).Returns(true);
        (await Handler.Handle(new RegisterCommand("alice", "a@b.co", "correct-horse-battery-staple", null), CancellationToken.None)).Error.ShouldBe(UserErrors.UsernameTaken);

        _indexer.Compute(Arg.Any<string>()).Returns("idx");
        _f.Users.EmailExistsAsync("idx", Arg.Any<CancellationToken>()).Returns(true);
        var result = await Handler.Handle(new RegisterCommand("bob", "a@b.co", "correct-horse-battery-staple", null), CancellationToken.None);
        result.Error.Code.ShouldBe("user.registration_unavailable");
        result.Error.Message.ShouldNotContain("e-mail", Case.Insensitive);
    }
}

public class PasswordPolicyTests
{
    [Theory]
    [InlineData("correct-horse-battery-staple", null, true)]
    [InlineData("short", null, false)]
    [InlineData("password1234", null, false)]
    [InlineData("aaaaaaaaaaaaaaa", null, false)]
    [InlineData("alice-has-a-long-password", "alice", false)]
    [InlineData("совершенно секретный пароль", null, true)]
    public void Evaluates(string password, string? username, bool expected) =>
        PasswordPolicy.IsAcceptable(password, username).ShouldBe(expected);

    [Fact]
    public void Rejects_over_long_passwords() =>
        PasswordPolicy.IsAcceptable(new string('x', 129) + "abc").ShouldBeFalse();
}
