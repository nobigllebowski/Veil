using Veil.Crypto.Keys;
using Veil.Domain.Auth;
using Veil.Domain.Common;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;
using Veil.Domain.Users;

namespace Veil.Domain.Tests;

public class UsernameTests
{
    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("  Alice.Smith_01 ", "alice.smith_01")]
    [InlineData("abc", "abc")]
    public void Normalises_valid_handles(string raw, string expected)
    {
        var result = Username.Create(raw);
        result.IsSuccess.ShouldBeTrue();
        result.Value.Value.ShouldBe(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ab")]
    [InlineData(".alice")]
    [InlineData("alice.")]
    [InlineData("al ice")]
    [InlineData("алиса")]
    [InlineData("a-b")]
    public void Rejects_invalid_handles(string raw)
    {
        var result = Username.Create(raw);
        result.IsFailure.ShouldBeTrue();
        result.Error.ShouldBe(UserErrors.UsernameInvalid);
    }

    [Fact]
    public void Rejects_too_long_handles() =>
        Username.Create(new string('a', Username.MaxLength + 1)).IsFailure.ShouldBeTrue();
}

public class EmailAddressTests
{
    [Fact]
    public void Normalises_and_validates()
    {
        EmailAddress.Create("  Alice@Example.COM ").Value.Value.ShouldBe("alice@example.com");
        EmailAddress.Create("not-an-email").IsFailure.ShouldBeTrue();
        EmailAddress.Create("").IsFailure.ShouldBeTrue();
        EmailAddress.Create("a@b.c " + new string('x', 300)).IsFailure.ShouldBeTrue();
    }
}

public class ResultTests
{
    [Fact]
    public void Success_and_failure_semantics()
    {
        var ok = Result.Success(42);
        ok.IsSuccess.ShouldBeTrue();
        ok.Value.ShouldBe(42);
        ok.Map(v => v * 2).Value.ShouldBe(84);

        Result<int> failed = Error.NotFound("x", "missing");
        failed.IsFailure.ShouldBeTrue();
        Should.Throw<InvalidOperationException>(() => failed.Value);
        failed.Match(_ => "ok", e => e.Code).ShouldBe("x");
    }

    [Fact]
    public void Invalid_combinations_are_rejected()
    {
        Should.Throw<ArgumentException>(() => Result.Failure(Error.None));
    }
}

public class UserTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static User NewUser() =>
        User.Register(Username.Create("alice").Value, null, EmailAddress.Create("alice@example.com").Value, "idx", "hash", Now).Value;

    [Fact]
    public void Register_defaults_display_name_and_raises_event()
    {
        var user = NewUser();
        user.DisplayName.ShouldBe("alice");
        user.DomainEvents.ShouldHaveSingleItem().ShouldBeOfType<UserRegistered>();
        user.SecurityStamp.ShouldBe(0);
    }

    [Fact]
    public void Locks_out_after_max_failed_attempts_and_unlocks_after_duration()
    {
        var user = NewUser();
        user.RecordFailedLogin(Now, 3, TimeSpan.FromMinutes(15)).ShouldBeFalse();
        user.RecordFailedLogin(Now, 3, TimeSpan.FromMinutes(15)).ShouldBeFalse();
        user.RecordFailedLogin(Now, 3, TimeSpan.FromMinutes(15)).ShouldBeTrue();

        user.IsLockedOut(Now.AddMinutes(14)).ShouldBeTrue();
        user.IsLockedOut(Now.AddMinutes(16)).ShouldBeFalse();
        user.DomainEvents.OfType<UserLockedOut>().ShouldHaveSingleItem();

        user.RecordSuccessfulLogin(Now.AddMinutes(16));
        user.FailedLoginAttempts.ShouldBe(0);
        user.LastLoginAt.ShouldBe(Now.AddMinutes(16));
    }

    [Fact]
    public void Password_change_bumps_security_stamp_but_rehash_does_not()
    {
        var user = NewUser();
        user.RehashPassword("hash2");
        user.SecurityStamp.ShouldBe(0);
        user.ChangePassword("hash3");
        user.SecurityStamp.ShouldBe(1);
        user.InvalidateSessions();
        user.SecurityStamp.ShouldBe(2);
    }

    [Fact]
    public void Totp_lifecycle()
    {
        var user = NewUser();
        user.ConfirmTotpEnrollment().Error.ShouldBe(UserErrors.TotpNotPending);
        user.BeginTotpEnrollment("secret").IsSuccess.ShouldBeTrue();
        user.TotpEnabled.ShouldBeFalse();
        user.ConfirmTotpEnrollment().IsSuccess.ShouldBeTrue();
        user.TotpEnabled.ShouldBeTrue();
        user.BeginTotpEnrollment("again").Error.ShouldBe(UserErrors.TotpAlreadyEnabled);
        user.DisableTotp().IsSuccess.ShouldBeTrue();
        user.TotpSecret.ShouldBeNull();
        user.DisableTotp().Error.ShouldBe(UserErrors.TotpNotEnabled);
    }
}

public class DeviceTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Registers_with_a_valid_bundle()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var device = Device.Register(Guid.NewGuid(), "Laptop", keys.ExportPublicKeys(), 0, Now);

        device.IsSuccess.ShouldBeTrue();
        device.Value.IsActive.ShouldBeTrue();
        device.Value.Identity.ShouldBe(keys.Identity.Public);
        device.Value.DomainEvents.ShouldHaveSingleItem().ShouldBeOfType<DeviceRegistered>();
    }

    [Fact]
    public void Rejects_bundle_with_forged_signature()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var other = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var forged = keys.ExportPublicKeys() with { SignedPreKey = other.CurrentSignedPreKey.KeyPair.PublicKey };

        Device.Register(Guid.NewGuid(), "Laptop", forged, 0, Now).Error.ShouldBe(DeviceErrors.InvalidSignature);
    }

    [Fact]
    public void Rejects_bundle_with_wrong_lengths()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var broken = keys.ExportPublicKeys() with { KemPreKey = new byte[10] };
        Device.Register(Guid.NewGuid(), "Laptop", broken, 0, Now).Error.ShouldBe(DeviceErrors.InvalidKeyMaterial);
    }

    [Fact]
    public void Enforces_device_limit_and_name()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        Device.Register(Guid.NewGuid(), "Laptop", keys.ExportPublicKeys(), Device.MaxDevicesPerUser, Now).Error.ShouldBe(DeviceErrors.TooManyDevices);
        Device.Register(Guid.NewGuid(), "  ", keys.ExportPublicKeys(), 0, Now).Error.ShouldBe(DeviceErrors.NameInvalid);
    }

    [Fact]
    public void Pre_key_rotation_requires_increasing_ids_and_valid_signatures()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var device = Device.Register(Guid.NewGuid(), "Laptop", keys.ExportPublicKeys(), 0, Now).Value;

        var rotated = keys.RotateSignedPreKey();
        device.RotateSignedPreKey(rotated.Id, rotated.KeyPair.PublicKey, rotated.Signature, Now).IsSuccess.ShouldBeTrue();
        device.RotateSignedPreKey(rotated.Id, rotated.KeyPair.PublicKey, rotated.Signature, Now).Error.ShouldBe(DeviceErrors.PreKeyIdNotIncreasing);
        device.RotateSignedPreKey(rotated.Id + 1, rotated.KeyPair.PublicKey, rotated.Signature, Now).Error.ShouldBe(DeviceErrors.InvalidSignature);

        var kem = keys.RotateKemPreKey();
        device.RotateKemPreKey(kem.Id, kem.KeyPair.PublicKey, kem.Signature, Now).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void One_time_pre_key_uploads_are_bounded()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var device = Device.Register(Guid.NewGuid(), "Laptop", keys.ExportPublicKeys(), 0, Now).Value;
        var batch = keys.GenerateOneTimePreKeys(5).Select(k => (k.Id, k.KeyPair.PublicKey)).ToList();

        device.AddOneTimePreKeys(batch, 0, Now).IsSuccess.ShouldBeTrue();
        device.OneTimePreKeys.Count.ShouldBe(5);
        device.AddOneTimePreKeys(batch, Device.MaxStoredOneTimePreKeys, Now).Error.ShouldBe(DeviceErrors.TooManyOneTimePreKeys);
        device.AddOneTimePreKeys([(99u, new byte[3])], 0, Now).Error.ShouldBe(DeviceErrors.InvalidKeyMaterial);
    }

    [Fact]
    public void Revoke_is_idempotent_and_drops_pre_keys()
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var device = Device.Register(Guid.NewGuid(), "Laptop", keys.ExportPublicKeys(), 0, Now).Value;
        device.AddOneTimePreKeys(keys.GenerateOneTimePreKeys(2).Select(k => (k.Id, k.KeyPair.PublicKey)).ToList(), 0, Now);

        device.Revoke(Now);
        device.Revoke(Now.AddMinutes(1));

        device.IsActive.ShouldBeFalse();
        device.RevokedAt.ShouldBe(Now);
        device.OneTimePreKeys.ShouldBeEmpty();
        device.DomainEvents.OfType<DeviceRevoked>().Count().ShouldBe(1);
    }
}

public class RefreshTokenTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Lifecycle()
    {
        var token = RefreshToken.Issue(Guid.NewGuid(), null, "hash", Guid.NewGuid(), Now, TimeSpan.FromDays(30), "ip");
        token.IsActive(Now).ShouldBeTrue();
        token.IsActive(Now.AddDays(31)).ShouldBeFalse();

        token.MarkUsed(Now.AddMinutes(1));
        token.MarkUsed(Now.AddMinutes(2));
        token.UsedAt.ShouldBe(Now.AddMinutes(1));
        token.IsActive(Now.AddMinutes(3)).ShouldBeFalse();

        token.Revoke(Now.AddMinutes(4));
        token.IsRevoked.ShouldBeTrue();
    }
}

public class ConversationTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Direct_key_is_order_independent()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        Conversation.ComputeDirectKey(a, b).ShouldBe(Conversation.ComputeDirectKey(b, a));
    }

    [Fact]
    public void Direct_conversation_has_two_owners_and_rejects_self()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var direct = Conversation.CreateDirect(a, b, Now).Value;

        direct.Members.Count.ShouldBe(2);
        direct.RoleOf(a).ShouldBe(MemberRole.Owner);
        direct.RoleOf(b).ShouldBe(MemberRole.Owner);
        direct.AddMember(a, Guid.NewGuid(), Now).Error.ShouldBe(ConversationErrors.NotAGroup);
        Conversation.CreateDirect(a, a, Now).Error.ShouldBe(ConversationErrors.CannotChatWithSelf);
    }

    [Fact]
    public void Group_membership_rules()
    {
        var owner = Guid.NewGuid();
        var member = Guid.NewGuid();
        var stranger = Guid.NewGuid();
        var group = Conversation.CreateGroup(owner, "  Team  ", [member, member, owner], Now).Value;

        group.Title.ShouldBe("Team");
        group.Members.Count.ShouldBe(2);

        group.AddMember(member, stranger, Now).Error.ShouldBe(ConversationErrors.InsufficientRole);
        group.AddMember(owner, member, Now).Error.ShouldBe(ConversationErrors.AlreadyMember);
        group.AddMember(owner, stranger, Now).IsSuccess.ShouldBeTrue();

        group.RemoveMember(member, stranger, Now).Error.ShouldBe(ConversationErrors.InsufficientRole);
        group.RemoveMember(stranger, stranger, Now).IsSuccess.ShouldBeTrue(); // leaving is always allowed
        group.RemoveMember(owner, owner, Now).Error.ShouldBe(ConversationErrors.LastOwner);
        group.RemoveMember(owner, member, Now).IsSuccess.ShouldBeTrue();
        group.RemoveMember(owner, owner, Now).IsSuccess.ShouldBeTrue(); // sole remaining member may leave

        group.DomainEvents.OfType<ConversationCreated>().ShouldHaveSingleItem();
        group.DomainEvents.OfType<MemberAdded>().Count().ShouldBe(1);
        group.DomainEvents.OfType<MemberRemoved>().Count().ShouldBe(3);
    }

    [Fact]
    public void Group_requires_title_and_bounds_members()
    {
        Conversation.CreateGroup(Guid.NewGuid(), " ", [], Now).Error.ShouldBe(ConversationErrors.TitleInvalid);
        var tooMany = Enumerable.Range(0, Conversation.MaxMembers).Select(_ => Guid.NewGuid()).ToList();
        Conversation.CreateGroup(Guid.NewGuid(), "big", tooMany, Now).Error.ShouldBe(ConversationErrors.TooManyMembers);
    }

    [Fact]
    public void Rename_is_restricted_to_admins()
    {
        var owner = Guid.NewGuid();
        var member = Guid.NewGuid();
        var group = Conversation.CreateGroup(owner, "Team", [member], Now).Value;
        group.Rename(member, "Hacked").Error.ShouldBe(ConversationErrors.InsufficientRole);
        group.Rename(owner, "Renamed").IsSuccess.ShouldBeTrue();
        group.Title.ShouldBe("Renamed");
    }
}

public class MessageEnvelopeTests
{
    [Fact]
    public void Validates_payload_size_and_sets_expiry()
    {
        var now = DateTimeOffset.UtcNow;
        var ok = MessageEnvelope.Create(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), new byte[100], now, TimeSpan.FromDays(7));
        ok.IsSuccess.ShouldBeTrue();
        ok.Value.ExpiresAt.ShouldBe(now.AddDays(7));
        ok.Value.DomainEvents.ShouldHaveSingleItem().ShouldBeOfType<EnvelopeStored>();

        MessageEnvelope.Create(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), [], now, TimeSpan.FromDays(7)).Error.ShouldBe(MessageErrors.PayloadInvalid);
        MessageEnvelope.Create(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), new byte[MessageEnvelope.MaxPayloadBytes + 1], now, TimeSpan.FromDays(7)).Error.ShouldBe(MessageErrors.PayloadInvalid);
    }
}
