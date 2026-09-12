using System.Text;
using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;
using Veil.Crypto.Protocol;

namespace Veil.Crypto.Tests;

public class PqxdhTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Both_parties_derive_the_same_secret(bool useOneTimePreKey)
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 2);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 2);

        var bundle = TestBundles.From(bob, useOneTimePreKey);

        var initiator = Pqxdh.Initiate(alice.Identity, bundle);
        var responder = Pqxdh.Respond(bob, initiator.Header);

        responder.SharedSecret.ShouldBe(initiator.SharedSecret);
        responder.AssociatedData.ShouldBe(initiator.AssociatedData);
        initiator.SharedSecret.Length.ShouldBe(32);
        initiator.Header.OneTimePreKeyId.HasValue.ShouldBe(useOneTimePreKey);
    }

    [Fact]
    public void One_time_pre_key_cannot_be_used_twice()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 0);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 0);
        var bundle = TestBundles.From(bob, includeOneTimePreKey: true);
        bob.AvailableOneTimePreKeys.ShouldBe(1);

        var initiator = Pqxdh.Initiate(alice.Identity, bundle);
        Pqxdh.Respond(bob, initiator.Header);

        Should.Throw<SessionException>(() => Pqxdh.Respond(bob, initiator.Header));
        bob.AvailableOneTimePreKeys.ShouldBe(0);
    }

    [Fact]
    public void Tampered_signed_pre_key_is_rejected()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var mallory = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);

        var honest = TestBundles.From(bob, includeOneTimePreKey: false);
        var substituted = honest with { SignedPreKey = mallory.CurrentSignedPreKey.KeyPair.PublicKey };

        Should.Throw<InvalidSignatureException>(() => Pqxdh.Initiate(alice.Identity, substituted));
    }

    [Fact]
    public void Tampered_kem_pre_key_is_rejected()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var mallory = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);

        var honest = TestBundles.From(bob, includeOneTimePreKey: false);
        var substituted = honest with { KemPreKey = mallory.CurrentKemPreKey.KeyPair.PublicKey };

        Should.Throw<InvalidSignatureException>(() => Pqxdh.Initiate(alice.Identity, substituted));
    }

    [Fact]
    public void Substituted_identity_dh_key_is_rejected()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var mallory = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);

        var honest = TestBundles.From(bob, includeOneTimePreKey: false);
        var substituted = honest with { Identity = honest.Identity with { DhKey = mallory.Identity.DhKey.PublicKey } };

        Should.Throw<InvalidSignatureException>(() => Pqxdh.Initiate(alice.Identity, substituted));
    }

    [Fact]
    public void Pre_key_header_round_trips_through_encoding()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var initiator = Pqxdh.Initiate(alice.Identity, TestBundles.From(bob, includeOneTimePreKey: true));

        var encoded = initiator.Header.Encode();
        encoded.Length.ShouldBe(PreKeyHeader.EncodedSize);
        var decoded = PreKeyHeader.Decode(encoded);

        decoded.ShouldBeEquivalentTo(initiator.Header);
        Should.Throw<MalformedMessageException>(() => PreKeyHeader.Decode(encoded.AsSpan(1)));
    }
}

public class RatchetSessionTests
{
    private static (RatchetSession Alice, RatchetSession Bob) NewPair()
    {
        var secret = CryptoBytes.Random(32);
        var bobKey = X25519.GenerateKeyPair();
        var ad = CryptoBytes.Random(64);
        return (RatchetSession.InitializeAsInitiator(secret, bobKey.PublicKey, ad), RatchetSession.InitializeAsResponder(secret, bobKey, ad));
    }

    [Fact]
    public void Ping_pong_conversation_round_trips()
    {
        var (alice, bob) = NewPair();

        for (var i = 0; i < 25; i++)
        {
            var toBob = Encoding.UTF8.GetBytes($"alice->bob {i}");
            bob.Decrypt(alice.Encrypt(toBob)).ShouldBe(toBob);

            var toAlice = Encoding.UTF8.GetBytes($"bob->alice {i}");
            alice.Decrypt(bob.Encrypt(toAlice)).ShouldBe(toAlice);
        }

        alice.SkippedKeyCount.ShouldBe(0);
        bob.SkippedKeyCount.ShouldBe(0);
    }

    [Fact]
    public void Responder_cannot_send_before_receiving()
    {
        var (_, bob) = NewPair();
        bob.CanSend.ShouldBeFalse();
        Should.Throw<SessionException>(() => bob.Encrypt("x"u8));
    }

    [Fact]
    public void Out_of_order_delivery_is_handled()
    {
        var (alice, bob) = NewPair();
        var messages = Enumerable.Range(0, 5).Select(i => alice.Encrypt(Encoding.UTF8.GetBytes($"m{i}"))).ToList();

        bob.Decrypt(messages[4]).ShouldBe("m4"u8.ToArray());
        bob.SkippedKeyCount.ShouldBe(4);
        bob.Decrypt(messages[1]).ShouldBe("m1"u8.ToArray());
        bob.Decrypt(messages[0]).ShouldBe("m0"u8.ToArray());
        bob.Decrypt(messages[3]).ShouldBe("m3"u8.ToArray());
        bob.Decrypt(messages[2]).ShouldBe("m2"u8.ToArray());
        bob.SkippedKeyCount.ShouldBe(0);
    }

    [Fact]
    public void Out_of_order_across_ratchet_steps_is_handled()
    {
        var (alice, bob) = NewPair();

        var a0 = alice.Encrypt("a0"u8);
        var a1 = alice.Encrypt("a1"u8);
        bob.Decrypt(a1).ShouldBe("a1"u8.ToArray());

        var b0 = bob.Encrypt("b0"u8);
        alice.Decrypt(b0).ShouldBe("b0"u8.ToArray());

        var a2 = alice.Encrypt("a2"u8); // new sending chain after DH ratchet
        bob.Decrypt(a2).ShouldBe("a2"u8.ToArray());

        // a0 belongs to the previous receiving chain; its key must have been retained.
        bob.Decrypt(a0).ShouldBe("a0"u8.ToArray());
    }

    [Fact]
    public void Replayed_message_is_rejected()
    {
        var (alice, bob) = NewPair();
        var message = alice.Encrypt("once"u8);

        bob.Decrypt(message).ShouldBe("once"u8.ToArray());
        Should.Throw<CryptoException>(() => bob.Decrypt(message));
    }

    [Fact]
    public void Tampered_ciphertext_does_not_desync_the_session()
    {
        var (alice, bob) = NewPair();
        var first = alice.Encrypt("first"u8);
        var tampered = first with { Ciphertext = [.. first.Ciphertext] };
        tampered.Ciphertext[0] ^= 0xFF;

        Should.Throw<DecryptionFailedException>(() => bob.Decrypt(tampered));
        bob.ReceiveCount.ShouldBe(0u);

        bob.Decrypt(first).ShouldBe("first"u8.ToArray());
    }

    [Fact]
    public void Tampered_header_is_rejected()
    {
        var (alice, bob) = NewPair();
        var message = alice.Encrypt("payload"u8);
        var forged = message with { Header = message.Header with { MessageNumber = 7 } };

        Should.Throw<CryptoException>(() => bob.Decrypt(forged));
    }

    [Fact]
    public void Excessive_skip_is_rejected()
    {
        var (alice, bob) = NewPair();
        var message = alice.Encrypt("far"u8);
        var forged = message with { Header = message.Header with { MessageNumber = ProtocolConstants.MaxSkippedMessageKeys + 5 } };

        Should.Throw<SessionException>(() => bob.Decrypt(forged));
    }

    [Fact]
    public void Export_import_preserves_state_mid_conversation()
    {
        var (alice, bob) = NewPair();
        bob.Decrypt(alice.Encrypt("1"u8));
        alice.Decrypt(bob.Encrypt("2"u8));
        var skipped = alice.Encrypt("skipped"u8);
        bob.Decrypt(alice.Encrypt("3"u8));

        var restoredBob = RatchetSession.Import(bob.Export());
        var restoredAlice = RatchetSession.Import(alice.Export());

        restoredBob.Decrypt(skipped).ShouldBe("skipped"u8.ToArray());
        restoredAlice.Decrypt(restoredBob.Encrypt("4"u8)).ShouldBe("4"u8.ToArray());
        restoredBob.Decrypt(restoredAlice.Encrypt("5"u8)).ShouldBe("5"u8.ToArray());
    }

    [Fact]
    public void Exported_state_is_a_copy()
    {
        var (alice, bob) = NewPair();
        var snapshot = alice.Export();
        bob.Decrypt(alice.Encrypt("advance"u8));
        alice.Decrypt(bob.Encrypt("ratchet"u8));

        snapshot.RootKey.ShouldNotBe(alice.Export().RootKey);
        snapshot.RootKey.ShouldNotBe(new byte[32]);
    }

    [Fact]
    public void Ciphertext_is_unique_per_message()
    {
        var (alice, _) = NewPair();
        var first = alice.Encrypt("same"u8);
        var second = alice.Encrypt("same"u8);
        first.Ciphertext.ShouldNotBe(second.Ciphertext);
    }
}

public class PeerSessionTests
{
    [Fact]
    public void Full_flow_over_envelopes()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 3);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 3);

        var aliceSession = PeerSession.Initiate(alice.Identity, TestBundles.From(bob, includeOneTimePreKey: true));
        aliceSession.IsHandshakePending.ShouldBeTrue();

        var first = aliceSession.Encrypt("hi bob"u8);
        var second = aliceSession.Encrypt("still hi"u8);
        Envelope.Decode(first).Type.ShouldBe(EnvelopeType.PreKeyMessage);

        var (bobSession, plaintext) = PeerSession.Respond(bob, Envelope.Decode(first));
        plaintext.ShouldBe("hi bob"u8.ToArray());
        bobSession.Decrypt(second).ShouldBe("still hi"u8.ToArray());
        bobSession.RemoteIdentity.ShouldBe(alice.Identity.Public);

        var reply = bobSession.Encrypt("hi alice"u8);
        Envelope.Decode(reply).Type.ShouldBe(EnvelopeType.Message);
        aliceSession.Decrypt(reply).ShouldBe("hi alice"u8.ToArray());
        aliceSession.IsHandshakePending.ShouldBeFalse();

        var third = aliceSession.Encrypt("no more handshake"u8);
        Envelope.Decode(third).Type.ShouldBe(EnvelopeType.Message);
        bobSession.Decrypt(third).ShouldBe("no more handshake"u8.ToArray());
    }

    [Fact]
    public void Ciphertext_length_hides_plaintext_length()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var session = PeerSession.Initiate(alice.Identity, TestBundles.From(bob, includeOneTimePreKey: false));
        session.Encrypt("a"u8); // clear nothing; just make lengths comparable after handshake header
        var shortMessage = session.Encrypt("a"u8);
        var longerMessage = session.Encrypt(new byte[150]);

        shortMessage.Length.ShouldBe(longerMessage.Length);
    }

    [Fact]
    public void Session_state_round_trips()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        var aliceSession = PeerSession.Initiate(alice.Identity, TestBundles.From(bob, includeOneTimePreKey: true));
        var first = aliceSession.Encrypt("one"u8);
        var (bobSession, _) = PeerSession.Respond(bob, Envelope.Decode(first));

        var restoredAlice = PeerSession.Import(aliceSession.Export());
        var restoredBob = PeerSession.Import(bobSession.Export());

        restoredAlice.IsHandshakePending.ShouldBeTrue();
        restoredBob.InitiatorEphemeralKey.ShouldNotBeNull();
        restoredBob.Decrypt(restoredAlice.Encrypt("two"u8)).ShouldBe("two"u8.ToArray());
        restoredAlice.Decrypt(restoredBob.Encrypt("three"u8)).ShouldBe("three"u8.ToArray());
    }

    [Fact]
    public void Malformed_envelopes_are_rejected()
    {
        Should.Throw<MalformedMessageException>(() => Envelope.Decode([]));
        Should.Throw<MalformedMessageException>(() => Envelope.Decode(new byte[100]));
        var wrongVersion = new byte[100];
        wrongVersion[0] = 0x09;
        wrongVersion[1] = 0x02;
        Should.Throw<MalformedMessageException>(() => Envelope.Decode(wrongVersion));
    }
}

public class SafetyNumberTests
{
    [Fact]
    public void Is_symmetric_and_sixty_digits()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);

        var fromAlice = SafetyNumber.Compute(alice.Identity.Public, "alice", bob.Identity.Public, "bob");
        var fromBob = SafetyNumber.Compute(bob.Identity.Public, "bob", alice.Identity.Public, "alice");

        fromAlice.ShouldBe(fromBob);
        fromAlice.Replace(" ", "", StringComparison.Ordinal).Length.ShouldBe(60);
        fromAlice.Split(' ').Length.ShouldBe(12);
    }

    [Fact]
    public void Changes_when_identity_changes()
    {
        using var alice = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var bob = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        using var mallory = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);

        SafetyNumber.Compute(alice.Identity.Public, "alice", bob.Identity.Public, "bob")
            .ShouldNotBe(SafetyNumber.Compute(alice.Identity.Public, "alice", mallory.Identity.Public, "bob"));
    }
}

public class DeviceKeyStoreTests
{
    [Fact]
    public void Export_import_round_trips_all_material()
    {
        using var store = DeviceKeyStore.Generate(oneTimePreKeyCount: 5);
        store.RotateSignedPreKey();

        using var restored = DeviceKeyStore.Import(store.Export());

        restored.Identity.Public.ShouldBe(store.Identity.Public);
        restored.CurrentSignedPreKeyId.ShouldBe(store.CurrentSignedPreKeyId);
        restored.CurrentKemPreKeyId.ShouldBe(store.CurrentKemPreKeyId);
        restored.AvailableOneTimePreKeys.ShouldBe(5);
        restored.FindSignedPreKey(1).ShouldNotBeNull();
        restored.ExportPublicKeys().ShouldBeEquivalentTo(store.ExportPublicKeys());
    }

    [Fact]
    public void Published_bundle_verifies()
    {
        using var store = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        Should.NotThrow(() => TestBundles.From(store, includeOneTimePreKey: true).Verify());
    }

    [Fact]
    public void Stale_pre_keys_are_pruned_but_current_ones_kept()
    {
        var time = new FakeTime(DateTimeOffset.UtcNow);
        using var store = DeviceKeyStore.Generate(oneTimePreKeyCount: 1, time);
        time.Advance(TimeSpan.FromDays(10));
        store.RotateSignedPreKey(time);
        store.RotateKemPreKey(time);

        store.PruneStalePreKeys(TimeSpan.FromDays(7), time);

        store.FindSignedPreKey(1).ShouldBeNull();
        store.FindSignedPreKey(2).ShouldNotBeNull();
        store.FindKemPreKey(1).ShouldBeNull();
        store.FindKemPreKey(2).ShouldNotBeNull();
    }

    private sealed class FakeTime(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}

internal static class TestBundles
{
    public static PreKeyBundle From(DeviceKeyStore store, bool includeOneTimePreKey)
    {
        var published = store.ExportPublicKeys();
        uint? oneTimeId = null;
        byte[]? oneTimeKey = null;
        if (includeOneTimePreKey)
        {
            var batch = store.GenerateOneTimePreKeys(1);
            oneTimeId = batch[0].Id;
            oneTimeKey = batch[0].KeyPair.PublicKey;
        }

        return new PreKeyBundle(
            published.Identity,
            published.SignedPreKeyId,
            published.SignedPreKey,
            published.SignedPreKeySignature,
            published.KemPreKeyId,
            published.KemPreKey,
            published.KemPreKeySignature,
            oneTimeId,
            oneTimeKey);
    }
}
