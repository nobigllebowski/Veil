using System.Net;
using Microsoft.EntityFrameworkCore;
using Veil.Client.Sdk;
using Veil.Contracts;
using Veil.Crypto.Protocol;
using Veil.Infrastructure.Persistence;

namespace Veil.Api.IntegrationTests;

[Collection(ApiCollection.Name)]
public class EndToEndEncryptionTests(VeilApiFactory factory)
{
    [Fact]
    public async Task Two_users_exchange_messages_the_server_cannot_read()
    {
        using var alice = await TestPersona.CreateAsync(factory, "alice");
        using var bob = await TestPersona.CreateAsync(factory, "bob");
        var conversation = await alice.Api.CreateDirectConversationAsync(bob.UserId);

        var sent = await alice.Messenger.SendTextAsync(conversation.Id, "hello bob 👋");
        sent.Status.ShouldBe(MessageStatus.Sent);
        alice.Messenger.History(conversation.Id).ShouldHaveSingleItem().Outgoing.ShouldBeTrue();

        // What the server holds is an opaque pre-key envelope, not the text.
        await using (var db = await factory.GetService<IDbContextFactory<VeilDbContext>>().CreateDbContextAsync())
        {
            var stored = await db.MessageEnvelopes.AsNoTracking().SingleAsync(e => e.RecipientDeviceId == bob.DeviceId);
            System.Text.Encoding.UTF8.GetString(stored.Payload).ShouldNotContain("hello bob");
            Envelope.Decode(stored.Payload).Type.ShouldBe(EnvelopeType.PreKeyMessage);
            stored.RecipientDeviceId.ShouldBe(bob.DeviceId);
        }

        var received = await bob.Messenger.PullAsync();
        received.ShouldHaveSingleItem().Message.Body.ShouldBe("hello bob 👋");
        received[0].SenderUserId.ShouldBe(alice.UserId);
        bob.Messenger.History(conversation.Id).ShouldHaveSingleItem().Status.ShouldBe(MessageStatus.Received);
        bob.Messenger.UnreadCount(conversation.Id).ShouldBe(1);

        // Acknowledged text ciphertext is gone from the server; Bob's encrypted delivery receipt is waiting for Alice.
        (await bob.Api.FetchPendingAsync()).ShouldBeEmpty();
        (await alice.Messenger.PullAsync()).ShouldBeEmpty();
        alice.Messenger.History(conversation.Id).Single().Status.ShouldBe(MessageStatus.Delivered);

        await bob.Messenger.SendTextAsync(conversation.Id, "hi alice");
        var reply = await alice.Messenger.PullAsync();
        reply.ShouldHaveSingleItem().Message.Body.ShouldBe("hi alice");

        // After the first round-trip the handshake header is dropped and the ratchet has advanced.
        await alice.Messenger.SendTextAsync(conversation.Id, "second message");
        await using (var db = await factory.GetService<IDbContextFactory<VeilDbContext>>().CreateDbContextAsync())
        {
            var stored = await db.MessageEnvelopes.AsNoTracking().Where(e => e.RecipientDeviceId == bob.DeviceId).OrderBy(e => e.Id).LastAsync();
            Envelope.Decode(stored.Payload).Type.ShouldBe(EnvelopeType.Message);
        }

        (await bob.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("second message");
        bob.Messenger.History(conversation.Id).Count.ShouldBe(3);
        alice.Messenger.SafetyNumberWith(bob.Username, bob.Messenger.Identity!).ShouldBe(bob.Messenger.SafetyNumberWith(alice.Username, alice.Messenger.Identity!));
    }

    [Fact]
    public async Task Messages_fan_out_to_every_device_and_stale_device_sets_are_healed()
    {
        using var alice = await TestPersona.CreateAsync(factory, "alice");
        using var bobPhone = await TestPersona.CreateAsync(factory, "bob", "phone");
        var conversation = await alice.Api.CreateDirectConversationAsync(bobPhone.UserId);

        await alice.Messenger.SendTextAsync(conversation.Id, "one device");
        (await bobPhone.Messenger.PullAsync()).ShouldHaveSingleItem();

        // Bob adds a laptop; Alice's next send must reach both devices without any manual refresh.
        using var bobLaptop = await bobPhone.AddDeviceAsync(factory, "laptop");
        await alice.Messenger.SendTextAsync(conversation.Id, "two devices");

        (await bobPhone.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("two devices");
        (await bobLaptop.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("two devices");

        // The server refuses a send that skips a device.
        var bundles = await alice.Api.GetPreKeyBundlesAsync(bobPhone.UserId);
        var partial = await Should.ThrowAsync<VeilApiException>(() =>
            alice.Api.SendEnvelopesAsync(conversation.Id, [new OutgoingEnvelope(bobPhone.UserId, bundles[0].DeviceId, new byte[64])]));
        partial.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        partial.IsDeviceSetMismatch.ShouldBeTrue();
        partial.Problem!.Mismatches!.Single().MissingDeviceIds.ShouldHaveSingleItem();

        // Revoking the laptop shrinks the required set again and the SDK heals its session table.
        await bobPhone.Api.RevokeDeviceAsync(bobLaptop.DeviceId);
        await alice.Messenger.SendTextAsync(conversation.Id, "back to one");
        (await bobPhone.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("back to one");
        var revoked = await Should.ThrowAsync<VeilApiException>(() => bobLaptop.Api.FetchPendingAsync());
        revoked.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Group_conversation_reaches_every_member()
    {
        using var alice = await TestPersona.CreateAsync(factory, "alice");
        using var bob = await TestPersona.CreateAsync(factory, "bob");
        using var carol = await TestPersona.CreateAsync(factory, "carol");
        var group = await alice.Api.CreateGroupConversationAsync("Project Veil", [bob.UserId, carol.UserId]);
        group.Members.Count.ShouldBe(3);

        await alice.Messenger.SendTextAsync(group.Id, "welcome all");

        (await bob.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("welcome all");
        (await carol.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("welcome all");

        await carol.Messenger.SendTextAsync(group.Id, "thanks!");
        (await alice.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("thanks!");
        (await bob.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("thanks!");

        // The title is metadata the server stores encrypted at rest.
        await using var db = await factory.GetService<IDbContextFactory<VeilDbContext>>().CreateDbContextAsync();
        var rawTitle = await db.Database.SqlQuery<string>($"SELECT title AS \"Value\" FROM conversations WHERE id = {group.Id}").SingleAsync();
        rawTitle.ShouldStartWith("v1.");
        rawTitle.ShouldNotContain("Project Veil");
    }

    [Fact]
    public async Task One_time_pre_keys_are_consumed_once_and_replenished()
    {
        using var alice = await TestPersona.CreateAsync(factory, "alice");
        using var bob = await TestPersona.CreateAsync(factory, "bob");

        var before = await bob.Api.GetOneTimePreKeyCountAsync();
        var first = await alice.Api.GetPreKeyBundlesAsync(bob.UserId);
        var second = await alice.Api.GetPreKeyBundlesAsync(bob.UserId);

        first.Single().OneTimePreKeyId.ShouldNotBeNull();
        second.Single().OneTimePreKeyId.ShouldNotBe(first.Single().OneTimePreKeyId);
        (await bob.Api.GetOneTimePreKeyCountAsync()).ShouldBe(before - 2);

        // Forged bundles are refused on upload: the server validates every signature.
        var forged = await Should.ThrowAsync<VeilApiException>(() =>
            bob.Api.RotateSignedPreKeyAsync(999, new byte[32], new byte[64]));
        forged.Code.ShouldBe("device.invalid_signature");
    }

    [Fact]
    public async Task Sessions_survive_client_restarts_through_encrypted_state()
    {
        using var alice = await TestPersona.CreateAsync(factory, "alice");
        using var bob = await TestPersona.CreateAsync(factory, "bob");
        var conversation = await alice.Api.CreateDirectConversationAsync(bob.UserId);
        await alice.Messenger.SendTextAsync(conversation.Id, "before restart");
        (await bob.Messenger.PullAsync()).ShouldHaveSingleItem();

        var path = Path.Combine(Path.GetTempPath(), $"veil-{Guid.NewGuid():N}.state");
        try
        {
            var store = new EncryptedFileStateStore(path, "a strong passphrase");
            await store.SaveAsync(bob.State);

            var bytes = await File.ReadAllBytesAsync(path);
            System.Text.Encoding.Latin1.GetString(bytes).ShouldNotContain(bob.Username);
            await Should.ThrowAsync<UnauthorizedAccessException>(() => new EncryptedFileStateStore(path, "wrong passphrase").LoadAsync());

            var restored = await store.LoadAsync();
            using var restoredApi = factory.CreateApiClient();
            using var bobAgain = new VeilMessenger(restoredApi, restored!, store);

            await alice.Messenger.SendTextAsync(conversation.Id, "after restart");
            (await bobAgain.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("after restart");

            await bobAgain.SendTextAsync(conversation.Id, "still here");
            (await alice.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("still here");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Realtime_hub_announces_new_envelopes()
    {
        using var alice = await TestPersona.CreateAsync(factory, "alice");
        using var bob = await TestPersona.CreateAsync(factory, "bob");
        var conversation = await alice.Api.CreateDirectConversationAsync(bob.UserId);

        var announced = new TaskCompletionSource<EnvelopeAvailableNotification>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var realtime = new RealtimeClient(new Uri("http://localhost/"), () => Task.FromResult(bob.Api.AccessToken), factory.Server.CreateHandler());
        realtime.EnvelopeAvailable += n => announced.TrySetResult(n);
        await realtime.ConnectAsync();

        await alice.Messenger.SendTextAsync(conversation.Id, "ping");

        var notification = await announced.Task.WaitAsync(TimeSpan.FromSeconds(10));
        notification.ConversationId.ShouldBe(conversation.Id);
        notification.SenderUserId.ShouldBe(alice.UserId);

        (await bob.Messenger.PullAsync()).ShouldHaveSingleItem().Message.Body.ShouldBe("ping");
    }

    [Fact]
    public async Task Hub_rejects_sessions_without_a_device()
    {
        using var persona = await TestPersona.CreateAsync(factory, "nodev", registerDevice: false);
        await using var realtime = new RealtimeClient(new Uri("http://localhost/"), () => Task.FromResult(persona.Api.AccessToken), factory.Server.CreateHandler());

        await Should.ThrowAsync<HttpRequestException>(() => realtime.ConnectAsync());
    }
}
