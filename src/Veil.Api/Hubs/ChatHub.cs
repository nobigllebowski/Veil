using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Veil.Api.Auth;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Realtime;
using Veil.Contracts;
using Veil.Infrastructure.Realtime;

namespace Veil.Api.Hubs;

/// <summary>Strongly-typed client contract. Every payload is routing metadata; message content never travels here in the clear.</summary>
public interface IChatClient
{
    Task EnvelopeAvailable(EnvelopeAvailableNotification notification);
    Task ConversationChanged(ConversationChangedNotification notification);
    Task DeviceListChanged();
    Task Typing(TypingNotification notification);
    Task PresenceChanged(PresenceNotification notification);
}

[Authorize(Policy = AuthPolicies.DeviceBound)]
public sealed class ChatHub(IPresenceTracker presence, IConversationRepository conversations) : Hub<IChatClient>
{
    public static string UserGroup(Guid userId) => $"user:{userId:N}";

    public static string DeviceGroup(Guid deviceId) => $"device:{deviceId:N}";

    public override async Task OnConnectedAsync()
    {
        var userId = CurrentUser.TryGetUserId(Context.User) ?? throw new HubException("Unauthenticated.");
        var deviceId = CurrentUser.TryGetDeviceId(Context.User) ?? throw new HubException("Device-bound session required.");

        await Groups.AddToGroupAsync(Context.ConnectionId, UserGroup(userId), Context.ConnectionAborted);
        await Groups.AddToGroupAsync(Context.ConnectionId, DeviceGroup(deviceId), Context.ConnectionAborted);
        await presence.ConnectedAsync(userId, Context.ConnectionId, Context.ConnectionAborted);
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        if (CurrentUser.TryGetUserId(Context.User) is { } userId)
        {
            await presence.DisconnectedAsync(userId, Context.ConnectionId, CancellationToken.None);
        }

        await base.OnDisconnectedAsync(exception);
    }

    /// <summary>Keeps presence alive; clients call it every minute or so.</summary>
    public Task Heartbeat()
    {
        var userId = CurrentUser.TryGetUserId(Context.User) ?? throw new HubException("Unauthenticated.");
        return presence.HeartbeatAsync(userId, Context.ConnectionAborted);
    }

    /// <summary>Ephemeral typing indicator, fanned out to the other members of a conversation the caller belongs to.</summary>
    public async Task Typing(Guid conversationId)
    {
        var userId = CurrentUser.TryGetUserId(Context.User) ?? throw new HubException("Unauthenticated.");
        var conversation = await conversations.GetByIdAsync(conversationId, Context.ConnectionAborted);
        if (conversation is null || !conversation.IsMember(userId))
        {
            return;
        }

        var others = conversation.Members.Where(m => m.UserId != userId).Select(m => UserGroup(m.UserId)).ToList();
        await Clients.Groups(others).Typing(new TypingNotification(conversationId, userId));
    }
}

/// <summary>Pushes outbox-delivered domain events to connected devices through the hub.</summary>
internal sealed class SignalRRealtimeNotifier(IHubContext<ChatHub, IChatClient> hub) : IRealtimeNotifier
{
    public Task NotifyEnvelopeAvailableAsync(Guid recipientDeviceId, EnvelopeAvailableNotification notification, CancellationToken cancellationToken) =>
        hub.Clients.Group(ChatHub.DeviceGroup(recipientDeviceId)).EnvelopeAvailable(notification);

    public Task NotifyConversationChangedAsync(IReadOnlyCollection<Guid> userIds, ConversationChangedNotification notification, CancellationToken cancellationToken) =>
        hub.Clients.Groups(userIds.Select(ChatHub.UserGroup).ToList()).ConversationChanged(notification);

    public Task NotifyDeviceListChangedAsync(Guid userId, CancellationToken cancellationToken) =>
        hub.Clients.Group(ChatHub.UserGroup(userId)).DeviceListChanged();
}
