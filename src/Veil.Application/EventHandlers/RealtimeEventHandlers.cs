using Veil.Application.Abstractions.Events;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Realtime;
using Veil.Contracts;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;

namespace Veil.Application.EventHandlers;

internal sealed class EnvelopeStoredHandler(IRealtimeNotifier notifier) : IDomainEventHandler<EnvelopeStored>
{
    public Task HandleAsync(EnvelopeStored domainEvent, CancellationToken cancellationToken) =>
        notifier.NotifyEnvelopeAvailableAsync(
            domainEvent.RecipientDeviceId,
            new EnvelopeAvailableNotification(domainEvent.EnvelopeId, domainEvent.ConversationId, domainEvent.SenderUserId, domainEvent.OccurredAt),
            cancellationToken);
}

internal sealed class ConversationCreatedHandler(IRealtimeNotifier notifier) : IDomainEventHandler<ConversationCreated>
{
    public Task HandleAsync(ConversationCreated domainEvent, CancellationToken cancellationToken) =>
        notifier.NotifyConversationChangedAsync(domainEvent.MemberIds, new ConversationChangedNotification(domainEvent.ConversationId, "created", null), cancellationToken);
}

internal sealed class MemberAddedHandler(IConversationRepository conversations, IRealtimeNotifier notifier) : IDomainEventHandler<MemberAdded>
{
    public async Task HandleAsync(MemberAdded domainEvent, CancellationToken cancellationToken)
    {
        var conversation = await conversations.GetByIdAsync(domainEvent.ConversationId, cancellationToken);
        var recipients = conversation?.Members.Select(m => m.UserId).ToList() ?? [domainEvent.UserId];
        await notifier.NotifyConversationChangedAsync(recipients, new ConversationChangedNotification(domainEvent.ConversationId, "member_added", domainEvent.UserId), cancellationToken);
    }
}

internal sealed class MemberRemovedHandler(IConversationRepository conversations, IRealtimeNotifier notifier) : IDomainEventHandler<MemberRemoved>
{
    public async Task HandleAsync(MemberRemoved domainEvent, CancellationToken cancellationToken)
    {
        var conversation = await conversations.GetByIdAsync(domainEvent.ConversationId, cancellationToken);
        var recipients = (conversation?.Members.Select(m => m.UserId) ?? []).Append(domainEvent.UserId).Distinct().ToList();
        await notifier.NotifyConversationChangedAsync(recipients, new ConversationChangedNotification(domainEvent.ConversationId, "member_removed", domainEvent.UserId), cancellationToken);
    }
}

internal sealed class DeviceRegisteredHandler(IRealtimeNotifier notifier) : IDomainEventHandler<DeviceRegistered>
{
    public Task HandleAsync(DeviceRegistered domainEvent, CancellationToken cancellationToken) =>
        notifier.NotifyDeviceListChangedAsync(domainEvent.UserId, cancellationToken);
}

internal sealed class DeviceRevokedHandler(IRealtimeNotifier notifier) : IDomainEventHandler<DeviceRevoked>
{
    public Task HandleAsync(DeviceRevoked domainEvent, CancellationToken cancellationToken) =>
        notifier.NotifyDeviceListChangedAsync(domainEvent.UserId, cancellationToken);
}
