using Veil.Contracts;

namespace Veil.Application.Abstractions.Realtime;

/// <summary>Push channel to connected clients (SignalR). Never carries plaintext content: only routing facts.</summary>
public interface IRealtimeNotifier
{
    Task NotifyEnvelopeAvailableAsync(Guid recipientDeviceId, EnvelopeAvailableNotification notification, CancellationToken cancellationToken);
    Task NotifyConversationChangedAsync(IReadOnlyCollection<Guid> userIds, ConversationChangedNotification notification, CancellationToken cancellationToken);
    Task NotifyDeviceListChangedAsync(Guid userId, CancellationToken cancellationToken);
}

public interface IPresenceService
{
    Task<IReadOnlySet<Guid>> GetOnlineUsersAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken);
}
