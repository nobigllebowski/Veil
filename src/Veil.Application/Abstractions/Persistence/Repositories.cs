using Veil.Domain.Auth;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;
using Veil.Domain.Users;

namespace Veil.Application.Abstractions.Persistence;

public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken);
    Task<User?> GetByUsernameAsync(Username username, CancellationToken cancellationToken);
    Task<IReadOnlyList<User>> GetByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);
    Task<bool> UsernameExistsAsync(Username username, CancellationToken cancellationToken);
    Task<bool> EmailExistsAsync(string emailBlindIndex, CancellationToken cancellationToken);
    void Add(User user);
}

public interface IDeviceRepository
{
    Task<Device?> GetByIdAsync(Guid id, CancellationToken cancellationToken);
    Task<Device?> GetActiveAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken);
    Task<IReadOnlyList<Device>> ListActiveByUserAsync(Guid userId, CancellationToken cancellationToken);
    Task<IReadOnlyList<Device>> ListActiveByUsersAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken);
    Task<int> CountActiveAsync(Guid userId, CancellationToken cancellationToken);
    Task<int> CountOneTimePreKeysAsync(Guid deviceId, CancellationToken cancellationToken);

    /// <summary>Atomically removes and returns one one-time pre-key, or null when the device has none left.</summary>
    Task<OneTimePreKeyDto?> ConsumeOneTimePreKeyAsync(Guid deviceId, CancellationToken cancellationToken);

    void Add(Device device);
}

public sealed record OneTimePreKeyDto(uint KeyId, byte[] PublicKey);

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetByHashAsync(string tokenHash, CancellationToken cancellationToken);
    Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken);
    Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken);
    Task<int> RevokeAllForDeviceAsync(Guid deviceId, DateTimeOffset now, CancellationToken cancellationToken);
    void Add(RefreshToken token);
}

public interface IConversationRepository
{
    Task<Conversation?> GetByIdAsync(Guid id, CancellationToken cancellationToken);
    Task<Conversation?> GetDirectAsync(string directKey, CancellationToken cancellationToken);
    Task<IReadOnlyList<Conversation>> ListForUserAsync(Guid userId, CancellationToken cancellationToken);
    void Add(Conversation conversation);
}

public interface IMessageRepository
{
    Task<IReadOnlyList<MessageEnvelope>> ListPendingForDeviceAsync(Guid deviceId, int limit, CancellationToken cancellationToken);
    Task<int> DeleteAcknowledgedAsync(Guid deviceId, IReadOnlyCollection<Guid> envelopeIds, CancellationToken cancellationToken);
    void AddRange(IEnumerable<MessageEnvelope> envelopes);
}
