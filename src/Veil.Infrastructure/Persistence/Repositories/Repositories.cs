using Microsoft.EntityFrameworkCore;
using Veil.Application.Abstractions.Persistence;
using Veil.Domain.Auth;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;
using Veil.Domain.Users;

namespace Veil.Infrastructure.Persistence.Repositories;

internal sealed class UnitOfWork(VeilDbContext context) : IUnitOfWork
{
    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) => context.SaveChangesAsync(cancellationToken);
}

internal sealed class UserRepository(VeilDbContext context) : IUserRepository
{
    public Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken) =>
        context.Users.FirstOrDefaultAsync(u => u.Id == id, cancellationToken);

    public Task<User?> GetByUsernameAsync(Username username, CancellationToken cancellationToken) =>
        context.Users.FirstOrDefaultAsync(u => u.Username == username, cancellationToken);

    public async Task<IReadOnlyList<User>> GetByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken) =>
        ids.Count == 0 ? [] : await context.Users.Where(u => ids.Contains(u.Id)).ToListAsync(cancellationToken);

    public Task<bool> UsernameExistsAsync(Username username, CancellationToken cancellationToken) =>
        context.Users.AnyAsync(u => u.Username == username, cancellationToken);

    public Task<bool> EmailExistsAsync(string emailBlindIndex, CancellationToken cancellationToken) =>
        context.Users.AnyAsync(u => u.EmailBlindIndex == emailBlindIndex, cancellationToken);

    public void Add(User user) => context.Users.Add(user);
}

internal sealed class DeviceRepository(VeilDbContext context) : IDeviceRepository
{
    public Task<Device?> GetByIdAsync(Guid id, CancellationToken cancellationToken) =>
        context.Devices.FirstOrDefaultAsync(d => d.Id == id, cancellationToken);

    public Task<Device?> GetActiveAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken) =>
        context.Devices.FirstOrDefaultAsync(d => d.Id == deviceId && d.UserId == userId && d.RevokedAt == null, cancellationToken);

    public async Task<IReadOnlyList<Device>> ListActiveByUserAsync(Guid userId, CancellationToken cancellationToken) =>
        await context.Devices.Where(d => d.UserId == userId && d.RevokedAt == null).OrderBy(d => d.CreatedAt).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Device>> ListActiveByUsersAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken) =>
        userIds.Count == 0 ? [] : await context.Devices.Where(d => userIds.Contains(d.UserId) && d.RevokedAt == null).ToListAsync(cancellationToken);

    public Task<int> CountActiveAsync(Guid userId, CancellationToken cancellationToken) =>
        context.Devices.CountAsync(d => d.UserId == userId && d.RevokedAt == null, cancellationToken);

    public Task<int> CountOneTimePreKeysAsync(Guid deviceId, CancellationToken cancellationToken) =>
        context.OneTimePreKeys.CountAsync(k => k.DeviceId == deviceId, cancellationToken);

    /// <summary>DELETE … RETURNING with SKIP LOCKED guarantees each key is handed out exactly once under concurrency.</summary>
    public async Task<OneTimePreKeyDto?> ConsumeOneTimePreKeyAsync(Guid deviceId, CancellationToken cancellationToken)
    {
        var consumed = await context.Database
            .SqlQuery<ConsumedPreKey>($"""
                DELETE FROM one_time_pre_keys
                WHERE id = (
                    SELECT id FROM one_time_pre_keys
                    WHERE device_id = {deviceId}
                    ORDER BY id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED)
                RETURNING key_id, public_key
                """)
            .ToListAsync(cancellationToken);

        return consumed.Count == 0 ? null : new OneTimePreKeyDto((uint)consumed[0].KeyId, consumed[0].PublicKey);
    }

    public void Add(Device device) => context.Devices.Add(device);

    private sealed record ConsumedPreKey(long KeyId, byte[] PublicKey);
}

internal sealed class RefreshTokenRepository(VeilDbContext context) : IRefreshTokenRepository
{
    public Task<RefreshToken?> GetByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);

    public Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken) =>
        context.RefreshTokens
            .Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now), cancellationToken);

    public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken) =>
        context.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now), cancellationToken);

    public Task<int> RevokeAllForDeviceAsync(Guid deviceId, DateTimeOffset now, CancellationToken cancellationToken) =>
        context.RefreshTokens
            .Where(t => t.DeviceId == deviceId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now), cancellationToken);

    public void Add(RefreshToken token) => context.RefreshTokens.Add(token);
}

internal sealed class ConversationRepository(VeilDbContext context) : IConversationRepository
{
    public Task<Conversation?> GetByIdAsync(Guid id, CancellationToken cancellationToken) =>
        context.Conversations.FirstOrDefaultAsync(c => c.Id == id, cancellationToken);

    public Task<Conversation?> GetDirectAsync(string directKey, CancellationToken cancellationToken) =>
        context.Conversations.FirstOrDefaultAsync(c => c.DirectKey == directKey, cancellationToken);

    public async Task<IReadOnlyList<Conversation>> ListForUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        var ids = context.ConversationMembers.Where(m => m.UserId == userId).Select(m => m.ConversationId);
        return await context.Conversations.Where(c => ids.Contains(c.Id)).OrderByDescending(c => c.CreatedAt).ToListAsync(cancellationToken);
    }

    public void Add(Conversation conversation) => context.Conversations.Add(conversation);
}

internal sealed class MessageRepository(VeilDbContext context) : IMessageRepository
{
    public async Task<IReadOnlyList<MessageEnvelope>> ListPendingForDeviceAsync(Guid deviceId, int limit, CancellationToken cancellationToken) =>
        await context.MessageEnvelopes
            .AsNoTracking()
            .Where(e => e.RecipientDeviceId == deviceId)
            .OrderBy(e => e.Id)
            .Take(limit)
            .ToListAsync(cancellationToken);

    public Task<int> DeleteAcknowledgedAsync(Guid deviceId, IReadOnlyCollection<Guid> envelopeIds, CancellationToken cancellationToken) =>
        context.MessageEnvelopes
            .Where(e => e.RecipientDeviceId == deviceId && envelopeIds.Contains(e.Id))
            .ExecuteDeleteAsync(cancellationToken);

    public void AddRange(IEnumerable<MessageEnvelope> envelopes) => context.MessageEnvelopes.AddRange(envelopes);
}
