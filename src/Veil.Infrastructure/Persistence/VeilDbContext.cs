using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Veil.Domain.Audit;
using Veil.Domain.Auth;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;
using Veil.Domain.Users;
using Veil.Infrastructure.Outbox;
using Veil.Infrastructure.Persistence.Configurations;
using Veil.Infrastructure.Security;

namespace Veil.Infrastructure.Persistence;

public sealed class VeilDbContext(DbContextOptions<VeilDbContext> options, IFieldEncryptor encryptor) : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<OneTimePreKey> OneTimePreKeys => Set<OneTimePreKey>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<Conversation> Conversations => Set<Conversation>();
    public DbSet<ConversationMember> ConversationMembers => Set<ConversationMember>();
    public DbSet<MessageEnvelope> MessageEnvelopes => Set<MessageEnvelope>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    internal IFieldEncryptor Encryptor { get; } = encryptor;

    /// <summary>Per-SaveChanges state used by the singleton interceptors (a DbContext is never used concurrently).</summary>
    internal bool OutboxRowsPending { get; set; }

    internal Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction? OwnedAuditTransaction { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new UserConfiguration(this));
        modelBuilder.ApplyConfiguration(new DeviceConfiguration());
        modelBuilder.ApplyConfiguration(new OneTimePreKeyConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
        modelBuilder.ApplyConfiguration(new ConversationConfiguration(this));
        modelBuilder.ApplyConfiguration(new ConversationMemberConfiguration());
        modelBuilder.ApplyConfiguration(new MessageEnvelopeConfiguration());
        modelBuilder.ApplyConfiguration(new AuditEntryConfiguration());
        modelBuilder.ApplyConfiguration(new OutboxMessageConfiguration());
        modelBuilder.ApplyConfiguration(new DataProtectionKeyConfiguration());
    }
}
