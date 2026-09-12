using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Veil.Domain.Audit;
using Veil.Infrastructure.Outbox;

namespace Veil.Infrastructure.Persistence.Configurations;

internal sealed class AuditEntryConfiguration : IEntityTypeConfiguration<AuditEntry>
{
    public void Configure(EntityTypeBuilder<AuditEntry> builder)
    {
        builder.ToTable("audit_entries");
        builder.HasKey(a => a.Sequence);
        builder.Property(a => a.Sequence).UseIdentityAlwaysColumn();
        builder.Property(a => a.Action).HasMaxLength(64).IsRequired();
        builder.Property(a => a.IpHash).HasMaxLength(64);
        // Stored as text, not jsonb: the hash chain covers the exact bytes and jsonb would re-format them.
        builder.Property(a => a.Detail).HasColumnType("text");
        builder.Property(a => a.PreviousHash).HasMaxLength(64).IsRequired();
        builder.Property(a => a.Hash).HasMaxLength(64).IsRequired();
        builder.HasIndex(a => a.ActorUserId);
        builder.HasIndex(a => a.OccurredAt);
    }
}

internal sealed class OutboxMessageConfiguration : IEntityTypeConfiguration<OutboxMessage>
{
    public void Configure(EntityTypeBuilder<OutboxMessage> builder)
    {
        builder.ToTable("outbox_messages");
        builder.HasKey(o => o.Id);
        builder.Property(o => o.Id).ValueGeneratedNever();
        builder.Property(o => o.Type).HasMaxLength(256).IsRequired();
        builder.Property(o => o.Payload).HasColumnType("jsonb").IsRequired();
        builder.Property(o => o.LastError).HasMaxLength(2000);
        builder.HasIndex(o => o.OccurredAt).HasFilter("processed_at IS NULL");
    }
}

internal sealed class DataProtectionKeyConfiguration : IEntityTypeConfiguration<DataProtectionKey>
{
    public void Configure(EntityTypeBuilder<DataProtectionKey> builder)
    {
        builder.ToTable("data_protection_keys");
    }
}
