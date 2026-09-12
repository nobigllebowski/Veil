using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;

namespace Veil.Infrastructure.Persistence.Configurations;

internal sealed class MessageEnvelopeConfiguration : IEntityTypeConfiguration<MessageEnvelope>
{
    public void Configure(EntityTypeBuilder<MessageEnvelope> builder)
    {
        builder.ToTable("message_envelopes");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).ValueGeneratedNever();
        builder.Property(e => e.Payload).HasMaxLength(MessageEnvelope.MaxPayloadBytes).IsRequired();
        builder.HasIndex(e => new { e.RecipientDeviceId, e.Id });
        builder.HasIndex(e => e.ExpiresAt);
        builder.HasOne<Conversation>().WithMany().HasForeignKey(e => e.ConversationId).OnDelete(DeleteBehavior.Cascade);
        builder.HasOne<Device>().WithMany().HasForeignKey(e => e.RecipientDeviceId).OnDelete(DeleteBehavior.Cascade);
        builder.Ignore(e => e.DomainEvents);
    }
}
