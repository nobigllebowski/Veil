using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Veil.Domain.Conversations;
using Veil.Domain.Users;

namespace Veil.Infrastructure.Persistence.Configurations;

internal sealed class ConversationConfiguration(VeilDbContext context) : IEntityTypeConfiguration<Conversation>
{
    public void Configure(EntityTypeBuilder<Conversation> builder)
    {
        builder.ToTable("conversations");
        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id).ValueGeneratedNever();
        builder.Property(c => c.Type).HasConversion<int>();
        builder.Property(c => c.Title).HasConversion(Converters.EncryptedNullableString(context.Encryptor, "conversations.title")).HasMaxLength(1024);
        builder.Property(c => c.DirectKey).HasMaxLength(65);
        builder.HasIndex(c => c.DirectKey).IsUnique();

        builder.HasMany(c => c.Members).WithOne().HasForeignKey(m => m.ConversationId).OnDelete(DeleteBehavior.Cascade);
        builder.Navigation(c => c.Members).UsePropertyAccessMode(PropertyAccessMode.Field).AutoInclude();

        builder.Property<uint>("xmin").IsRowVersion();
        builder.Ignore(c => c.DomainEvents);
    }
}

internal sealed class ConversationMemberConfiguration : IEntityTypeConfiguration<ConversationMember>
{
    public void Configure(EntityTypeBuilder<ConversationMember> builder)
    {
        builder.ToTable("conversation_members");
        builder.HasKey(m => new { m.ConversationId, m.UserId });
        builder.Property(m => m.Role).HasConversion<int>();
        builder.HasIndex(m => m.UserId);
        builder.HasOne<User>().WithMany().HasForeignKey(m => m.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}
