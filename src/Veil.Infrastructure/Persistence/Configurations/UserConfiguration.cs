using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Veil.Domain.Users;

namespace Veil.Infrastructure.Persistence.Configurations;

internal sealed class UserConfiguration(VeilDbContext context) : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        builder.HasKey(u => u.Id);
        builder.Property(u => u.Id).ValueGeneratedNever();

        builder.Property(u => u.Username).HasConversion(Converters.UsernameConverter).HasMaxLength(Username.MaxLength).IsRequired();
        builder.HasIndex(u => u.Username).IsUnique();

        builder.Property(u => u.DisplayName).HasMaxLength(User.DisplayNameMaxLength).IsRequired();

        builder.Property(u => u.Email).HasConversion(Converters.EncryptedEmail(context.Encryptor, "users.email")).HasMaxLength(1024).IsRequired();
        builder.Property(u => u.EmailBlindIndex).HasMaxLength(64).IsRequired();
        builder.HasIndex(u => u.EmailBlindIndex).IsUnique();

        builder.Property(u => u.PasswordHash).HasMaxLength(256).IsRequired();
        builder.Property(u => u.TotpSecret).HasConversion(Converters.EncryptedNullableString(context.Encryptor, "users.totp_secret")).HasMaxLength(512);
        builder.Property(u => u.TotpEnabled);
        builder.Property(u => u.CreatedAt);
        builder.Property(u => u.LastLoginAt);
        builder.Property(u => u.FailedLoginAttempts);
        builder.Property(u => u.LockedUntil);
        builder.Property(u => u.SecurityStamp);

        builder.Property<uint>("xmin").IsRowVersion();
        builder.Ignore(u => u.DomainEvents);
    }
}
