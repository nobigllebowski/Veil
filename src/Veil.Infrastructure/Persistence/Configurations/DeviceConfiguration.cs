using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Veil.Crypto;
using Veil.Domain.Devices;
using Veil.Domain.Users;

namespace Veil.Infrastructure.Persistence.Configurations;

internal sealed class DeviceConfiguration : IEntityTypeConfiguration<Device>
{
    public void Configure(EntityTypeBuilder<Device> builder)
    {
        builder.ToTable("devices");
        builder.HasKey(d => d.Id);
        builder.Property(d => d.Id).ValueGeneratedNever();

        builder.Property(d => d.Name).HasMaxLength(Device.NameMaxLength).IsRequired();
        builder.Property(d => d.IdentitySigningKey).HasMaxLength(ProtocolConstants.Ed25519PublicKeySize).IsRequired();
        builder.Property(d => d.IdentityDhKey).HasMaxLength(ProtocolConstants.X25519KeySize).IsRequired();
        builder.Property(d => d.IdentityDhKeySignature).HasMaxLength(ProtocolConstants.Ed25519SignatureSize).IsRequired();
        builder.Property(d => d.SignedPreKeyId).HasConversion(Converters.UIntToLong);
        builder.Property(d => d.SignedPreKey).HasMaxLength(ProtocolConstants.X25519KeySize).IsRequired();
        builder.Property(d => d.SignedPreKeySignature).HasMaxLength(ProtocolConstants.Ed25519SignatureSize).IsRequired();
        builder.Property(d => d.KemPreKeyId).HasConversion(Converters.UIntToLong);
        builder.Property(d => d.KemPreKey).HasMaxLength(ProtocolConstants.MlKem768PublicKeySize).IsRequired();
        builder.Property(d => d.KemPreKeySignature).HasMaxLength(ProtocolConstants.Ed25519SignatureSize).IsRequired();
        builder.Property(d => d.CreatedAt);
        builder.Property(d => d.LastActiveAt);
        builder.Property(d => d.RevokedAt);

        builder.HasOne<User>().WithMany().HasForeignKey(d => d.UserId).OnDelete(DeleteBehavior.Cascade);
        builder.HasIndex(d => new { d.UserId, d.RevokedAt });

        builder.HasMany(d => d.OneTimePreKeys)
            .WithOne()
            .HasForeignKey(k => k.DeviceId)
            .OnDelete(DeleteBehavior.Cascade);
        builder.Navigation(d => d.OneTimePreKeys).UsePropertyAccessMode(PropertyAccessMode.Field).AutoInclude(false);

        builder.Property<uint>("xmin").IsRowVersion();
        builder.Ignore(d => d.DomainEvents);
        builder.Ignore(d => d.Identity);
        builder.Ignore(d => d.IsActive);
    }
}

internal sealed class OneTimePreKeyConfiguration : IEntityTypeConfiguration<OneTimePreKey>
{
    public void Configure(EntityTypeBuilder<OneTimePreKey> builder)
    {
        builder.ToTable("one_time_pre_keys");
        builder.HasKey(k => k.Id);
        builder.Property(k => k.Id).UseIdentityAlwaysColumn();
        builder.Property(k => k.KeyId).HasConversion(Converters.UIntToLong);
        builder.Property(k => k.PublicKey).HasMaxLength(ProtocolConstants.X25519KeySize).IsRequired();
        builder.HasIndex(k => new { k.DeviceId, k.KeyId }).IsUnique();
    }
}
