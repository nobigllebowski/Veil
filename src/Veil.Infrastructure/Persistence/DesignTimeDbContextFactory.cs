using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Veil.Infrastructure.Options;
using Veil.Infrastructure.Security;

namespace Veil.Infrastructure.Persistence;

/// <summary>Used only by <c>dotnet ef</c> to build migrations; never runs in the application.</summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<VeilDbContext>
{
    public VeilDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<VeilDbContext>()
            .UseNpgsql("Host=localhost;Database=veil_design;Username=postgres;Password=postgres", npgsql => npgsql.MigrationsAssembly(typeof(VeilDbContext).Assembly.FullName))
            .UseSnakeCaseNamingConvention()
            .Options;

        var security = Microsoft.Extensions.Options.Options.Create(new SecurityOptions
        {
            FieldEncryptionKey = Convert.ToBase64String(new byte[32]),
            BlindIndexKey = Convert.ToBase64String(new byte[32]),
            IpHashSalt = "design-time-only-salt",
        });

        return new VeilDbContext(options, new AesGcmFieldEncryptor(security));
    }
}
