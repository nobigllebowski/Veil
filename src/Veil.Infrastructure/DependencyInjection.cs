using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Realtime;
using Veil.Application.Abstractions.Security;
using Veil.Application.Options;
using Veil.Infrastructure.Maintenance;
using Veil.Infrastructure.Options;
using Veil.Infrastructure.Outbox;
using Veil.Infrastructure.Persistence;
using Veil.Infrastructure.Persistence.Interceptors;
using Veil.Infrastructure.Persistence.Repositories;
using Veil.Infrastructure.Realtime;
using Veil.Infrastructure.Security;

namespace Veil.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddVeilInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<SecurityOptions>().Bind(configuration.GetSection(SecurityOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
        services.AddOptions<AuthOptions>().Bind(configuration.GetSection(AuthOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
        services.AddOptions<MessagingOptions>().Bind(configuration.GetSection(MessagingOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
        services.AddOptions<OutboxOptions>().Bind(configuration.GetSection(OutboxOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();

        services.TryAddSingleton(TimeProvider.System);

        // Persistence
        var connectionString = configuration.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres is not configured.");

        services.AddSingleton<OutboxSignal>();
        services.AddSingleton<IFieldEncryptor, AesGcmFieldEncryptor>();
        services.AddSingleton<OutboxInterceptor>();
        services.AddSingleton<AuditChainInterceptor>();

        services.AddDbContextFactory<VeilDbContext>((provider, options) =>
        {
            // No retrying execution strategy: the audit chain and the outbox rely on explicit transactions
            // (advisory locks, SKIP LOCKED), which EF cannot replay transparently.
            options.UseNpgsql(connectionString, npgsql => npgsql.MigrationsAssembly(typeof(VeilDbContext).Assembly.FullName));
            options.UseSnakeCaseNamingConvention();
            options.AddInterceptors(
                provider.GetRequiredService<OutboxInterceptor>(),
                provider.GetRequiredService<AuditChainInterceptor>());
        });

        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IDeviceRepository, DeviceRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IConversationRepository, ConversationRepository>();
        services.AddScoped<IMessageRepository, MessageRepository>();

        // Redis + caches
        var redisConnection = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException("ConnectionStrings:Redis is not configured.");
        services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redisConnection));
        services.AddStackExchangeRedisCache(options => options.Configuration = redisConnection);
        services.AddHybridCache();

        // Security services
        services.AddSingleton<ISigningKeyProvider, SigningKeyProvider>();
        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.AddSingleton<IBlindIndexer, HmacBlindIndexer>();
        services.AddSingleton<IRefreshTokenGenerator, RefreshTokenGenerator>();
        services.AddSingleton<IAccessTokenIssuer, JwtAccessTokenIssuer>();
        services.AddSingleton<ITotpProvider, TotpProvider>();
        services.AddSingleton<ISessionValidator, SessionValidator>();
        services.AddSingleton<ISessionCache>(sp => sp.GetRequiredService<ISessionValidator>());
        services.AddScoped<IAuditor, HashChainAuditor>();
        services.AddSingleton<AuditChainVerifier>();

        // Realtime presence
        services.AddSingleton<RedisPresenceService>();
        services.AddSingleton<IPresenceService>(sp => sp.GetRequiredService<RedisPresenceService>());
        services.AddSingleton<IPresenceTracker>(sp => sp.GetRequiredService<RedisPresenceService>());

        // Background workers
        services.AddHostedService<OutboxProcessor>();
        services.AddHostedService<MaintenanceService>();

        return services;
    }
}
