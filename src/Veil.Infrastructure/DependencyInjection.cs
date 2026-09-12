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
    /// <summary>True when <c>ConnectionStrings:Redis</c> is set; otherwise the API runs in single-instance mode.</summary>
    public static bool IsRedisConfigured(IConfiguration configuration) =>
        !string.IsNullOrWhiteSpace(configuration?.GetConnectionString("Redis"));

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

        // Redis is required for multi-instance deployments (presence, TOTP replay guard, cache L2, SignalR backplane).
        // Without a connection string the same features run in-process, which is fine for a single dev instance.
        var redisConnection = configuration.GetConnectionString("Redis");
        if (!string.IsNullOrWhiteSpace(redisConnection))
        {
            services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redisConnection));
            services.AddStackExchangeRedisCache(options => options.Configuration = redisConnection);
            services.AddSingleton<ITotpReplayGuard, RedisTotpReplayGuard>();
            services.AddSingleton<RedisPresenceService>();
            services.AddSingleton<IPresenceService>(sp => sp.GetRequiredService<RedisPresenceService>());
            services.AddSingleton<IPresenceTracker>(sp => sp.GetRequiredService<RedisPresenceService>());
        }
        else
        {
            services.AddSingleton<ITotpReplayGuard, InMemoryTotpReplayGuard>();
            services.AddSingleton<InMemoryPresenceService>();
            services.AddSingleton<IPresenceService>(sp => sp.GetRequiredService<InMemoryPresenceService>());
            services.AddSingleton<IPresenceTracker>(sp => sp.GetRequiredService<InMemoryPresenceService>());
        }

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

        // Background workers
        services.AddHostedService<OutboxProcessor>();
        services.AddHostedService<MaintenanceService>();

        return services;
    }
}
