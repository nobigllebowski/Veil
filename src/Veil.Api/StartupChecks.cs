using Microsoft.EntityFrameworkCore;
using Npgsql;
using StackExchange.Redis;
using Veil.Infrastructure.Persistence;

namespace Veil.Api;

/// <summary>
/// Fails fast with an actionable message when a backing service is unreachable, instead of an unhandled
/// <c>Npgsql.PostgresException</c> deep inside EF Core. Runs migrations when <c>Database:MigrateOnStartup</c> is set.
/// </summary>
internal static class StartupChecks
{
    private const string DevHint = "Start the development services with `docker compose -f docker-compose.dev.yml up -d`, " +
                                   "run the solution through src/Veil.AppHost (Aspire), or point the connection string at your own server " +
                                   "with `dotnet user-secrets set` in src/Veil.Api.";

    /// <returns><c>true</c> when the API may start; <c>false</c> after logging what is wrong.</returns>
    public static async Task<bool> RunAsync(WebApplication app)
    {
        return await CheckPostgresAsync(app) && await CheckRedisAsync(app);
    }

    private static async Task<bool> CheckPostgresAsync(WebApplication app)
    {
        var connectionString = app.Configuration.GetConnectionString("Postgres") ?? string.Empty;
        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        var migrate = app.Configuration.GetValue<bool>("Database:MigrateOnStartup");

        try
        {
            await using var scope = app.Services.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<VeilDbContext>();

            if (migrate)
            {
                await context.Database.MigrateAsync();
                app.Logger.LogInformation("Database {Database} on {Host}:{Port} is migrated", builder.Database, builder.Host, builder.Port);
            }
            else
            {
                await context.Database.OpenConnectionAsync();
                await context.Database.CloseConnectionAsync();
            }

            return true;
        }
        catch (PostgresException ex) when (ex.SqlState is PostgresErrorCodes.InvalidPassword or PostgresErrorCodes.InvalidAuthorizationSpecification)
        {
            app.Logger.LogCritical(
                "PostgreSQL at {Host}:{Port} rejected the credentials of role '{User}' (SQLSTATE {SqlState}). " +
                "The role does not exist or has a different password. For a local server run scripts/init-local-postgres.sql " +
                "(creates role 'veil' and database 'veil'), or set ConnectionStrings:Postgres to a working account. {Hint}",
                builder.Host, builder.Port, builder.Username, ex.SqlState, DevHint);
            return false;
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.InvalidCatalogName)
        {
            app.Logger.LogCritical(
                "PostgreSQL at {Host}:{Port} has no database '{Database}' (SQLSTATE {SqlState}). " +
                "Create it with `CREATE DATABASE {Database} OWNER {User};` or run scripts/init-local-postgres.sql. {Hint}",
                builder.Host, builder.Port, builder.Database, ex.SqlState, builder.Database, builder.Username, DevHint);
            return false;
        }
        catch (PostgresException ex)
        {
            app.Logger.LogCritical(ex,
                "PostgreSQL at {Host}:{Port} reported SQLSTATE {SqlState} while {Action} database '{Database}': {Message}",
                builder.Host, builder.Port, ex.SqlState, migrate ? "migrating" : "opening", builder.Database, ex.MessageText);
            return false;
        }
        catch (Exception ex) when (ex is NpgsqlException or InvalidOperationException or System.Net.Sockets.SocketException or TimeoutException)
        {
            app.Logger.LogCritical(ex,
                "Cannot reach PostgreSQL at {Host}:{Port} (database '{Database}', role '{User}'). {Hint}",
                builder.Host, builder.Port, builder.Database, builder.Username, DevHint);
            return false;
        }
    }

    private static async Task<bool> CheckRedisAsync(WebApplication app)
    {
        var connectionString = app.Configuration.GetConnectionString("Redis") ?? string.Empty;
        try
        {
            var multiplexer = app.Services.GetRequiredService<IConnectionMultiplexer>();
            await multiplexer.GetDatabase().PingAsync();
            return true;
        }
        catch (Exception ex) when (ex is RedisException or InvalidOperationException or TimeoutException)
        {
            var endpoints = string.Join(", ", ConfigurationOptions.Parse(connectionString, ignoreUnknown: true).EndPoints.Select(e => e.ToString()));
            app.Logger.LogCritical(ex, "Cannot reach Redis at {Endpoints}. {Hint}", endpoints, DevHint);
            return false;
        }
    }
}
