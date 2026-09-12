using System.Diagnostics;
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
    private const string DevHint =
        "Start the development services with `docker compose -f docker-compose.dev.yml up -d`, run the solution through " +
        "src/Veil.AppHost (Aspire), or point the connection strings at your own servers with `dotnet user-secrets set` in src/Veil.Api.";

    /// <returns><c>true</c> when the API may start; <c>false</c> after logging what is wrong.</returns>
    public static async Task<bool> RunAsync(WebApplication app)
    {
        if (!await CheckPostgresAsync(app))
        {
            return false;
        }

        if (!Veil.Infrastructure.DependencyInjection.IsRedisConfigured(app.Configuration))
        {
            app.Logger.LogWarning("ConnectionStrings:Redis is empty: running in single-instance mode (in-memory presence, TOTP replay guard and cache, no SignalR backplane). Configure Redis before scaling out.");
            return true;
        }

        return await CheckRedisAsync(app);
    }

    private static async Task<bool> CheckPostgresAsync(WebApplication app)
    {
        var connectionString = app.Configuration.GetConnectionString("Postgres") ?? string.Empty;
        var cs = new NpgsqlConnectionStringBuilder(connectionString);
        var migrate = app.Configuration.GetValue<bool>("Database:MigrateOnStartup");
        var where = $"PostgreSQL at {cs.Host}:{cs.Port} (database '{cs.Database}', role '{cs.Username}')";

        try
        {
            await using var scope = app.Services.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<VeilDbContext>();

            if (migrate)
            {
                await context.Database.MigrateAsync();
                app.Logger.LogInformation("Database {Database} on {Host}:{Port} is migrated", cs.Database, cs.Host, cs.Port);
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
            return Fail(app, ex,
                $"{where} rejected the credentials (SQLSTATE {ex.SqlState}): the role does not exist or has a different password. " +
                $"For a local server run scripts/init-local-postgres.sql (creates role 'veil' and database 'veil'), or set ConnectionStrings:Postgres to a working account. {DevHint}");
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.InvalidCatalogName)
        {
            return Fail(app, ex,
                $"{where}: the database does not exist (SQLSTATE {ex.SqlState}). Create it with `CREATE DATABASE {cs.Database} OWNER {cs.Username};` " +
                $"or run scripts/init-local-postgres.sql. {DevHint}");
        }
        catch (PostgresException ex)
        {
            return Fail(app, ex, $"{where} reported SQLSTATE {ex.SqlState} while {(migrate ? "migrating" : "opening")}: {ex.MessageText}");
        }
        catch (Exception ex) when (ex is NpgsqlException or InvalidOperationException or System.Net.Sockets.SocketException or TimeoutException)
        {
            return Fail(app, ex, $"Cannot reach {where}: {ex.Message} {DevHint}");
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
            return Fail(app, ex,
                $"Cannot reach Redis at {endpoints}: {ex.Message} Leave ConnectionStrings:Redis empty to run a single instance without Redis. {DevHint}");
        }
    }

    /// <summary>
    /// Logs the failure. Under a debugger the console closes with the process and Visual Studio only reports that it
    /// "cannot connect to the web server", so the message is also raised as an exception to put the cause on screen.
    /// </summary>
    private static bool Fail(WebApplication app, Exception cause, string message)
    {
        app.Logger.LogCritical(cause, "{StartupFailure}", message);
        if (Debugger.IsAttached)
        {
            throw new InvalidOperationException("Veil cannot start. " + message, cause);
        }

        return false;
    }
}
