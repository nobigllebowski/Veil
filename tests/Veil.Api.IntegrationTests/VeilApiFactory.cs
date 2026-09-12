using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using Veil.Client.Sdk;

namespace Veil.Api.IntegrationTests;

/// <summary>
/// Boots the real API against real PostgreSQL and Redis. Uses <c>VEIL_TEST_POSTGRES</c> / <c>VEIL_TEST_REDIS</c>
/// when set (CI service containers, local services), otherwise starts Testcontainers.
/// </summary>
public sealed class VeilApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private PostgreSqlContainer? _postgres;
    private RedisContainer? _redis;

    public string PostgresConnectionString { get; private set; } = string.Empty;
    public string RedisConnectionString { get; private set; } = string.Empty;
    public string SigningKeyPem { get; } = CreateSigningKey();

    public async ValueTask InitializeAsync()
    {
        var postgres = Environment.GetEnvironmentVariable("VEIL_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(postgres))
        {
            _postgres = new PostgreSqlBuilder("postgres:17-alpine").Build();
            await _postgres.StartAsync();
            postgres = _postgres.GetConnectionString();
        }

        var redis = Environment.GetEnvironmentVariable("VEIL_TEST_REDIS");
        if (string.IsNullOrWhiteSpace(redis))
        {
            _redis = new RedisBuilder("redis:7-alpine").Build();
            await _redis.StartAsync();
            redis = _redis.GetConnectionString();
        }

        PostgresConnectionString = postgres;
        RedisConnectionString = redis;

        await ResetDatabaseAsync();
        await ResetRedisAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (_postgres is not null)
        {
            await _postgres.DisposeAsync();
        }

        if (_redis is not null)
        {
            await _redis.DisposeAsync();
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Postgres"] = PostgresConnectionString,
            ["ConnectionStrings:Redis"] = RedisConnectionString,
            ["Security:FieldEncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["Security:BlindIndexKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["Security:IpHashSalt"] = "integration-test-salt",
            ["Security:JwtSigningKeyPem"] = SigningKeyPem,
            ["Security:Argon2:MemoryKiB"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:Parallelism"] = "1",
            ["Database:MigrateOnStartup"] = "true",
            ["Https:Redirect"] = "false",
            ["OpenApi:Enabled"] = "true",
            ["Outbox:PollingInterval"] = "00:00:00.200",
            ["RateLimiting:GlobalPerMinute"] = "100000",
            ["RateLimiting:AuthPerMinute"] = "100000",
            ["RateLimiting:KeysPerMinute"] = "100000",
            ["RateLimiting:LookupPerMinute"] = "100000",
            ["RateLimiting:MessagingPerMinute"] = "100000",
            ["Serilog:MinimumLevel:Default"] = "Warning",
        };

        foreach (var (key, value) in settings)
        {
            builder.UseSetting(key, value);
        }
    }

    /// <summary>A fresh API client + SDK wrapper sharing this server.</summary>
    public VeilApiClient CreateApiClient()
    {
        var http = CreateClient();
        http.BaseAddress = new Uri("http://localhost/");
        return new VeilApiClient(http);
    }

    public T GetService<T>() where T : notnull => Services.GetRequiredService<T>();

    private async Task ResetDatabaseAsync()
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;", connection);
        await command.ExecuteNonQueryAsync();
    }

    private async Task ResetRedisAsync()
    {
        await using var multiplexer = await ConnectionMultiplexer.ConnectAsync(RedisConnectionString + ",allowAdmin=true");
        foreach (var endpoint in multiplexer.GetEndPoints())
        {
            await multiplexer.GetServer(endpoint).FlushDatabaseAsync(multiplexer.GetDatabase().Database);
        }
    }

    private static string CreateSigningKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }
}

[CollectionDefinition(Name)]
public sealed class ApiCollection : ICollectionFixture<VeilApiFactory>
{
    public const string Name = "api";
}

/// <summary>A registered, logged-in user with one device and an E2EE messenger bound to it.</summary>
public sealed class TestPersona : IDisposable
{
    public const string Password = "correct-horse-battery-staple";

    private TestPersona(string username, VeilApiClient api, VeilMessenger messenger, ClientState state)
    {
        Username = username;
        Api = api;
        Messenger = messenger;
        State = state;
    }

    public string Username { get; }
    public VeilApiClient Api { get; }
    public VeilMessenger Messenger { get; }
    public ClientState State { get; }
    public Guid UserId => State.UserId;
    public Guid DeviceId => State.DeviceId!.Value;

    public static async Task<TestPersona> CreateAsync(VeilApiFactory factory, string prefix, string deviceName = "test-device", bool registerDevice = true)
    {
        var username = $"{prefix}{Guid.NewGuid():N}"[..Math.Min(32, prefix.Length + 12)];
        var api = factory.CreateApiClient();
        var profile = await api.RegisterAsync(username, $"{username}@example.com", Password, prefix);
        await api.LoginAsync(username, Password);

        var state = new ClientState { ServerUrl = "http://localhost/", UserId = profile.Id, Username = username };
        var messenger = new VeilMessenger(api, state, new InMemoryClientStateStore());
        if (registerDevice)
        {
            await messenger.RegisterDeviceAsync(deviceName);
        }

        return new TestPersona(username, api, messenger, state);
    }

    /// <summary>Logs the same account in on another device (separate keys, separate sessions).</summary>
    public async Task<TestPersona> AddDeviceAsync(VeilApiFactory factory, string deviceName)
    {
        var api = factory.CreateApiClient();
        await api.LoginAsync(Username, Password);
        var state = new ClientState { ServerUrl = "http://localhost/", UserId = UserId, Username = Username };
        var messenger = new VeilMessenger(api, state, new InMemoryClientStateStore());
        await messenger.RegisterDeviceAsync(deviceName);
        return new TestPersona(Username, api, messenger, state);
    }

    public void Dispose()
    {
        Messenger.Dispose();
        Api.Dispose();
    }
}
