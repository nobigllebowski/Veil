using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Npgsql;

namespace Veil.Web.E2ETests;

/// <summary>
/// Boots the real API (which also serves the Blazor client) as a child process on a free port, against the
/// PostgreSQL named by <c>VEIL_E2E_POSTGRES</c> (default: the local development server, database <c>veil_e2e</c>)
/// and without Redis (single-instance mode), so the browser can talk to a genuine HTTP endpoint.
/// </summary>
public sealed partial class ApiHost : IAsyncLifetime
{
    private Process? _process;
    private readonly List<string> _log = [];

    public Uri BaseAddress { get; private set; } = new("http://127.0.0.1/");

    public string ConnectionString { get; } = Environment.GetEnvironmentVariable("VEIL_E2E_POSTGRES")
        ?? "Host=localhost;Port=5432;Database=veil_e2e;Username=veil;Password=veil_dev_password";

    public async ValueTask InitializeAsync()
    {
        await EnsureDatabaseAsync();

        var repoRoot = FindRepoRoot();
        var configuration = typeof(ApiHost).Assembly.GetCustomAttribute<System.Reflection.AssemblyConfigurationAttribute>()?.Configuration ?? "Debug";
        var apiDll = Environment.GetEnvironmentVariable("VEIL_E2E_API_DLL")
            ?? Path.Combine(repoRoot, "src", "Veil.Api", "bin", configuration, "net10.0", "Veil.Api.dll");
        if (!File.Exists(apiDll))
        {
            throw new FileNotFoundException($"Build the solution first; {apiDll} is missing.");
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var start = new ProcessStartInfo("dotnet", $"\"{apiDll}\" --urls http://127.0.0.1:0")
        {
            WorkingDirectory = Path.GetDirectoryName(apiDll)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        start.Environment["ConnectionStrings__Postgres"] = ConnectionString;
        start.Environment["ConnectionStrings__Redis"] = string.Empty;
        start.Environment["Security__FieldEncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        start.Environment["Security__BlindIndexKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        start.Environment["Security__IpHashSalt"] = "e2e-test-salt-value";
        start.Environment["Security__JwtSigningKeyPem"] = ecdsa.ExportPkcs8PrivateKeyPem();
        start.Environment["Security__Argon2__MemoryKiB"] = "8192";
        start.Environment["Security__Argon2__Iterations"] = "1";
        start.Environment["Security__Argon2__Parallelism"] = "1";
        start.Environment["Database__MigrateOnStartup"] = "true";
        start.Environment["Https__Redirect"] = "false";
        start.Environment["Outbox__PollingInterval"] = "00:00:00.200";
        start.Environment["RateLimiting__AuthPerMinute"] = "100000";
        start.Environment["RateLimiting__GlobalPerMinute"] = "100000";
        start.Environment["RateLimiting__KeysPerMinute"] = "100000";
        start.Environment["RateLimiting__MessagingPerMinute"] = "100000";
        start.Environment["Serilog__MinimumLevel__Default"] = "Warning";
        start.Environment["Serilog__MinimumLevel__Override__Microsoft.Hosting.Lifetime"] = "Information";
        start.Environment["OpenApi__Enabled"] = "false";
        start.Environment.Remove("ASPNETCORE_URLS");

        _process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the API process.");
        var listening = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);

        _process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null)
            {
                return;
            }

            lock (_log)
            {
                _log.Add(e.Data);
            }

            var match = ListeningPattern().Match(e.Data);
            if (match.Success)
            {
                var address = match.Groups["plain"].Success ? match.Groups["plain"].Value : match.Groups["json"].Value;
                listening.TrySetResult(new Uri(address + "/"));
            }
        };
        _process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (_log)
                {
                    _log.Add("ERR " + e.Data);
                }
            }
        };
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        var exited = Task.Run(() => _process.WaitForExit());
        var winner = await Task.WhenAny(listening.Task, exited, Task.Delay(TimeSpan.FromSeconds(90)));
        if (winner != listening.Task)
        {
            throw new InvalidOperationException("The API did not start:\n" + Log());
        }

        BaseAddress = await listening.Task;
    }

    public string Log()
    {
        lock (_log)
        {
            return string.Join('\n', _log.TakeLast(60));
        }
    }

    /// <summary>Writes the complete API log to <c>VEIL_E2E_LOG_DIR</c> (when set) so a failing run can be diagnosed.</summary>
    public async Task DumpLogAsync(string name)
    {
        var directory = Environment.GetEnvironmentVariable("VEIL_E2E_LOG_DIR");
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }

        Directory.CreateDirectory(directory);
        string[] lines;
        lock (_log)
        {
            lines = [.. _log];
        }

        await File.WriteAllLinesAsync(Path.Combine(directory, name), lines);
    }

    public async ValueTask DisposeAsync()
    {
        if (_process is { HasExited: false })
        {
            _process.Kill(entireProcessTree: true);
            await _process.WaitForExitAsync();
        }

        _process?.Dispose();
    }

    private async Task EnsureDatabaseAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(ConnectionString);
        var database = builder.Database!;
        builder.Database = "postgres";
        await using (var admin = new NpgsqlConnection(builder.ConnectionString))
        {
            await admin.OpenAsync();
            await using var exists = new NpgsqlCommand("SELECT 1 FROM pg_database WHERE datname = @name", admin);
            exists.Parameters.AddWithValue("name", database);
            if (await exists.ExecuteScalarAsync() is null)
            {
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", admin);
                await create.ExecuteNonQueryAsync();
            }
        }

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var reset = new NpgsqlCommand("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;", connection);
        await reset.ExecuteNonQueryAsync();
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Veil.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Veil.slnx not found above the test directory.");
    }

    // Plain-text console: "Now listening on: http://..."; compact JSON console: ..."address":"http://..."...
    [GeneratedRegex(@"Now listening on: (?<plain>http://[^\s""]+)|""address"":""(?<json>http://[^""]+)""")]
    private static partial Regex ListeningPattern();
}
