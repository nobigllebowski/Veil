using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Veil.Application.Abstractions.Security;
using Veil.Infrastructure.Options;

namespace Veil.Infrastructure.Security;

/// <summary>
/// Argon2id in PHC string format: <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;salt&gt;$&lt;hash&gt;</c>.
/// Parameters are stored with the hash, so costs can be raised later and old hashes still verify (and get flagged for rehash).
/// </summary>
public sealed class Argon2PasswordHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly Argon2Options _options;
    private readonly string _dummyHash;

    public Argon2PasswordHasher(IOptions<SecurityOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value.Argon2;
        _dummyHash = Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
    }

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(password, salt, _options.MemoryKiB, _options.Iterations, _options.Parallelism);
        return string.Create(CultureInfo.InvariantCulture,
            $"$argon2id$v=19$m={_options.MemoryKiB},t={_options.Iterations},p={_options.Parallelism}${ToBase64NoPad(salt)}${ToBase64NoPad(hash)}");
    }

    public PasswordVerification Verify(string password, string hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (!TryParse(hash, out var memory, out var iterations, out var parallelism, out var salt, out var expected))
        {
            return PasswordVerification.Failed;
        }

        var actual = Derive(password, salt, memory, iterations, parallelism);
        var matches = CryptographicOperations.FixedTimeEquals(actual, expected);
        CryptographicOperations.ZeroMemory(actual);
        if (!matches)
        {
            return PasswordVerification.Failed;
        }

        var current = memory == _options.MemoryKiB && iterations == _options.Iterations && parallelism == _options.Parallelism;
        return current ? PasswordVerification.Success : PasswordVerification.SuccessRehashNeeded;
    }

    public void MitigateTiming(string password) => Verify(password, _dummyHash);

    private static byte[] Derive(string password, byte[] salt, int memoryKiB, int iterations, int parallelism)
    {
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(memoryKiB)
            .WithIterations(iterations)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();

        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);
        var output = new byte[HashSize];
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            generator.GenerateBytes(passwordBytes, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }

        return output;
    }

    private static bool TryParse(string? encoded, out int memory, out int iterations, out int parallelism, out byte[] salt, out byte[] hash)
    {
        memory = iterations = parallelism = 0;
        salt = hash = [];
        if (string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5 || parts[0] != "argon2id" || parts[1] != "v=19")
        {
            return false;
        }

        foreach (var kv in parts[2].Split(','))
        {
            var pair = kv.Split('=');
            if (pair.Length != 2 || !int.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value <= 0)
            {
                return false;
            }

            switch (pair[0])
            {
                case "m": memory = value; break;
                case "t": iterations = value; break;
                case "p": parallelism = value; break;
                default: return false;
            }
        }

        if (memory == 0 || iterations == 0 || parallelism == 0)
        {
            return false;
        }

        try
        {
            salt = FromBase64NoPad(parts[3]);
            hash = FromBase64NoPad(parts[4]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length == SaltSize && hash.Length == HashSize;
    }

    private static string ToBase64NoPad(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    private static byte[] FromBase64NoPad(string data) => Convert.FromBase64String(data.PadRight(data.Length + ((4 - (data.Length % 4)) % 4), '='));
}
