using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Veil.Crypto.Primitives;

/// <summary>Argon2id (RFC 9106) key derivation for passphrase-protected local storage.</summary>
public static class Argon2id
{
    public const int DefaultMemoryKiB = 64 * 1024;
    public const int DefaultIterations = 3;
    public const int DefaultParallelism = 4;

    public static byte[] DeriveKey(ReadOnlySpan<byte> passphrase, ReadOnlySpan<byte> salt, int outputLength, int memoryKiB = DefaultMemoryKiB, int iterations = DefaultIterations, int parallelism = DefaultParallelism)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputLength);
        ArgumentOutOfRangeException.ThrowIfLessThan(salt.Length, 8);

        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(memoryKiB)
            .WithIterations(iterations)
            .WithParallelism(parallelism)
            .WithSalt(salt.ToArray())
            .Build();

        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);
        var output = new byte[outputLength];
        generator.GenerateBytes(passphrase.ToArray(), output);
        return output;
    }
}
