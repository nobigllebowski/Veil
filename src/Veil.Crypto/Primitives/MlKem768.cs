using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Veil.Crypto.Primitives;

/// <summary>
/// ML-KEM-768 (FIPS 203) key encapsulation. Provides the post-quantum half of the hybrid PQXDH handshake so that
/// a future quantum adversary who recorded traffic today cannot recover session keys ("harvest now, decrypt later").
/// </summary>
public static class MlKem768
{
    private static readonly MLKemParameters Parameters = MLKemParameters.ml_kem_768;

    public static MlKemKeyPair GenerateKeyPair()
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), Parameters));
        var pair = generator.GenerateKeyPair();
        var privateKey = (MLKemPrivateKeyParameters)pair.Private;
        return MlKemKeyPair.From(privateKey.GetSeed(), privateKey.GetPublicKeyEncoded());
    }

    public static byte[] DerivePublicKey(ReadOnlySpan<byte> seed)
    {
        CryptoBytes.RequireLength(seed, ProtocolConstants.MlKem768SeedSize, nameof(seed));
        return MLKemPrivateKeyParameters.FromSeed(Parameters, seed.ToArray()).GetPublicKeyEncoded();
    }

    /// <summary>Encapsulates a fresh 32-byte shared secret to <paramref name="publicKey"/>.</summary>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        CryptoBytes.RequireLength(publicKey, ProtocolConstants.MlKem768PublicKeySize, nameof(publicKey));

        var encapsulator = new MLKemEncapsulator(Parameters);
        encapsulator.Init(MLKemPublicKeyParameters.FromEncoding(Parameters, publicKey.ToArray()));

        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, secret);
        return (ciphertext, secret);
    }

    public static byte[] Decapsulate(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> ciphertext)
    {
        CryptoBytes.RequireLength(seed, ProtocolConstants.MlKem768SeedSize, nameof(seed));
        CryptoBytes.RequireLength(ciphertext, ProtocolConstants.MlKem768CiphertextSize, nameof(ciphertext));

        var decapsulator = new MLKemDecapsulator(Parameters);
        decapsulator.Init(MLKemPrivateKeyParameters.FromSeed(Parameters, seed.ToArray()));

        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext, secret);
        return secret;
    }
}

/// <summary>ML-KEM-768 key pair. The private key is stored in its compact 64-byte seed form (d || z).</summary>
public sealed class MlKemKeyPair : IDisposable
{
    private bool _disposed;

    private MlKemKeyPair(byte[] seed, byte[] publicKey)
    {
        Seed = seed;
        PublicKey = publicKey;
    }

    public byte[] Seed { get; }
    public byte[] PublicKey { get; }

    public static MlKemKeyPair From(byte[] seed, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(publicKey);
        CryptoBytes.RequireLength(seed, ProtocolConstants.MlKem768SeedSize, nameof(seed));
        CryptoBytes.RequireLength(publicKey, ProtocolConstants.MlKem768PublicKeySize, nameof(publicKey));
        return new MlKemKeyPair(seed, publicKey);
    }

    public static MlKemKeyPair FromSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        return new MlKemKeyPair(seed, MlKem768.DerivePublicKey(seed));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptoBytes.Zero(Seed);
        _disposed = true;
    }
}
