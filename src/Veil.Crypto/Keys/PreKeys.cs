using Veil.Crypto.Primitives;

namespace Veil.Crypto.Keys;

/// <summary>Medium-term X25519 pre-key, signed by the identity key. Rotated periodically (e.g. weekly).</summary>
public sealed class SignedPreKeyPair : IDisposable
{
    private SignedPreKeyPair(uint id, X25519KeyPair keyPair, byte[] signature, DateTimeOffset createdAt)
    {
        Id = id;
        KeyPair = keyPair;
        Signature = signature;
        CreatedAt = createdAt;
    }

    public uint Id { get; }
    public X25519KeyPair KeyPair { get; }
    public byte[] Signature { get; }
    public DateTimeOffset CreatedAt { get; }

    public static SignedPreKeyPair Generate(IdentityKeyPair identity, uint id, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var pair = X25519.GenerateKeyPair();
        var signature = identity.Sign(SignedMaterial.SignedPreKey(id, pair.PublicKey));
        return new SignedPreKeyPair(id, pair, signature, (time ?? TimeProvider.System).GetUtcNow());
    }

    public static SignedPreKeyPair From(uint id, byte[] privateKey, byte[] signature, DateTimeOffset createdAt) =>
        new(id, X25519KeyPair.FromPrivateKey(privateKey), signature, createdAt);

    public void Dispose() => KeyPair.Dispose();
}

/// <summary>Medium-term ML-KEM-768 pre-key ("last-resort" post-quantum pre-key), signed by the identity key.</summary>
public sealed class KemPreKeyPair : IDisposable
{
    private KemPreKeyPair(uint id, MlKemKeyPair keyPair, byte[] signature, DateTimeOffset createdAt)
    {
        Id = id;
        KeyPair = keyPair;
        Signature = signature;
        CreatedAt = createdAt;
    }

    public uint Id { get; }
    public MlKemKeyPair KeyPair { get; }
    public byte[] Signature { get; }
    public DateTimeOffset CreatedAt { get; }

    public static KemPreKeyPair Generate(IdentityKeyPair identity, uint id, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var pair = MlKem768.GenerateKeyPair();
        var signature = identity.Sign(SignedMaterial.KemPreKey(id, pair.PublicKey));
        return new KemPreKeyPair(id, pair, signature, (time ?? TimeProvider.System).GetUtcNow());
    }

    public static KemPreKeyPair From(uint id, byte[] seed, byte[] signature, DateTimeOffset createdAt) =>
        new(id, MlKemKeyPair.FromSeed(seed), signature, createdAt);

    public void Dispose() => KeyPair.Dispose();
}

/// <summary>Single-use X25519 pre-key. Consumed by exactly one handshake, then deleted.</summary>
public sealed class OneTimePreKeyPair : IDisposable
{
    private OneTimePreKeyPair(uint id, X25519KeyPair keyPair)
    {
        Id = id;
        KeyPair = keyPair;
    }

    public uint Id { get; }
    public X25519KeyPair KeyPair { get; }

    public static OneTimePreKeyPair Generate(uint id) => new(id, X25519.GenerateKeyPair());

    public static OneTimePreKeyPair From(uint id, byte[] privateKey) => new(id, X25519KeyPair.FromPrivateKey(privateKey));

    public void Dispose() => KeyPair.Dispose();
}
