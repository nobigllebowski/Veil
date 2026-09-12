using Veil.Crypto.Primitives;

namespace Veil.Crypto.Keys;

/// <summary>
/// Long-term identity of a device: an Ed25519 signing key (authenticates pre-keys) and an X25519 DH key
/// (participates in key agreement). The DH key is bound to the signing key by a signature so a bundle cannot mix
/// identity keys from two different devices.
/// </summary>
public sealed class IdentityKeyPair : IDisposable
{
    private IdentityKeyPair(Ed25519KeyPair signingKey, X25519KeyPair dhKey, byte[] dhKeySignature)
    {
        SigningKey = signingKey;
        DhKey = dhKey;
        DhKeySignature = dhKeySignature;
    }

    public Ed25519KeyPair SigningKey { get; }
    public X25519KeyPair DhKey { get; }
    public byte[] DhKeySignature { get; }

    public IdentityPublicKeys Public => new(SigningKey.PublicKey, DhKey.PublicKey, DhKeySignature);

    public static IdentityKeyPair Generate()
    {
        var signing = Ed25519.GenerateKeyPair();
        var dh = X25519.GenerateKeyPair();
        var signature = signing.Sign(SignedMaterial.IdentityBinding(dh.PublicKey));
        return new IdentityKeyPair(signing, dh, signature);
    }

    public static IdentityKeyPair From(byte[] signingSeed, byte[] dhPrivateKey)
    {
        var signing = Ed25519KeyPair.FromSeed(signingSeed);
        var dh = X25519KeyPair.FromPrivateKey(dhPrivateKey);
        var signature = signing.Sign(SignedMaterial.IdentityBinding(dh.PublicKey));
        return new IdentityKeyPair(signing, dh, signature);
    }

    public byte[] Sign(ReadOnlySpan<byte> message) => SigningKey.Sign(message);

    public void Dispose()
    {
        SigningKey.Dispose();
        DhKey.Dispose();
    }
}

/// <summary>Public half of an identity, as published to the server and to peers.</summary>
public sealed record IdentityPublicKeys(byte[] SigningKey, byte[] DhKey, byte[] DhKeySignature)
{
    public bool Verify() => Ed25519.Verify(SigningKey, SignedMaterial.IdentityBinding(DhKey), DhKeySignature);

    /// <summary>Stable fingerprint of the identity (SHA-256 over both public keys) suitable for display and comparison.</summary>
    public byte[] Fingerprint() => Kdf.Sha256(CryptoBytes.Concat(SigningKey, DhKey));

    public bool Equals(IdentityPublicKeys? other) =>
        other is not null &&
        SigningKey.AsSpan().SequenceEqual(other.SigningKey) &&
        DhKey.AsSpan().SequenceEqual(other.DhKey);

    public override int GetHashCode() => BitConverter.ToInt32(Fingerprint(), 0);
}
