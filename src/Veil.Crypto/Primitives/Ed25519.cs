using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Veil.Crypto.Primitives;

/// <summary>EdDSA signatures over edwards25519 (RFC 8032, pure Ed25519).</summary>
public static class Ed25519
{
    public static Ed25519KeyPair GenerateKeyPair() =>
        Ed25519KeyPair.FromSeed(CryptoBytes.Random(ProtocolConstants.Ed25519SeedSize));

    public static byte[] DerivePublicKey(ReadOnlySpan<byte> seed)
    {
        CryptoBytes.RequireLength(seed, ProtocolConstants.Ed25519SeedSize, nameof(seed));
        return new Ed25519PrivateKeyParameters(seed.ToArray()).GeneratePublicKey().GetEncoded();
    }

    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        CryptoBytes.RequireLength(seed, ProtocolConstants.Ed25519SeedSize, nameof(seed));
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, new Ed25519PrivateKeyParameters(seed.ToArray()));
        signer.BlockUpdate(message);
        return signer.GenerateSignature();
    }

    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != ProtocolConstants.Ed25519PublicKeySize || signature.Length != ProtocolConstants.Ed25519SignatureSize)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(publicKey.ToArray()));
            verifier.BlockUpdate(message);
            return verifier.VerifySignature(signature.ToArray());
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Org.BouncyCastle.Crypto.CryptoException)
        {
            return false;
        }
    }
}

/// <summary>Ed25519 key pair. The private key is the 32-byte RFC 8032 seed.</summary>
public sealed class Ed25519KeyPair : IDisposable
{
    private bool _disposed;

    private Ed25519KeyPair(byte[] seed, byte[] publicKey)
    {
        Seed = seed;
        PublicKey = publicKey;
    }

    public byte[] Seed { get; }
    public byte[] PublicKey { get; }

    public static Ed25519KeyPair FromSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        return new Ed25519KeyPair(seed, Ed25519.DerivePublicKey(seed));
    }

    public byte[] Sign(ReadOnlySpan<byte> message) => Ed25519.Sign(Seed, message);

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
