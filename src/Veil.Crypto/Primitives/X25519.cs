using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace Veil.Crypto.Primitives;

/// <summary>Elliptic-curve Diffie–Hellman over Curve25519 (RFC 7748).</summary>
public static class X25519
{
    public static X25519KeyPair GenerateKeyPair()
    {
        var privateKey = CryptoBytes.Random(ProtocolConstants.X25519KeySize);
        return X25519KeyPair.FromPrivateKey(privateKey);
    }

    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        CryptoBytes.RequireLength(privateKey, ProtocolConstants.X25519KeySize, nameof(privateKey));
        var parameters = new X25519PrivateKeyParameters(privateKey.ToArray());
        return parameters.GeneratePublicKey().GetEncoded();
    }

    /// <summary>Computes the shared secret. Rejects the all-zero output produced by low-order points.</summary>
    public static byte[] Agree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
    {
        CryptoBytes.RequireLength(privateKey, ProtocolConstants.X25519KeySize, nameof(privateKey));
        CryptoBytes.RequireLength(peerPublicKey, ProtocolConstants.X25519KeySize, nameof(peerPublicKey));

        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(privateKey.ToArray()));
        var shared = new byte[agreement.AgreementSize];

        try
        {
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublicKey.ToArray()), shared);
        }
        catch (InvalidOperationException ex)
        {
            // BouncyCastle rejects low-order points itself; normalise to the library's exception type.
            throw new CryptoException("X25519 agreement failed (low-order or invalid public key).", ex);
        }

        if (IsAllZero(shared))
        {
            CryptoBytes.Zero(shared);
            throw new CryptoException("X25519 agreement produced an all-zero secret (low-order public key).");
        }

        return shared;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        byte acc = 0;
        foreach (var b in data)
        {
            acc |= b;
        }

        return acc == 0;
    }
}

/// <summary>X25519 key pair. Private key material is zeroed on dispose.</summary>
public sealed class X25519KeyPair : IDisposable
{
    private bool _disposed;

    private X25519KeyPair(byte[] privateKey, byte[] publicKey)
    {
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    public byte[] PrivateKey { get; }
    public byte[] PublicKey { get; }

    public static X25519KeyPair FromPrivateKey(byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        return new X25519KeyPair(privateKey, X25519.DerivePublicKey(privateKey));
    }

    public static X25519KeyPair From(byte[] privateKey, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(publicKey);
        CryptoBytes.RequireLength(privateKey, ProtocolConstants.X25519KeySize, nameof(privateKey));
        CryptoBytes.RequireLength(publicKey, ProtocolConstants.X25519KeySize, nameof(publicKey));
        return new X25519KeyPair(privateKey, publicKey);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptoBytes.Zero(PrivateKey);
        _disposed = true;
    }
}
