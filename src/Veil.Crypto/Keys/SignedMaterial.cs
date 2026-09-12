using Veil.Crypto.Primitives;

namespace Veil.Crypto.Keys;

/// <summary>
/// Canonical, domain-separated encodings of pre-key material as signed by an identity key. A signature over a
/// signed pre-key can never be confused with a signature over a KEM pre-key or any other protocol message.
/// </summary>
public static class SignedMaterial
{
    public static byte[] SignedPreKey(uint keyId, ReadOnlySpan<byte> publicKey) =>
        Encode(ProtocolConstants.SignedPreKeyLabel, keyId, publicKey);

    public static byte[] KemPreKey(uint keyId, ReadOnlySpan<byte> publicKey) =>
        Encode(ProtocolConstants.KemPreKeyLabel, keyId, publicKey);

    /// <summary>Binds the X25519 identity DH key to the Ed25519 identity signing key.</summary>
    public static byte[] IdentityBinding(ReadOnlySpan<byte> identityDhKey) =>
        Encode(ProtocolConstants.IdentityBindingLabel, 0, identityDhKey);

    private static byte[] Encode(ReadOnlySpan<byte> label, uint keyId, ReadOnlySpan<byte> publicKey)
    {
        var result = new byte[1 + label.Length + sizeof(uint) + publicKey.Length];
        result[0] = ProtocolConstants.Version;
        label.CopyTo(result.AsSpan(1));
        CryptoBytes.UInt32BigEndian(keyId).CopyTo(result.AsSpan(1 + label.Length));
        publicKey.CopyTo(result.AsSpan(1 + label.Length + sizeof(uint)));
        return result;
    }
}
