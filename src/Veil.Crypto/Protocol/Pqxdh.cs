using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;

namespace Veil.Crypto.Protocol;

/// <summary>
/// PQXDH: the Signal "Extended Triple Diffie-Hellman" handshake hardened with an ML-KEM-768 encapsulation.
/// The classical X25519 agreements provide authentication and forward secrecy; the KEM secret is mixed into the
/// key derivation so that breaking X25519 alone (e.g. with a quantum computer) is not enough to recover the session key.
/// </summary>
public static class Pqxdh
{
    private static readonly byte[] DiscriminatorPrefix = Enumerable.Repeat((byte)0xFF, 32).ToArray();
    private static readonly byte[] ZeroSalt = new byte[32];

    /// <summary>Alice: derives the session secret from Bob's published bundle.</summary>
    public static InitiatorHandshake Initiate(IdentityKeyPair localIdentity, PreKeyBundle remoteBundle)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(remoteBundle);

        remoteBundle.Verify();

        using var ephemeral = X25519.GenerateKeyPair();
        var (kemCiphertext, kemSecret) = MlKem768.Encapsulate(remoteBundle.KemPreKey);

        var dh1 = X25519.Agree(localIdentity.DhKey.PrivateKey, remoteBundle.SignedPreKey);
        var dh2 = X25519.Agree(ephemeral.PrivateKey, remoteBundle.Identity.DhKey);
        var dh3 = X25519.Agree(ephemeral.PrivateKey, remoteBundle.SignedPreKey);
        var dh4 = remoteBundle.HasOneTimePreKey ? X25519.Agree(ephemeral.PrivateKey, remoteBundle.OneTimePreKey!) : null;

        var sharedSecret = DeriveSharedSecret(dh1, dh2, dh3, dh4, kemSecret);
        var associatedData = BuildAssociatedData(localIdentity.Public, remoteBundle.Identity);

        var header = new PreKeyHeader(
            localIdentity.Public,
            [.. ephemeral.PublicKey],
            remoteBundle.SignedPreKeyId,
            remoteBundle.OneTimePreKeyId,
            remoteBundle.KemPreKeyId,
            kemCiphertext);

        return new InitiatorHandshake(sharedSecret, associatedData, header, remoteBundle.SignedPreKey);
    }

    /// <summary>Bob: reconstructs the session secret from the pre-key header using his private pre-keys.</summary>
    public static ResponderHandshake Respond(DeviceKeyStore localKeys, PreKeyHeader header)
    {
        ArgumentNullException.ThrowIfNull(localKeys);
        ArgumentNullException.ThrowIfNull(header);

        if (!header.InitiatorIdentity.Verify())
        {
            throw new InvalidSignatureException("Initiator identity DH key is not bound to its signing key.");
        }

        var signedPreKey = localKeys.FindSignedPreKey(header.SignedPreKeyId)
            ?? throw new SessionException($"Signed pre-key {header.SignedPreKeyId} is unknown or has been retired.");
        var kemPreKey = localKeys.FindKemPreKey(header.KemPreKeyId)
            ?? throw new SessionException($"KEM pre-key {header.KemPreKeyId} is unknown or has been retired.");

        OneTimePreKeyPair? oneTime = null;
        if (header.OneTimePreKeyId is { } oneTimeId)
        {
            oneTime = localKeys.TakeOneTimePreKey(oneTimeId)
                ?? throw new SessionException($"One-time pre-key {oneTimeId} was already consumed (possible replay).");
        }

        try
        {
            var kemSecret = MlKem768.Decapsulate(kemPreKey.KeyPair.Seed, header.KemCiphertext);
            var dh1 = X25519.Agree(signedPreKey.KeyPair.PrivateKey, header.InitiatorIdentity.DhKey);
            var dh2 = X25519.Agree(localKeys.Identity.DhKey.PrivateKey, header.EphemeralKey);
            var dh3 = X25519.Agree(signedPreKey.KeyPair.PrivateKey, header.EphemeralKey);
            var dh4 = oneTime is null ? null : X25519.Agree(oneTime.KeyPair.PrivateKey, header.EphemeralKey);

            var sharedSecret = DeriveSharedSecret(dh1, dh2, dh3, dh4, kemSecret);
            var associatedData = BuildAssociatedData(header.InitiatorIdentity, localKeys.Identity.Public);

            return new ResponderHandshake(sharedSecret, associatedData, signedPreKey.KeyPair);
        }
        finally
        {
            oneTime?.Dispose();
        }
    }

    private static byte[] DeriveSharedSecret(byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4, byte[] kemSecret)
    {
        var ikm = dh4 is null
            ? CryptoBytes.Concat(DiscriminatorPrefix, dh1, dh2, dh3, kemSecret)
            : CryptoBytes.Concat(DiscriminatorPrefix, dh1, dh2, dh3, dh4, kemSecret);

        var secret = Kdf.Hkdf(ikm, ZeroSalt, ProtocolConstants.PqxdhInfo, ProtocolConstants.RootKeySize);

        CryptoBytes.Zero(ikm);
        CryptoBytes.Zero(dh1);
        CryptoBytes.Zero(dh2);
        CryptoBytes.Zero(dh3);
        if (dh4 is not null)
        {
            CryptoBytes.Zero(dh4);
        }

        CryptoBytes.Zero(kemSecret);
        return secret;
    }

    /// <summary>AD = initiator identity || responder identity. Binds every message to both long-term identities.</summary>
    private static byte[] BuildAssociatedData(IdentityPublicKeys initiator, IdentityPublicKeys responder) =>
        CryptoBytes.Concat(initiator.SigningKey, initiator.DhKey, responder.SigningKey, responder.DhKey);
}

public sealed record InitiatorHandshake(byte[] SharedSecret, byte[] AssociatedData, PreKeyHeader Header, byte[] ResponderRatchetKey);

public sealed record ResponderHandshake(byte[] SharedSecret, byte[] AssociatedData, X25519KeyPair OwnRatchetKeyPair);
