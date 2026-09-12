using Veil.Crypto.Primitives;

namespace Veil.Crypto.Keys;

/// <summary>
/// Everything an initiator needs to start a session with a remote device. Served by the server, but every
/// component is signed by the device's identity key, so a malicious server cannot substitute keys without
/// breaking the signatures (and the identity key itself is verified out-of-band via safety numbers).
/// </summary>
public sealed record PreKeyBundle(
    IdentityPublicKeys Identity,
    uint SignedPreKeyId,
    byte[] SignedPreKey,
    byte[] SignedPreKeySignature,
    uint KemPreKeyId,
    byte[] KemPreKey,
    byte[] KemPreKeySignature,
    uint? OneTimePreKeyId,
    byte[]? OneTimePreKey)
{
    public bool HasOneTimePreKey => OneTimePreKeyId.HasValue && OneTimePreKey is not null;

    /// <summary>Verifies every signature in the bundle. Throws <see cref="InvalidSignatureException"/> on failure.</summary>
    public void Verify()
    {
        if (!Identity.Verify())
        {
            throw new InvalidSignatureException("Identity DH key is not bound to the identity signing key.");
        }

        if (SignedPreKey.Length != ProtocolConstants.X25519KeySize ||
            !Ed25519.Verify(Identity.SigningKey, SignedMaterial.SignedPreKey(SignedPreKeyId, SignedPreKey), SignedPreKeySignature))
        {
            throw new InvalidSignatureException("Signed pre-key signature is invalid.");
        }

        if (KemPreKey.Length != ProtocolConstants.MlKem768PublicKeySize ||
            !Ed25519.Verify(Identity.SigningKey, SignedMaterial.KemPreKey(KemPreKeyId, KemPreKey), KemPreKeySignature))
        {
            throw new InvalidSignatureException("KEM pre-key signature is invalid.");
        }

        if (OneTimePreKey is not null && OneTimePreKey.Length != ProtocolConstants.X25519KeySize)
        {
            throw new MalformedMessageException("One-time pre-key has an invalid length.");
        }
    }
}
