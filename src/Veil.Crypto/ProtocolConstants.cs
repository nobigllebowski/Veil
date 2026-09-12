using System.Text;

namespace Veil.Crypto;

/// <summary>
/// Sizes and domain-separation labels used across the protocol. Every label is versioned so that a future
/// protocol revision can never produce a value that collides with the current one.
/// </summary>
public static class ProtocolConstants
{
    public const byte Version = 0x01;

    public const int X25519KeySize = 32;
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SeedSize = 32;
    public const int Ed25519SignatureSize = 64;
    public const int MlKem768PublicKeySize = 1184;
    public const int MlKem768SeedSize = 64;
    public const int MlKem768CiphertextSize = 1088;
    public const int MlKem768SharedSecretSize = 32;
    public const int AeadKeySize = 32;
    public const int AeadNonceSize = 12;
    public const int AeadTagSize = 16;
    public const int RootKeySize = 32;
    public const int ChainKeySize = 32;
    public const int MessageKeySize = 32;
    public const int RatchetHeaderSize = X25519KeySize + sizeof(uint) + sizeof(uint);

    /// <summary>Plaintext is padded to a multiple of this size before encryption to blur message lengths.</summary>
    public const int PaddingBlockSize = 160;

    /// <summary>Upper bound of message keys a session will derive ahead for out-of-order delivery.</summary>
    public const int MaxSkippedMessageKeys = 1000;

    /// <summary>Maximum number of skipped message keys retained per session; oldest are evicted first.</summary>
    public const int MaxStoredSkippedKeys = 2000;

    public static ReadOnlySpan<byte> PqxdhInfo => "Veil_PQXDH_v1_X25519_MLKEM768_SHA256"u8;
    public static ReadOnlySpan<byte> RootKdfInfo => "Veil_DoubleRatchet_RootKDF_v1"u8;
    public static ReadOnlySpan<byte> MessageKeysInfo => "Veil_DoubleRatchet_MessageKeys_v1"u8;
    public static ReadOnlySpan<byte> SignedPreKeyLabel => "Veil_SignedPreKey_v1"u8;
    public static ReadOnlySpan<byte> KemPreKeyLabel => "Veil_KemPreKey_v1"u8;
    public static ReadOnlySpan<byte> IdentityBindingLabel => "Veil_IdentityDhKey_v1"u8;
    public static ReadOnlySpan<byte> SafetyNumberLabel => "Veil_SafetyNumber_v1"u8;

    internal static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
}
