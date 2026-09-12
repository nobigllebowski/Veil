using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;

namespace Veil.Crypto.Protocol;

/// <summary>
/// Human-comparable fingerprint of two identities (the "safety number"). Two users who read the same 60 digits
/// to each other over a trusted channel have verified that no one - including the server - substituted keys.
/// </summary>
public static class SafetyNumber
{
    private const int Iterations = 5200;
    private const int FingerprintBytes = 30;

    public static string Compute(IdentityPublicKeys localIdentity, string localIdentifier, IdentityPublicKeys remoteIdentity, string remoteIdentifier)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(remoteIdentity);

        var local = Fingerprint(localIdentity, localIdentifier);
        var remote = Fingerprint(remoteIdentity, remoteIdentifier);

        // Order lexicographically so both parties compute the identical string.
        var ordered = string.CompareOrdinal(local, remote) <= 0 ? local + remote : remote + local;
        return string.Join(' ', Enumerable.Range(0, ordered.Length / 5).Select(i => ordered.Substring(i * 5, 5)));
    }

    private static string Fingerprint(IdentityPublicKeys identity, string identifier)
    {
        var keyMaterial = CryptoBytes.Concat(identity.SigningKey, identity.DhKey);
        var identifierBytes = Encoding.UTF8.GetBytes(identifier.Normalize(NormalizationForm.FormKC));
        var hash = CryptoBytes.Concat(ProtocolConstants.SafetyNumberLabel.ToArray(), keyMaterial, identifierBytes);

        for (var i = 0; i < Iterations; i++)
        {
            hash = Kdf.Sha512(CryptoBytes.Concat(hash, keyMaterial));
        }

        var digits = new StringBuilder(30);
        for (var i = 0; i < FingerprintBytes; i += 5)
        {
            var chunk = hash.AsSpan(i, 5);
            ulong value = ((ulong)chunk[0] << 32) | BinaryPrimitives.ReadUInt32BigEndian(chunk[1..]);
            digits.Append((value % 100000).ToString("D5", CultureInfo.InvariantCulture));
        }

        return digits.ToString();
    }
}
