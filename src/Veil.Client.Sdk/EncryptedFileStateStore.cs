using System.Text;
using Veil.Crypto;
using Veil.Crypto.Primitives;

namespace Veil.Client.Sdk;

/// <summary>
/// Stores the client state in a single file encrypted with AES-256-GCM under a key derived from the user's
/// passphrase with Argon2id. Layout: <c>"VEIL" || version || salt(16) || nonce(12) || ciphertext || tag</c>.
/// </summary>
public sealed class EncryptedFileStateStore(string path, string passphrase) : IClientStateStore
{
    private const byte FormatVersion = 1;
    private const int SaltSize = 16;
    private static readonly byte[] Magic = "VEIL"u8.ToArray();
    private static readonly byte[] Purpose = "Veil_ClientState_v1"u8.ToArray();

    public string Path { get; } = path;

    public async Task<ClientState?> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(Path))
        {
            return null;
        }

        var blob = await File.ReadAllBytesAsync(Path, cancellationToken);
        if (blob.Length < Magic.Length + 1 + SaltSize + ProtocolConstants.AeadNonceSize + ProtocolConstants.AeadTagSize ||
            !blob.AsSpan(0, Magic.Length).SequenceEqual(Magic) || blob[Magic.Length] != FormatVersion)
        {
            throw new InvalidDataException("Not a Veil state file or unsupported version.");
        }

        var offset = Magic.Length + 1;
        var salt = blob.AsSpan(offset, SaltSize);
        offset += SaltSize;
        var nonce = blob.AsSpan(offset, ProtocolConstants.AeadNonceSize);
        offset += ProtocolConstants.AeadNonceSize;

        var key = DeriveKey(salt);
        try
        {
            var plaintext = Aead.Decrypt(key, nonce, blob.AsSpan(offset), Purpose);
            var state = ClientState.Deserialize(plaintext);
            CryptoBytes.Zero(plaintext);
            return state;
        }
        catch (DecryptionFailedException ex)
        {
            throw new UnauthorizedAccessException("Wrong passphrase or corrupted state file.", ex);
        }
        finally
        {
            CryptoBytes.Zero(key);
        }
    }

    public async Task SaveAsync(ClientState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        var salt = CryptoBytes.Random(SaltSize);
        var nonce = CryptoBytes.Random(ProtocolConstants.AeadNonceSize);
        var key = DeriveKey(salt);
        var plaintext = state.Serialize();

        try
        {
            var ciphertext = Aead.Encrypt(key, nonce, plaintext, Purpose);
            var blob = CryptoBytes.Concat(Magic, [FormatVersion], salt, nonce, ciphertext);

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            var temp = Path + ".tmp";
            await File.WriteAllBytesAsync(temp, blob, cancellationToken);
            File.Move(temp, Path, overwrite: true);
        }
        finally
        {
            CryptoBytes.Zero(key);
            CryptoBytes.Zero(plaintext);
        }
    }

    private byte[] DeriveKey(ReadOnlySpan<byte> salt) =>
        Argon2id.DeriveKey(Encoding.UTF8.GetBytes(passphrase), salt, ProtocolConstants.AeadKeySize);
}
