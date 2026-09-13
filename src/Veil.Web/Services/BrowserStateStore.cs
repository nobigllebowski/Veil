using System.Text;
using Veil.Client.Sdk;
using Veil.Crypto;
using Veil.Crypto.Primitives;

namespace Veil.Web.Services;

/// <summary>
/// Keeps the client state (device keys, ratchet sessions, history) in <c>localStorage</c>, encrypted with
/// AES-256-GCM under a key derived from the account password with Argon2id. The derived key lives only in
/// <c>sessionStorage</c>, so a closed tab needs the password again while a reload does not.
/// </summary>
public sealed class BrowserStateStore(BrowserStorage storage, string username, byte[] key) : IClientStateStore
{
    private const string Prefix = "veil.state.";
    private static readonly byte[] Purpose = "Veil_BrowserState_v1"u8.ToArray();

    // Tuned for the WebAssembly interpreter: still memory-hard, but unlocks in about a second on a laptop.
    public const int Argon2MemoryKiB = 24 * 1024;
    public const int Argon2Iterations = 2;
    public const int Argon2Parallelism = 1;

    public static string StateKey(string username) => Prefix + username.ToLowerInvariant();
    public static string SaltKey(string username) => "veil.salt." + username.ToLowerInvariant();
    public static string SessionKey(string username) => "veil.key." + username.ToLowerInvariant();

    public static async Task<IReadOnlyList<string>> KnownAccountsAsync(BrowserStorage storage)
    {
        var keys = await storage.ListLocalKeysAsync(Prefix);
        return keys.Select(k => k[Prefix.Length..]).OrderBy(k => k, StringComparer.Ordinal).ToList();
    }

    public static async Task<bool> ExistsAsync(BrowserStorage storage, string username) =>
        await storage.GetLocalAsync(StateKey(username)) is not null;

    public static byte[] DeriveKey(string password, byte[] salt) =>
        Argon2id.DeriveKey(Encoding.UTF8.GetBytes(password), salt, ProtocolConstants.AeadKeySize, Argon2MemoryKiB, Argon2Iterations, Argon2Parallelism);

    public static async Task<byte[]> GetOrCreateSaltAsync(BrowserStorage storage, string username)
    {
        var existing = await storage.GetLocalAsync(SaltKey(username));
        if (existing is not null)
        {
            return Convert.FromBase64String(existing);
        }

        var salt = CryptoBytes.Random(16);
        await storage.SetLocalAsync(SaltKey(username), Convert.ToBase64String(salt));
        return salt;
    }

    public static async Task WipeAsync(BrowserStorage storage, string username)
    {
        await storage.RemoveLocalAsync(StateKey(username));
        await storage.RemoveLocalAsync(SaltKey(username));
        await storage.RemoveSessionAsync(SessionKey(username));
    }

    public async Task<ClientState?> LoadAsync(CancellationToken cancellationToken = default)
    {
        var blob = await storage.GetLocalAsync(StateKey(username));
        if (blob is null)
        {
            return null;
        }

        var bytes = Convert.FromBase64String(blob);
        if (bytes.Length < ProtocolConstants.AeadNonceSize + ProtocolConstants.AeadTagSize)
        {
            throw new InvalidDataException("Stored state is corrupted.");
        }

        try
        {
            var plaintext = Aead.Decrypt(key, bytes.AsSpan(0, ProtocolConstants.AeadNonceSize), bytes.AsSpan(ProtocolConstants.AeadNonceSize), Purpose);
            var state = ClientState.Deserialize(plaintext);
            CryptoBytes.Zero(plaintext);
            return state;
        }
        catch (DecryptionFailedException ex)
        {
            throw new UnauthorizedAccessException("Wrong password for the local state.", ex);
        }
    }

    public async Task SaveAsync(ClientState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        var nonce = CryptoBytes.Random(ProtocolConstants.AeadNonceSize);
        var plaintext = state.Serialize();
        var ciphertext = Aead.Encrypt(key, nonce, plaintext, Purpose);
        CryptoBytes.Zero(plaintext);
        await storage.SetLocalAsync(StateKey(username), Convert.ToBase64String(CryptoBytes.Concat(nonce, ciphertext)));
    }
}
