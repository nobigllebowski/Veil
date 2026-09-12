namespace Veil.Crypto.Keys;

/// <summary>
/// All private key material owned by one device. Lives only on the device; the server sees public keys only.
/// </summary>
public sealed class DeviceKeyStore : IDisposable
{
    private readonly Dictionary<uint, SignedPreKeyPair> _signedPreKeys = new();
    private readonly Dictionary<uint, KemPreKeyPair> _kemPreKeys = new();
    private readonly Dictionary<uint, OneTimePreKeyPair> _oneTimePreKeys = new();
    private uint _nextSignedPreKeyId;
    private uint _nextKemPreKeyId;
    private uint _nextOneTimePreKeyId;

    private DeviceKeyStore(IdentityKeyPair identity)
    {
        Identity = identity;
    }

    public IdentityKeyPair Identity { get; }
    public uint CurrentSignedPreKeyId { get; private set; }
    public uint CurrentKemPreKeyId { get; private set; }
    public SignedPreKeyPair CurrentSignedPreKey => _signedPreKeys[CurrentSignedPreKeyId];
    public KemPreKeyPair CurrentKemPreKey => _kemPreKeys[CurrentKemPreKeyId];
    public int AvailableOneTimePreKeys => _oneTimePreKeys.Count;

    /// <summary>Creates a brand-new device: fresh identity, one signed pre-key, one KEM pre-key and a batch of one-time pre-keys.</summary>
    public static DeviceKeyStore Generate(int oneTimePreKeyCount = 100, TimeProvider? time = null)
    {
        var store = new DeviceKeyStore(IdentityKeyPair.Generate());
        store.RotateSignedPreKey(time);
        store.RotateKemPreKey(time);
        if (oneTimePreKeyCount > 0)
        {
            store.GenerateOneTimePreKeys(oneTimePreKeyCount);
        }

        return store;
    }

    public SignedPreKeyPair RotateSignedPreKey(TimeProvider? time = null)
    {
        var id = ++_nextSignedPreKeyId;
        var key = SignedPreKeyPair.Generate(Identity, id, time);
        _signedPreKeys[id] = key;
        CurrentSignedPreKeyId = id;
        return key;
    }

    public KemPreKeyPair RotateKemPreKey(TimeProvider? time = null)
    {
        var id = ++_nextKemPreKeyId;
        var key = KemPreKeyPair.Generate(Identity, id, time);
        _kemPreKeys[id] = key;
        CurrentKemPreKeyId = id;
        return key;
    }

    /// <summary>Generates a batch of one-time pre-keys and returns them so their public halves can be uploaded.</summary>
    public IReadOnlyList<OneTimePreKeyPair> GenerateOneTimePreKeys(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        var batch = new List<OneTimePreKeyPair>(count);
        for (var i = 0; i < count; i++)
        {
            var id = ++_nextOneTimePreKeyId;
            var key = OneTimePreKeyPair.Generate(id);
            _oneTimePreKeys[id] = key;
            batch.Add(key);
        }

        return batch;
    }

    /// <summary>Removes pre-keys older than <paramref name="retention"/> that are no longer current (grace period for in-flight handshakes).</summary>
    public void PruneStalePreKeys(TimeSpan retention, TimeProvider? time = null)
    {
        var now = (time ?? TimeProvider.System).GetUtcNow();
        foreach (var (id, key) in _signedPreKeys.ToArray())
        {
            if (id != CurrentSignedPreKeyId && now - key.CreatedAt > retention)
            {
                key.Dispose();
                _signedPreKeys.Remove(id);
            }
        }

        foreach (var (id, key) in _kemPreKeys.ToArray())
        {
            if (id != CurrentKemPreKeyId && now - key.CreatedAt > retention)
            {
                key.Dispose();
                _kemPreKeys.Remove(id);
            }
        }
    }

    public SignedPreKeyPair? FindSignedPreKey(uint id) => _signedPreKeys.GetValueOrDefault(id);

    public KemPreKeyPair? FindKemPreKey(uint id) => _kemPreKeys.GetValueOrDefault(id);

    /// <summary>Returns and permanently removes the one-time pre-key, guaranteeing single use.</summary>
    public OneTimePreKeyPair? TakeOneTimePreKey(uint id) => _oneTimePreKeys.Remove(id, out var key) ? key : null;

    /// <summary>Builds the public bundle to publish. One-time pre-keys are uploaded separately in batches.</summary>
    public PublishedKeys ExportPublicKeys() => new(
        Identity.Public,
        CurrentSignedPreKey.Id,
        CurrentSignedPreKey.KeyPair.PublicKey,
        CurrentSignedPreKey.Signature,
        CurrentKemPreKey.Id,
        CurrentKemPreKey.KeyPair.PublicKey,
        CurrentKemPreKey.Signature);

    public DeviceKeyStoreState Export() => new(
        Identity.SigningKey.Seed,
        Identity.DhKey.PrivateKey,
        _nextSignedPreKeyId,
        _nextKemPreKeyId,
        _nextOneTimePreKeyId,
        CurrentSignedPreKeyId,
        CurrentKemPreKeyId,
        _signedPreKeys.Values.Select(k => new SignedPreKeyState(k.Id, k.KeyPair.PrivateKey, k.Signature, k.CreatedAt)).ToList(),
        _kemPreKeys.Values.Select(k => new KemPreKeyState(k.Id, k.KeyPair.Seed, k.Signature, k.CreatedAt)).ToList(),
        _oneTimePreKeys.Values.Select(k => new OneTimePreKeyState(k.Id, k.KeyPair.PrivateKey)).ToList());

    public static DeviceKeyStore Import(DeviceKeyStoreState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var store = new DeviceKeyStore(IdentityKeyPair.From(state.IdentitySigningSeed, state.IdentityDhPrivateKey))
        {
            _nextSignedPreKeyId = state.NextSignedPreKeyId,
            _nextKemPreKeyId = state.NextKemPreKeyId,
            _nextOneTimePreKeyId = state.NextOneTimePreKeyId,
            CurrentSignedPreKeyId = state.CurrentSignedPreKeyId,
            CurrentKemPreKeyId = state.CurrentKemPreKeyId,
        };

        foreach (var s in state.SignedPreKeys)
        {
            store._signedPreKeys[s.Id] = SignedPreKeyPair.From(s.Id, s.PrivateKey, s.Signature, s.CreatedAt);
        }

        foreach (var k in state.KemPreKeys)
        {
            store._kemPreKeys[k.Id] = KemPreKeyPair.From(k.Id, k.Seed, k.Signature, k.CreatedAt);
        }

        foreach (var o in state.OneTimePreKeys)
        {
            store._oneTimePreKeys[o.Id] = OneTimePreKeyPair.From(o.Id, o.PrivateKey);
        }

        return store;
    }

    public void Dispose()
    {
        Identity.Dispose();
        foreach (var k in _signedPreKeys.Values)
        {
            k.Dispose();
        }

        foreach (var k in _kemPreKeys.Values)
        {
            k.Dispose();
        }

        foreach (var k in _oneTimePreKeys.Values)
        {
            k.Dispose();
        }
    }
}

/// <summary>Public key material a device publishes to the server (without one-time pre-keys).</summary>
public sealed record PublishedKeys(
    IdentityPublicKeys Identity,
    uint SignedPreKeyId,
    byte[] SignedPreKey,
    byte[] SignedPreKeySignature,
    uint KemPreKeyId,
    byte[] KemPreKey,
    byte[] KemPreKeySignature);

/// <summary>Serializable snapshot of <see cref="DeviceKeyStore"/>. Must be stored encrypted at rest.</summary>
public sealed record DeviceKeyStoreState(
    byte[] IdentitySigningSeed,
    byte[] IdentityDhPrivateKey,
    uint NextSignedPreKeyId,
    uint NextKemPreKeyId,
    uint NextOneTimePreKeyId,
    uint CurrentSignedPreKeyId,
    uint CurrentKemPreKeyId,
    List<SignedPreKeyState> SignedPreKeys,
    List<KemPreKeyState> KemPreKeys,
    List<OneTimePreKeyState> OneTimePreKeys);

public sealed record SignedPreKeyState(uint Id, byte[] PrivateKey, byte[] Signature, DateTimeOffset CreatedAt);

public sealed record KemPreKeyState(uint Id, byte[] Seed, byte[] Signature, DateTimeOffset CreatedAt);

public sealed record OneTimePreKeyState(uint Id, byte[] PrivateKey);
