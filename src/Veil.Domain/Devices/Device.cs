using Veil.Crypto;
using Veil.Crypto.Keys;
using Veil.Crypto.Primitives;
using Veil.Domain.Common;

namespace Veil.Domain.Devices;

/// <summary>
/// A user's device and its published public key material. Every signature is verified on upload, so the server
/// only ever stores bundles that a client will accept.
/// </summary>
public sealed class Device : AggregateRoot
{
    public const int NameMaxLength = 64;
    public const int MaxDevicesPerUser = 10;
    public const int MaxOneTimePreKeysPerUpload = 200;
    public const int MaxStoredOneTimePreKeys = 500;

    private readonly List<OneTimePreKey> _oneTimePreKeys = [];

    private Device()
    {
    }

    private Device(Guid id, Guid userId, string name, PublishedKeys keys, DateTimeOffset now) : base(id)
    {
        UserId = userId;
        Name = name;
        IdentitySigningKey = keys.Identity.SigningKey;
        IdentityDhKey = keys.Identity.DhKey;
        IdentityDhKeySignature = keys.Identity.DhKeySignature;
        SignedPreKeyId = keys.SignedPreKeyId;
        SignedPreKey = keys.SignedPreKey;
        SignedPreKeySignature = keys.SignedPreKeySignature;
        KemPreKeyId = keys.KemPreKeyId;
        KemPreKey = keys.KemPreKey;
        KemPreKeySignature = keys.KemPreKeySignature;
        CreatedAt = now;
        LastActiveAt = now;
    }

    public Guid UserId { get; private set; }
    public string Name { get; private set; } = null!;
    public byte[] IdentitySigningKey { get; private set; } = null!;
    public byte[] IdentityDhKey { get; private set; } = null!;
    public byte[] IdentityDhKeySignature { get; private set; } = null!;
    public uint SignedPreKeyId { get; private set; }
    public byte[] SignedPreKey { get; private set; } = null!;
    public byte[] SignedPreKeySignature { get; private set; } = null!;
    public uint KemPreKeyId { get; private set; }
    public byte[] KemPreKey { get; private set; } = null!;
    public byte[] KemPreKeySignature { get; private set; } = null!;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset LastActiveAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public IReadOnlyCollection<OneTimePreKey> OneTimePreKeys => _oneTimePreKeys.AsReadOnly();

    public bool IsActive => RevokedAt is null;

    public IdentityPublicKeys Identity => new(IdentitySigningKey, IdentityDhKey, IdentityDhKeySignature);

    public static Result<Device> Register(Guid userId, string? name, PublishedKeys keys, int existingActiveDevices, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(keys);

        var trimmed = name?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > NameMaxLength)
        {
            return DeviceErrors.NameInvalid;
        }

        if (existingActiveDevices >= MaxDevicesPerUser)
        {
            return DeviceErrors.TooManyDevices;
        }

        var validation = ValidateBundle(keys);
        if (validation.IsFailure)
        {
            return validation.Error;
        }

        var device = new Device(NewId(), userId, trimmed, keys, now);
        device.Raise(new DeviceRegistered(userId, device.Id, now));
        return device;
    }

    public Result RotateSignedPreKey(uint keyId, byte[] publicKey, byte[] signature, DateTimeOffset now)
    {
        if (keyId <= SignedPreKeyId)
        {
            return DeviceErrors.PreKeyIdNotIncreasing;
        }

        if (publicKey.Length != ProtocolConstants.X25519KeySize)
        {
            return DeviceErrors.InvalidKeyMaterial;
        }

        if (!Ed25519.Verify(IdentitySigningKey, SignedMaterial.SignedPreKey(keyId, publicKey), signature))
        {
            return DeviceErrors.InvalidSignature;
        }

        SignedPreKeyId = keyId;
        SignedPreKey = publicKey;
        SignedPreKeySignature = signature;
        LastActiveAt = now;
        return Result.Success();
    }

    public Result RotateKemPreKey(uint keyId, byte[] publicKey, byte[] signature, DateTimeOffset now)
    {
        if (keyId <= KemPreKeyId)
        {
            return DeviceErrors.PreKeyIdNotIncreasing;
        }

        if (publicKey.Length != ProtocolConstants.MlKem768PublicKeySize)
        {
            return DeviceErrors.InvalidKeyMaterial;
        }

        if (!Ed25519.Verify(IdentitySigningKey, SignedMaterial.KemPreKey(keyId, publicKey), signature))
        {
            return DeviceErrors.InvalidSignature;
        }

        KemPreKeyId = keyId;
        KemPreKey = publicKey;
        KemPreKeySignature = signature;
        LastActiveAt = now;
        return Result.Success();
    }

    public Result AddOneTimePreKeys(IReadOnlyList<(uint KeyId, byte[] PublicKey)> keys, int currentlyStored, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (keys.Count == 0 || keys.Count > MaxOneTimePreKeysPerUpload || currentlyStored + keys.Count > MaxStoredOneTimePreKeys)
        {
            return DeviceErrors.TooManyOneTimePreKeys;
        }

        if (keys.Any(k => k.PublicKey.Length != ProtocolConstants.X25519KeySize))
        {
            return DeviceErrors.InvalidKeyMaterial;
        }

        foreach (var (keyId, publicKey) in keys)
        {
            _oneTimePreKeys.Add(new OneTimePreKey(Id, keyId, publicKey));
        }

        LastActiveAt = now;
        return Result.Success();
    }

    public void Touch(DateTimeOffset now) => LastActiveAt = now;

    public void Revoke(DateTimeOffset now)
    {
        if (RevokedAt is not null)
        {
            return;
        }

        RevokedAt = now;
        _oneTimePreKeys.Clear();
        Raise(new DeviceRevoked(UserId, Id, now));
    }

    private static Result ValidateBundle(PublishedKeys keys)
    {
        if (keys.Identity.SigningKey.Length != ProtocolConstants.Ed25519PublicKeySize ||
            keys.Identity.DhKey.Length != ProtocolConstants.X25519KeySize ||
            keys.Identity.DhKeySignature.Length != ProtocolConstants.Ed25519SignatureSize ||
            keys.SignedPreKey.Length != ProtocolConstants.X25519KeySize ||
            keys.SignedPreKeySignature.Length != ProtocolConstants.Ed25519SignatureSize ||
            keys.KemPreKey.Length != ProtocolConstants.MlKem768PublicKeySize ||
            keys.KemPreKeySignature.Length != ProtocolConstants.Ed25519SignatureSize)
        {
            return DeviceErrors.InvalidKeyMaterial;
        }

        var bundle = new PreKeyBundle(keys.Identity, keys.SignedPreKeyId, keys.SignedPreKey, keys.SignedPreKeySignature, keys.KemPreKeyId, keys.KemPreKey, keys.KemPreKeySignature, null, null);
        try
        {
            bundle.Verify();
        }
        catch (CryptoException)
        {
            return DeviceErrors.InvalidSignature;
        }

        return Result.Success();
    }
}

/// <summary>Single-use pre-key. Deleted atomically when handed out, never returned twice.</summary>
public sealed class OneTimePreKey
{
    private OneTimePreKey()
    {
    }

    internal OneTimePreKey(Guid deviceId, uint keyId, byte[] publicKey)
    {
        DeviceId = deviceId;
        KeyId = keyId;
        PublicKey = publicKey;
    }

    public long Id { get; private set; }
    public Guid DeviceId { get; private set; }
    public uint KeyId { get; private set; }
    public byte[] PublicKey { get; private set; } = null!;
}

public sealed record DeviceRegistered(Guid UserId, Guid DeviceId, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);

public sealed record DeviceRevoked(Guid UserId, Guid DeviceId, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);
