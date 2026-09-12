using Veil.Domain.Common;

namespace Veil.Domain.Devices;

public static class DeviceErrors
{
    public static readonly Error NameInvalid = Error.Validation("device.name_invalid", "Device name must be 1-64 characters.");
    public static readonly Error InvalidKeyMaterial = Error.Validation("device.invalid_key_material", "Key material has an invalid length.");
    public static readonly Error InvalidSignature = Error.Validation("device.invalid_signature", "Pre-key signature does not verify against the identity key.");
    public static readonly Error NotFound = Error.NotFound("device.not_found", "Device not found.");
    public static readonly Error Revoked = Error.Forbidden("device.revoked", "This device has been revoked.");
    public static readonly Error TooManyDevices = Error.Conflict("device.limit_reached", "Maximum number of devices reached.");
    public static readonly Error TooManyOneTimePreKeys = Error.Validation("device.too_many_one_time_pre_keys", "Too many one-time pre-keys in one upload or on the server.");
    public static readonly Error PreKeyIdNotIncreasing = Error.Validation("device.pre_key_id_not_increasing", "Pre-key ids must increase monotonically.");
}
