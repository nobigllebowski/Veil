using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Features.Auth;
using Veil.Contracts;
using Veil.Crypto;
using Veil.Crypto.Keys;
using Veil.Domain.Audit;
using Veil.Domain.Common;
using Veil.Domain.Devices;
using Veil.Domain.Users;

namespace Veil.Application.Features.Devices;

/// <summary>Publishes a new device's key bundle and returns a session bound to that device.</summary>
public sealed record RegisterDeviceCommand(
    string Name,
    IdentityKeysDto Identity,
    uint SignedPreKeyId,
    byte[] SignedPreKey,
    byte[] SignedPreKeySignature,
    uint KemPreKeyId,
    byte[] KemPreKey,
    byte[] KemPreKeySignature,
    IReadOnlyList<OneTimePreKeyUpload> OneTimePreKeys) : ICommand<Result<DeviceRegistration>>;

internal sealed class RegisterDeviceCommandValidator : AbstractValidator<RegisterDeviceCommand>
{
    public RegisterDeviceCommandValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(Device.NameMaxLength);
        RuleFor(x => x.Identity).NotNull();
        RuleFor(x => x.Identity.SigningKey).NotNull().Must(k => k.Length == ProtocolConstants.Ed25519PublicKeySize).When(x => x.Identity is not null);
        RuleFor(x => x.Identity.DhKey).NotNull().Must(k => k.Length == ProtocolConstants.X25519KeySize).When(x => x.Identity is not null);
        RuleFor(x => x.SignedPreKey).NotNull().Must(k => k.Length == ProtocolConstants.X25519KeySize);
        RuleFor(x => x.KemPreKey).NotNull().Must(k => k.Length == ProtocolConstants.MlKem768PublicKeySize);
        RuleFor(x => x.OneTimePreKeys).NotNull().Must(k => k.Count <= Device.MaxOneTimePreKeysPerUpload);
        RuleForEach(x => x.OneTimePreKeys).ChildRules(k => k.RuleFor(p => p.PublicKey).NotNull().Must(p => p.Length == ProtocolConstants.X25519KeySize));
    }
}

internal sealed class RegisterDeviceCommandHandler(
    IUserRepository users,
    IDeviceRepository devices,
    ICurrentUser currentUser,
    TokenIssuance tokens,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<RegisterDeviceCommand, Result<DeviceRegistration>>
{
    public async Task<Result<DeviceRegistration>> Handle(RegisterDeviceCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return UserErrors.NotFound;
        }

        var now = time.GetUtcNow();
        var keys = new PublishedKeys(
            new IdentityPublicKeys(request.Identity.SigningKey, request.Identity.DhKey, request.Identity.DhKeySignature),
            request.SignedPreKeyId,
            request.SignedPreKey,
            request.SignedPreKeySignature,
            request.KemPreKeyId,
            request.KemPreKey,
            request.KemPreKeySignature);

        var activeCount = await devices.CountActiveAsync(user.Id, cancellationToken);
        var device = Device.Register(user.Id, request.Name, keys, activeCount, now);
        if (device.IsFailure)
        {
            return device.Error;
        }

        if (request.OneTimePreKeys.Count > 0)
        {
            var added = device.Value.AddOneTimePreKeys(request.OneTimePreKeys.Select(k => (k.KeyId, k.PublicKey)).ToList(), 0, now);
            if (added.IsFailure)
            {
                return added.Error;
            }
        }

        devices.Add(device.Value);
        var pair = tokens.Issue(user, device.Value.Id);
        await auditor.RecordAsync(AuditActions.DeviceRegistered, user.Id, new { deviceId = device.Value.Id }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new DeviceRegistration(device.Value.Id, pair);
    }
}
