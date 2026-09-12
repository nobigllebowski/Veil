using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Contracts;
using Veil.Crypto;
using Veil.Domain.Audit;
using Veil.Domain.Auth;
using Veil.Domain.Common;
using Veil.Domain.Devices;

namespace Veil.Application.Features.Devices;

public sealed record ListDevicesQuery : IQuery<Result<IReadOnlyList<DeviceSummary>>>;

internal sealed class ListDevicesQueryHandler(IDeviceRepository devices, ICurrentUser currentUser)
    : IQueryHandler<ListDevicesQuery, Result<IReadOnlyList<DeviceSummary>>>
{
    public async Task<Result<IReadOnlyList<DeviceSummary>>> Handle(ListDevicesQuery request, CancellationToken cancellationToken)
    {
        var list = await devices.ListActiveByUserAsync(currentUser.UserId, cancellationToken);
        var summaries = new List<DeviceSummary>(list.Count);
        foreach (var device in list)
        {
            var remaining = await devices.CountOneTimePreKeysAsync(device.Id, cancellationToken);
            summaries.Add(new DeviceSummary(device.Id, device.Name, device.CreatedAt, device.LastActiveAt, device.Id == currentUser.DeviceId, remaining));
        }

        return summaries;
    }
}

public sealed record RevokeDeviceCommand(Guid DeviceId) : ICommand<Result>;

internal sealed class RevokeDeviceCommandHandler(
    IDeviceRepository devices,
    IRefreshTokenRepository refreshTokens,
    ICurrentUser currentUser,
    ISessionCache sessionCache,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<RevokeDeviceCommand, Result>
{
    public async Task<Result> Handle(RevokeDeviceCommand request, CancellationToken cancellationToken)
    {
        var device = await devices.GetActiveAsync(currentUser.UserId, request.DeviceId, cancellationToken);
        if (device is null)
        {
            return DeviceErrors.NotFound;
        }

        var now = time.GetUtcNow();
        device.Revoke(now);
        await refreshTokens.RevokeAllForDeviceAsync(device.Id, now, cancellationToken);
        await auditor.RecordAsync(AuditActions.DeviceRevoked, currentUser.UserId, new { deviceId = device.Id }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await sessionCache.InvalidateDeviceAsync(device.Id, cancellationToken);
        return Result.Success();
    }
}

public sealed record UploadOneTimePreKeysCommand(IReadOnlyList<OneTimePreKeyUpload> Keys) : ICommand<Result<int>>;

internal sealed class UploadOneTimePreKeysCommandValidator : AbstractValidator<UploadOneTimePreKeysCommand>
{
    public UploadOneTimePreKeysCommandValidator()
    {
        RuleFor(x => x.Keys).NotEmpty().Must(k => k.Count <= Device.MaxOneTimePreKeysPerUpload);
        RuleForEach(x => x.Keys).ChildRules(k => k.RuleFor(p => p.PublicKey).NotNull().Must(p => p.Length == ProtocolConstants.X25519KeySize));
    }
}

internal sealed class UploadOneTimePreKeysCommandHandler(
    IDeviceRepository devices,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<UploadOneTimePreKeysCommand, Result<int>>
{
    public async Task<Result<int>> Handle(UploadOneTimePreKeysCommand request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } deviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        var device = await devices.GetActiveAsync(currentUser.UserId, deviceId, cancellationToken);
        if (device is null)
        {
            return DeviceErrors.NotFound;
        }

        var stored = await devices.CountOneTimePreKeysAsync(device.Id, cancellationToken);
        var result = device.AddOneTimePreKeys(request.Keys.Select(k => (k.KeyId, k.PublicKey)).ToList(), stored, time.GetUtcNow());
        if (result.IsFailure)
        {
            return result.Error;
        }

        await auditor.RecordAsync(AuditActions.PreKeysUploaded, currentUser.UserId, new { deviceId, count = request.Keys.Count }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return stored + request.Keys.Count;
    }
}

public sealed record RotateSignedPreKeyCommand(uint KeyId, byte[] PublicKey, byte[] Signature) : ICommand<Result>;

internal sealed class RotateSignedPreKeyCommandHandler(IDeviceRepository devices, ICurrentUser currentUser, IUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<RotateSignedPreKeyCommand, Result>
{
    public async Task<Result> Handle(RotateSignedPreKeyCommand request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } deviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        var device = await devices.GetActiveAsync(currentUser.UserId, deviceId, cancellationToken);
        if (device is null)
        {
            return DeviceErrors.NotFound;
        }

        var result = device.RotateSignedPreKey(request.KeyId, request.PublicKey, request.Signature, time.GetUtcNow());
        if (result.IsFailure)
        {
            return result;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }
}

public sealed record RotateKemPreKeyCommand(uint KeyId, byte[] PublicKey, byte[] Signature) : ICommand<Result>;

internal sealed class RotateKemPreKeyCommandHandler(IDeviceRepository devices, ICurrentUser currentUser, IUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<RotateKemPreKeyCommand, Result>
{
    public async Task<Result> Handle(RotateKemPreKeyCommand request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } deviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        var device = await devices.GetActiveAsync(currentUser.UserId, deviceId, cancellationToken);
        if (device is null)
        {
            return DeviceErrors.NotFound;
        }

        var result = device.RotateKemPreKey(request.KeyId, request.PublicKey, request.Signature, time.GetUtcNow());
        if (result.IsFailure)
        {
            return result;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }
}

public sealed record GetPreKeyStatusQuery : IQuery<Result<int>>;

internal sealed class GetPreKeyStatusQueryHandler(IDeviceRepository devices, ICurrentUser currentUser) : IQueryHandler<GetPreKeyStatusQuery, Result<int>>
{
    public async Task<Result<int>> Handle(GetPreKeyStatusQuery request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } deviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        return await devices.CountOneTimePreKeysAsync(deviceId, cancellationToken);
    }
}
