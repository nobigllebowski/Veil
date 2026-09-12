using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Contracts;
using Veil.Domain.Audit;
using Veil.Domain.Common;
using Veil.Domain.Users;

namespace Veil.Application.Features.Keys;

/// <summary>
/// Returns one bundle per active device of the target user, consuming a one-time pre-key from each. The caller
/// verifies every signature client-side; the server is only a courier for public material.
/// </summary>
public sealed record GetPreKeyBundlesQuery(Guid TargetUserId) : IQuery<Result<IReadOnlyList<PreKeyBundleDto>>>;

internal sealed class GetPreKeyBundlesQueryHandler(
    IUserRepository users,
    IDeviceRepository devices,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork) : IQueryHandler<GetPreKeyBundlesQuery, Result<IReadOnlyList<PreKeyBundleDto>>>
{
    public async Task<Result<IReadOnlyList<PreKeyBundleDto>>> Handle(GetPreKeyBundlesQuery request, CancellationToken cancellationToken)
    {
        var target = await users.GetByIdAsync(request.TargetUserId, cancellationToken);
        if (target is null)
        {
            return UserErrors.NotFound;
        }

        var targetDevices = await devices.ListActiveByUserAsync(target.Id, cancellationToken);
        var bundles = new List<PreKeyBundleDto>(targetDevices.Count);

        foreach (var device in targetDevices)
        {
            if (device.Id == currentUser.DeviceId)
            {
                continue;
            }

            var oneTime = await devices.ConsumeOneTimePreKeyAsync(device.Id, cancellationToken);
            bundles.Add(new PreKeyBundleDto(
                target.Id,
                device.Id,
                new IdentityKeysDto(device.IdentitySigningKey, device.IdentityDhKey, device.IdentityDhKeySignature),
                device.SignedPreKeyId,
                device.SignedPreKey,
                device.SignedPreKeySignature,
                device.KemPreKeyId,
                device.KemPreKey,
                device.KemPreKeySignature,
                oneTime?.KeyId,
                oneTime?.PublicKey));
        }

        await auditor.RecordAsync(AuditActions.PreKeyBundleFetched, currentUser.UserId, new { targetUserId = target.Id, devices = bundles.Count }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return bundles;
    }
}
