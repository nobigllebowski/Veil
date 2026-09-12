using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Contracts;
using Veil.Domain.Audit;
using Veil.Domain.Auth;
using Veil.Domain.Common;

namespace Veil.Application.Features.Auth;

public sealed record RefreshSessionCommand(string RefreshToken) : ICommand<Result<TokenPair>>;

internal sealed class RefreshSessionCommandValidator : AbstractValidator<RefreshSessionCommand>
{
    public RefreshSessionCommandValidator()
    {
        RuleFor(x => x.RefreshToken).NotEmpty().MaximumLength(256);
    }
}

/// <summary>
/// Refresh-token rotation with reuse detection: each token is single-use; presenting a used one means it was
/// stolen (or the legitimate client lost the response), so the whole family is revoked and the user must log in again.
/// </summary>
internal sealed class RefreshSessionCommandHandler(
    IRefreshTokenRepository refreshTokens,
    IRefreshTokenGenerator generator,
    IUserRepository users,
    IDeviceRepository devices,
    TokenIssuance tokens,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<RefreshSessionCommand, Result<TokenPair>>
{
    public async Task<Result<TokenPair>> Handle(RefreshSessionCommand request, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var existing = await refreshTokens.GetByHashAsync(generator.Hash(request.RefreshToken), cancellationToken);
        if (existing is null)
        {
            return AuthErrors.InvalidRefreshToken;
        }

        if (existing.IsUsed)
        {
            await refreshTokens.RevokeFamilyAsync(existing.FamilyId, now, cancellationToken);
            await auditor.RecordAsync(AuditActions.TokenReuseDetected, existing.UserId, new { familyId = existing.FamilyId, deviceId = existing.DeviceId }, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            return AuthErrors.RefreshTokenReuse;
        }

        if (!existing.IsActive(now))
        {
            return AuthErrors.InvalidRefreshToken;
        }

        var user = await users.GetByIdAsync(existing.UserId, cancellationToken);
        if (user is null || user.IsLockedOut(now))
        {
            return AuthErrors.InvalidRefreshToken;
        }

        if (existing.DeviceId is { } deviceId)
        {
            var device = await devices.GetActiveAsync(user.Id, deviceId, cancellationToken);
            if (device is null)
            {
                existing.Revoke(now);
                await unitOfWork.SaveChangesAsync(cancellationToken);
                return AuthErrors.InvalidRefreshToken;
            }

            device.Touch(now);
        }

        existing.MarkUsed(now);
        var pair = tokens.Issue(user, existing.DeviceId, existing.FamilyId);
        await auditor.RecordAsync(AuditActions.TokenRefreshed, user.Id, new { deviceId = existing.DeviceId }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return pair;
    }
}
