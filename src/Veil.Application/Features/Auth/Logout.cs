using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Domain.Audit;
using Veil.Domain.Common;

namespace Veil.Application.Features.Auth;

/// <summary>Revokes the refresh-token family of the presented token. Idempotent and never reveals whether the token existed.</summary>
public sealed record LogoutCommand(string? RefreshToken) : ICommand<Result>;

internal sealed class LogoutCommandHandler(
    IRefreshTokenRepository refreshTokens,
    IRefreshTokenGenerator generator,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<LogoutCommand, Result>
{
    public async Task<Result> Handle(LogoutCommand request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return Result.Success();
        }

        var token = await refreshTokens.GetByHashAsync(generator.Hash(request.RefreshToken), cancellationToken);
        if (token is null || token.UserId != currentUser.UserId)
        {
            return Result.Success();
        }

        await refreshTokens.RevokeFamilyAsync(token.FamilyId, time.GetUtcNow(), cancellationToken);
        await auditor.RecordAsync(AuditActions.LoggedOut, currentUser.UserId, new { familyId = token.FamilyId }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }
}

/// <summary>Revokes every refresh token of the current user and invalidates outstanding access tokens.</summary>
public sealed record LogoutEverywhereCommand : ICommand<Result>;

internal sealed class LogoutEverywhereCommandHandler(
    IRefreshTokenRepository refreshTokens,
    IUserRepository users,
    ICurrentUser currentUser,
    ISessionCache sessionCache,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<LogoutEverywhereCommand, Result>
{
    public async Task<Result> Handle(LogoutEverywhereCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return Result.Success();
        }

        user.InvalidateSessions();
        await refreshTokens.RevokeAllForUserAsync(user.Id, time.GetUtcNow(), cancellationToken);
        await auditor.RecordAsync(AuditActions.LoggedOut, user.Id, new { everywhere = true }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await sessionCache.InvalidateUserAsync(user.Id, cancellationToken);
        return Result.Success();
    }
}
