using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Contracts;
using Veil.Domain.Audit;
using Veil.Domain.Auth;
using Veil.Domain.Common;
using Veil.Domain.Users;

namespace Veil.Application.Features.Auth;

/// <summary>Changes the password, revokes every other session and returns fresh tokens for the current one.</summary>
public sealed record ChangePasswordCommand(string CurrentPassword, string NewPassword) : ICommand<Result<TokenPair>>;

internal sealed class ChangePasswordCommandValidator : AbstractValidator<ChangePasswordCommand>
{
    public ChangePasswordCommandValidator()
    {
        RuleFor(x => x.CurrentPassword).NotEmpty().MaximumLength(PasswordPolicy.MaxLength);
        RuleFor(x => x.NewPassword).NotEmpty().Length(PasswordPolicy.MinLength, PasswordPolicy.MaxLength);
    }
}

internal sealed class ChangePasswordCommandHandler(
    IUserRepository users,
    IRefreshTokenRepository refreshTokens,
    IPasswordHasher hasher,
    ICurrentUser currentUser,
    ISessionCache sessionCache,
    TokenIssuance tokens,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<ChangePasswordCommand, Result<TokenPair>>
{
    public async Task<Result<TokenPair>> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return UserErrors.NotFound;
        }

        if (hasher.Verify(request.CurrentPassword, user.PasswordHash) == PasswordVerification.Failed)
        {
            return AuthErrors.InvalidCredentials;
        }

        if (!PasswordPolicy.IsAcceptable(request.NewPassword, user.Username.Value))
        {
            return AuthErrors.PasswordTooWeak;
        }

        user.ChangePassword(hasher.Hash(request.NewPassword));
        await refreshTokens.RevokeAllForUserAsync(user.Id, time.GetUtcNow(), cancellationToken);
        var pair = tokens.Issue(user, currentUser.DeviceId);
        await auditor.RecordAsync(AuditActions.PasswordChanged, user.Id, null, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await sessionCache.InvalidateUserAsync(user.Id, cancellationToken);
        return pair;
    }
}
