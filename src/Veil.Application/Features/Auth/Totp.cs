using FluentValidation;
using Microsoft.Extensions.Options;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Options;
using Veil.Contracts;
using Veil.Domain.Audit;
using Veil.Domain.Auth;
using Veil.Domain.Common;
using Veil.Domain.Users;

namespace Veil.Application.Features.Auth;

public sealed record BeginTotpEnrollmentCommand : ICommand<Result<TotpEnrollment>>;

internal sealed class BeginTotpEnrollmentCommandHandler(
    IUserRepository users,
    ITotpProvider totp,
    ICurrentUser currentUser,
    IUnitOfWork unitOfWork,
    IOptions<AuthOptions> options) : ICommandHandler<BeginTotpEnrollmentCommand, Result<TotpEnrollment>>
{
    public async Task<Result<TotpEnrollment>> Handle(BeginTotpEnrollmentCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return UserErrors.NotFound;
        }

        var secret = totp.GenerateSecret();
        var result = user.BeginTotpEnrollment(secret);
        if (result.IsFailure)
        {
            return result.Error;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return new TotpEnrollment(secret, totp.BuildOtpAuthUri(options.Value.TotpIssuer, user.Username.Value, secret));
    }
}

public sealed record ConfirmTotpEnrollmentCommand(string Code) : ICommand<Result>;

internal sealed class ConfirmTotpEnrollmentCommandValidator : AbstractValidator<ConfirmTotpEnrollmentCommand>
{
    public ConfirmTotpEnrollmentCommandValidator()
    {
        RuleFor(x => x.Code).NotEmpty().Matches("^[0-9]{6}$");
    }
}

internal sealed class ConfirmTotpEnrollmentCommandHandler(
    IUserRepository users,
    ITotpProvider totp,
    ICurrentUser currentUser,
    ISessionCache sessionCache,
    IAuditor auditor,
    IUnitOfWork unitOfWork) : ICommandHandler<ConfirmTotpEnrollmentCommand, Result>
{
    public async Task<Result> Handle(ConfirmTotpEnrollmentCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return UserErrors.NotFound;
        }

        if (user.TotpSecret is null)
        {
            return UserErrors.TotpNotPending;
        }

        if (!await totp.VerifyAsync(user.Id, user.TotpSecret, request.Code, cancellationToken))
        {
            return AuthErrors.TotpInvalid;
        }

        var result = user.ConfirmTotpEnrollment();
        if (result.IsFailure)
        {
            return result;
        }

        await auditor.RecordAsync(AuditActions.TotpEnabled, user.Id, null, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await sessionCache.InvalidateUserAsync(user.Id, cancellationToken);
        return Result.Success();
    }
}

public sealed record DisableTotpCommand(string Password, string Code) : ICommand<Result>;

internal sealed class DisableTotpCommandValidator : AbstractValidator<DisableTotpCommand>
{
    public DisableTotpCommandValidator()
    {
        RuleFor(x => x.Password).NotEmpty().MaximumLength(PasswordPolicy.MaxLength);
        RuleFor(x => x.Code).NotEmpty().Matches("^[0-9]{6}$");
    }
}

internal sealed class DisableTotpCommandHandler(
    IUserRepository users,
    ITotpProvider totp,
    IPasswordHasher hasher,
    ICurrentUser currentUser,
    ISessionCache sessionCache,
    IAuditor auditor,
    IUnitOfWork unitOfWork) : ICommandHandler<DisableTotpCommand, Result>
{
    public async Task<Result> Handle(DisableTotpCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return UserErrors.NotFound;
        }

        if (hasher.Verify(request.Password, user.PasswordHash) == PasswordVerification.Failed)
        {
            return AuthErrors.InvalidCredentials;
        }

        if (user.TotpSecret is null || !await totp.VerifyAsync(user.Id, user.TotpSecret, request.Code, cancellationToken))
        {
            return AuthErrors.TotpInvalid;
        }

        var result = user.DisableTotp();
        if (result.IsFailure)
        {
            return result;
        }

        await auditor.RecordAsync(AuditActions.TotpDisabled, user.Id, null, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await sessionCache.InvalidateUserAsync(user.Id, cancellationToken);
        return Result.Success();
    }
}
