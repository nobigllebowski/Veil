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
using Veil.Domain.Devices;
using Veil.Domain.Users;

namespace Veil.Application.Features.Auth;

/// <summary>Password (+ optional TOTP) login. <c>DeviceId</c> optionally binds the session to an already-registered device.</summary>
public sealed record LoginCommand(string Username, string Password, string? TotpCode, Guid? DeviceId) : ICommand<Result<TokenPair>>;

internal sealed class LoginCommandValidator : AbstractValidator<LoginCommand>
{
    public LoginCommandValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MaximumLength(Username.MaxLength);
        RuleFor(x => x.Password).NotEmpty().MaximumLength(PasswordPolicy.MaxLength);
        RuleFor(x => x.TotpCode).Matches("^[0-9]{6}$").When(x => x.TotpCode is not null);
    }
}

internal sealed class LoginCommandHandler(
    IUserRepository users,
    IDeviceRepository devices,
    IPasswordHasher hasher,
    ITotpProvider totp,
    TokenIssuance tokens,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<AuthOptions> options) : ICommandHandler<LoginCommand, Result<TokenPair>>
{
    public async Task<Result<TokenPair>> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var username = Username.Create(request.Username);
        var user = username.IsSuccess ? await users.GetByUsernameAsync(username.Value, cancellationToken) : null;

        if (user is null)
        {
            hasher.MitigateTiming(request.Password);
            await auditor.RecordAsync(AuditActions.LoginFailed, null, new { reason = "unknown_user" }, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            return AuthErrors.InvalidCredentials;
        }

        if (user.IsLockedOut(now))
        {
            hasher.MitigateTiming(request.Password);
            return AuthErrors.AccountLocked;
        }

        var verification = hasher.Verify(request.Password, user.PasswordHash);
        if (verification == PasswordVerification.Failed)
        {
            return await RecordFailure(user, "bad_password", now, cancellationToken);
        }

        if (verification == PasswordVerification.SuccessRehashNeeded)
        {
            user.RehashPassword(hasher.Hash(request.Password));
        }

        if (user.TotpEnabled)
        {
            if (string.IsNullOrEmpty(request.TotpCode))
            {
                return AuthErrors.TotpRequired;
            }

            if (user.TotpSecret is null || !await totp.VerifyAsync(user.Id, user.TotpSecret, request.TotpCode, cancellationToken))
            {
                return await RecordFailure(user, "bad_totp", now, cancellationToken);
            }
        }

        Device? device = null;
        if (request.DeviceId is { } deviceId)
        {
            device = await devices.GetActiveAsync(user.Id, deviceId, cancellationToken);
            if (device is null)
            {
                return DeviceErrors.NotFound;
            }

            device.Touch(now);
        }

        user.RecordSuccessfulLogin(now);
        var pair = tokens.Issue(user, device?.Id);
        await auditor.RecordAsync(AuditActions.LoginSucceeded, user.Id, new { deviceId = device?.Id }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return pair;
    }

    private async Task<Result<TokenPair>> RecordFailure(User user, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var locked = user.RecordFailedLogin(now, options.Value.MaxFailedLoginAttempts, options.Value.LockoutDuration);
        await auditor.RecordAsync(locked ? AuditActions.AccountLocked : AuditActions.LoginFailed, user.Id, new { reason }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return locked ? AuthErrors.AccountLocked : reason == "bad_totp" ? AuthErrors.TotpInvalid : AuthErrors.InvalidCredentials;
    }
}
