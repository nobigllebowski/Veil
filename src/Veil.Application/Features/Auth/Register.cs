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

public sealed record RegisterCommand(string Username, string Email, string Password, string? DisplayName) : ICommand<Result<UserProfile>>;

internal sealed class RegisterCommandValidator : AbstractValidator<RegisterCommand>
{
    public RegisterCommandValidator()
    {
        RuleFor(x => x.Username).NotEmpty().Length(Username.MinLength, Username.MaxLength);
        RuleFor(x => x.Email).NotEmpty().MaximumLength(EmailAddress.MaxLength);
        RuleFor(x => x.Password).NotEmpty().Length(PasswordPolicy.MinLength, PasswordPolicy.MaxLength);
        RuleFor(x => x.DisplayName).MaximumLength(User.DisplayNameMaxLength);
    }
}

internal sealed class RegisterCommandHandler(
    IUserRepository users,
    IPasswordHasher hasher,
    IBlindIndexer blindIndexer,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<RegisterCommand, Result<UserProfile>>
{
    private static readonly Error RegistrationUnavailable =
        Error.Conflict("user.registration_unavailable", "Registration could not be completed with the provided details.");

    public async Task<Result<UserProfile>> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        var username = Username.Create(request.Username);
        if (username.IsFailure)
        {
            return username.Error;
        }

        var email = EmailAddress.Create(request.Email);
        if (email.IsFailure)
        {
            return email.Error;
        }

        if (!PasswordPolicy.IsAcceptable(request.Password, username.Value.Value))
        {
            return AuthErrors.PasswordTooWeak;
        }

        if (await users.UsernameExistsAsync(username.Value, cancellationToken))
        {
            return UserErrors.UsernameTaken;
        }

        var emailIndex = blindIndexer.Compute(email.Value.Value);
        if (await users.EmailExistsAsync(emailIndex, cancellationToken))
        {
            // Deliberately vague: do not confirm that an e-mail address is registered.
            return RegistrationUnavailable;
        }

        var user = User.Register(username.Value, request.DisplayName, email.Value, emailIndex, hasher.Hash(request.Password), time.GetUtcNow());
        if (user.IsFailure)
        {
            return user.Error;
        }

        users.Add(user.Value);
        await auditor.RecordAsync(AuditActions.UserRegistered, user.Value.Id, new { username = username.Value.Value }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return user.Value.ToProfile();
    }
}

internal static class UserMappings
{
    public static UserProfile ToProfile(this User user) =>
        new(user.Id, user.Username.Value, user.DisplayName, user.CreatedAt, user.TotpEnabled);

    public static PublicUser ToPublic(this User user) => new(user.Id, user.Username.Value, user.DisplayName);
}
