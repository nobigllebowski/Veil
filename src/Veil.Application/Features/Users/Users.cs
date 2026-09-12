using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Features.Auth;
using Veil.Contracts;
using Veil.Domain.Common;
using Veil.Domain.Users;

namespace Veil.Application.Features.Users;

public sealed record GetMeQuery : IQuery<Result<UserProfile>>;

internal sealed class GetMeQueryHandler(IUserRepository users, ICurrentUser currentUser) : IQueryHandler<GetMeQuery, Result<UserProfile>>
{
    public async Task<Result<UserProfile>> Handle(GetMeQuery request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        return user is null ? UserErrors.NotFound : user.ToProfile();
    }
}

/// <summary>Exact-match lookup only: no prefix search, so the directory cannot be enumerated.</summary>
public sealed record LookupUserQuery(string Username) : IQuery<Result<PublicUser>>;

internal sealed class LookupUserQueryValidator : AbstractValidator<LookupUserQuery>
{
    public LookupUserQueryValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MaximumLength(Username.MaxLength);
    }
}

internal sealed class LookupUserQueryHandler(IUserRepository users) : IQueryHandler<LookupUserQuery, Result<PublicUser>>
{
    public async Task<Result<PublicUser>> Handle(LookupUserQuery request, CancellationToken cancellationToken)
    {
        var username = Username.Create(request.Username);
        if (username.IsFailure)
        {
            return UserErrors.NotFound;
        }

        var user = await users.GetByUsernameAsync(username.Value, cancellationToken);
        return user is null ? UserErrors.NotFound : user.ToPublic();
    }
}

public sealed record UpdateProfileCommand(string DisplayName) : ICommand<Result<UserProfile>>;

internal sealed class UpdateProfileCommandValidator : AbstractValidator<UpdateProfileCommand>
{
    public UpdateProfileCommandValidator()
    {
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(User.DisplayNameMaxLength);
    }
}

internal sealed class UpdateProfileCommandHandler(IUserRepository users, ICurrentUser currentUser, IUnitOfWork unitOfWork)
    : ICommandHandler<UpdateProfileCommand, Result<UserProfile>>
{
    public async Task<Result<UserProfile>> Handle(UpdateProfileCommand request, CancellationToken cancellationToken)
    {
        var user = await users.GetByIdAsync(currentUser.UserId, cancellationToken);
        if (user is null)
        {
            return UserErrors.NotFound;
        }

        var result = user.UpdateDisplayName(request.DisplayName);
        if (result.IsFailure)
        {
            return result.Error;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return user.ToProfile();
    }
}
