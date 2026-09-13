using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Realtime;
using Veil.Contracts;
using Veil.Domain.Common;

namespace Veil.Application.Features.Users;

/// <summary>Which of the given users currently have a connected device.</summary>
public sealed record GetPresenceQuery(IReadOnlyList<Guid> UserIds) : IQuery<Result<PresenceResponse>>;

internal sealed class GetPresenceQueryValidator : AbstractValidator<GetPresenceQuery>
{
    public GetPresenceQueryValidator()
    {
        RuleFor(x => x.UserIds).NotNull().Must(ids => ids.Count <= 500);
    }
}

internal sealed class GetPresenceQueryHandler(IPresenceService presence) : IQueryHandler<GetPresenceQuery, Result<PresenceResponse>>
{
    public async Task<Result<PresenceResponse>> Handle(GetPresenceQuery request, CancellationToken cancellationToken)
    {
        var online = await presence.GetOnlineUsersAsync(request.UserIds.Distinct().ToList(), cancellationToken);
        return new PresenceResponse(online.ToList());
    }
}
