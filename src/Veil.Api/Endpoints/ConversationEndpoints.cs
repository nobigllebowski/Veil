using Veil.Application.Abstractions.Messaging;
using Veil.Application.Features.Conversations;
using Veil.Contracts;

namespace Veil.Api.Endpoints;

internal static class ConversationEndpoints
{
    public static RouteGroupBuilder MapConversationEndpoints(this RouteGroupBuilder api)
    {
        var group = api.MapGroup("/conversations").WithTags("Conversations");

        group.MapGet("/", async (ISender sender, CancellationToken ct) => (await sender.Send(new ListConversationsQuery(), ct)).ToOk())
            .Produces<IReadOnlyList<ConversationSummary>>();

        group.MapPost("/direct", async (CreateDirectConversationRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new CreateDirectConversationCommand(request.OtherUserId), ct)).ToOk())
            .Produces<ConversationSummary>()
            .WithSummary("Get or create the direct conversation with another user.");

        group.MapPost("/group", async (CreateGroupConversationRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new CreateGroupConversationCommand(request.Title, request.MemberIds), ct))
                    .ToHttp(c => Results.Created($"/api/v1/conversations/{c.Id}", c)))
            .Produces<ConversationSummary>(StatusCodes.Status201Created);

        group.MapGet("/{conversationId:guid}", async (Guid conversationId, ISender sender, CancellationToken ct) =>
                (await sender.Send(new GetConversationQuery(conversationId), ct)).ToOk())
            .Produces<ConversationSummary>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{conversationId:guid}/members", async (Guid conversationId, AddMemberRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new AddMemberCommand(conversationId, request.UserId), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent);

        group.MapDelete("/{conversationId:guid}/members/{userId:guid}", async (Guid conversationId, Guid userId, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RemoveMemberCommand(conversationId, userId), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent)
            .WithSummary("Remove a member, or leave when the id is your own.");

        return api;
    }
}
