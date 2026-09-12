using Veil.Api.Auth;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Features.Messages;
using Veil.Contracts;

namespace Veil.Api.Endpoints;

internal static class MessageEndpoints
{
    public static RouteGroupBuilder MapMessageEndpoints(this RouteGroupBuilder api)
    {
        var group = api.MapGroup("/messages")
            .WithTags("Messages")
            .RequireAuthorization(AuthPolicies.DeviceBound)
            .RequireRateLimiting(RateLimitPolicies.Messaging);

        group.MapPost("/", async (SendEnvelopesRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new SendEnvelopesCommand(request.ConversationId, request.Envelopes), ct))
                    .ToHttp(receipt => Results.Accepted(null, receipt)))
            .Produces<SendReceipt>(StatusCodes.Status202Accepted)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .WithSummary("Store one end-to-end encrypted envelope per recipient device. 409 with `mismatches` when the device set is stale.");

        group.MapGet("/pending", async (ISender sender, CancellationToken ct) =>
                (await sender.Send(new FetchPendingEnvelopesQuery(), ct)).ToOk())
            .Produces<IReadOnlyList<PendingEnvelopeDto>>()
            .WithSummary("Envelopes waiting for this device, oldest first.");

        group.MapPost("/ack", async (AcknowledgeRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new AcknowledgeEnvelopesCommand(request.EnvelopeIds), ct)).ToHttp(count => Results.Ok(new CountResponse(count))))
            .Produces<CountResponse>()
            .WithSummary("Confirm delivery; the server deletes the ciphertext immediately.");

        return api;
    }
}
