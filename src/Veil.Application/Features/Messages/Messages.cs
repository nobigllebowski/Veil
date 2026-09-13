using FluentValidation;
using Microsoft.Extensions.Options;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Options;
using Veil.Contracts;
using Veil.Domain.Auth;
using Veil.Domain.Common;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;

namespace Veil.Application.Features.Messages;

/// <summary>
/// Stores one ciphertext per recipient device. The server enforces that for every user the sender addressed, every
/// active device of that user is addressed too (the sender's own current device excepted), so a device can never be
/// silently left out. Which users are addressed is the client's choice: chat messages go to every member, delivery
/// receipts only to the original sender.
/// </summary>
public sealed record SendEnvelopesCommand(Guid ConversationId, IReadOnlyList<OutgoingEnvelope> Envelopes) : ICommand<Result<SendReceipt>>;

/// <summary>Conflict error carrying the exact device differences so the client can re-encrypt for the right set.</summary>
public sealed record DeviceSetMismatchError(IReadOnlyList<DeviceSetMismatch> Mismatches)
    : Error(MessageErrors.DeviceSetMismatch.Code, MessageErrors.DeviceSetMismatch.Message, ErrorType.Conflict);

internal sealed class SendEnvelopesCommandValidator : AbstractValidator<SendEnvelopesCommand>
{
    public SendEnvelopesCommandValidator()
    {
        RuleFor(x => x.Envelopes).NotEmpty().Must(e => e.Count <= MessageEnvelope.MaxEnvelopesPerSend).WithMessage("Too many envelopes.");
        RuleForEach(x => x.Envelopes).ChildRules(e =>
        {
            e.RuleFor(p => p.Payload).NotNull().Must(p => p.Length is > 0 and <= MessageEnvelope.MaxPayloadBytes).WithMessage("Payload must be 1 byte to 64 KiB.");
            e.RuleFor(p => p.RecipientDeviceId).NotEmpty();
            e.RuleFor(p => p.RecipientUserId).NotEmpty();
        });
    }
}

internal sealed class SendEnvelopesCommandHandler(
    IConversationRepository conversations,
    IDeviceRepository devices,
    IMessageRepository messages,
    ICurrentUser currentUser,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<MessagingOptions> options) : ICommandHandler<SendEnvelopesCommand, Result<SendReceipt>>
{
    public async Task<Result<SendReceipt>> Handle(SendEnvelopesCommand request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } senderDeviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        var conversation = await conversations.GetByIdAsync(request.ConversationId, cancellationToken);
        if (conversation is null || !conversation.IsMember(currentUser.UserId))
        {
            return ConversationErrors.NotFound;
        }

        var senderDevice = await devices.GetActiveAsync(currentUser.UserId, senderDeviceId, cancellationToken);
        if (senderDevice is null)
        {
            return DeviceErrors.Revoked;
        }

        var memberIds = conversation.Members.Select(m => m.UserId).ToList();
        if (request.Envelopes.Any(e => !memberIds.Contains(e.RecipientUserId)))
        {
            return MessageErrors.RecipientNotMember;
        }

        var addressed = request.Envelopes
            .GroupBy(e => e.RecipientUserId)
            .ToDictionary(g => g.Key, g => g.Select(e => e.RecipientDeviceId).ToHashSet());

        var expected = (await devices.ListActiveByUsersAsync(addressed.Keys.ToList(), cancellationToken))
            .Where(d => d.Id != senderDeviceId)
            .GroupBy(d => d.UserId)
            .ToDictionary(g => g.Key, g => g.Select(d => d.Id).ToHashSet());

        var mismatches = new List<DeviceSetMismatch>();
        foreach (var userId in expected.Keys.Union(addressed.Keys))
        {
            var want = expected.GetValueOrDefault(userId, []);
            var have = addressed.GetValueOrDefault(userId, []);
            var missing = want.Except(have).ToList();
            var stale = have.Except(want).ToList();
            if (missing.Count > 0 || stale.Count > 0)
            {
                mismatches.Add(new DeviceSetMismatch(userId, missing, stale));
            }
        }

        if (mismatches.Count > 0)
        {
            return new DeviceSetMismatchError(mismatches);
        }

        var now = time.GetUtcNow();
        var stored = new List<MessageEnvelope>(request.Envelopes.Count);
        foreach (var outgoing in request.Envelopes)
        {
            var envelope = MessageEnvelope.Create(conversation.Id, currentUser.UserId, senderDeviceId, outgoing.RecipientUserId, outgoing.RecipientDeviceId, outgoing.Payload, now, options.Value.EnvelopeRetention);
            if (envelope.IsFailure)
            {
                return envelope.Error;
            }

            stored.Add(envelope.Value);
        }

        senderDevice.Touch(now);
        messages.AddRange(stored);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return new SendReceipt(stored.Count, stored.Select(e => e.Id).ToList());
    }
}

public sealed record FetchPendingEnvelopesQuery : IQuery<Result<IReadOnlyList<PendingEnvelopeDto>>>;

internal sealed class FetchPendingEnvelopesQueryHandler(IMessageRepository messages, ICurrentUser currentUser, IOptions<MessagingOptions> options)
    : IQueryHandler<FetchPendingEnvelopesQuery, Result<IReadOnlyList<PendingEnvelopeDto>>>
{
    public async Task<Result<IReadOnlyList<PendingEnvelopeDto>>> Handle(FetchPendingEnvelopesQuery request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } deviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        var pending = await messages.ListPendingForDeviceAsync(deviceId, options.Value.MaxPendingFetch, cancellationToken);
        return pending.Select(e => new PendingEnvelopeDto(e.Id, e.ConversationId, e.SenderUserId, e.SenderDeviceId, e.Payload, e.SentAt)).ToList();
    }
}

/// <summary>Deletes delivered envelopes. The server keeps ciphertext only until the recipient confirms receipt.</summary>
public sealed record AcknowledgeEnvelopesCommand(IReadOnlyList<Guid> EnvelopeIds) : ICommand<Result<int>>;

internal sealed class AcknowledgeEnvelopesCommandValidator : AbstractValidator<AcknowledgeEnvelopesCommand>
{
    public AcknowledgeEnvelopesCommandValidator()
    {
        RuleFor(x => x.EnvelopeIds).NotEmpty().Must(ids => ids.Count <= 500);
    }
}

internal sealed class AcknowledgeEnvelopesCommandHandler(IMessageRepository messages, ICurrentUser currentUser)
    : ICommandHandler<AcknowledgeEnvelopesCommand, Result<int>>
{
    public async Task<Result<int>> Handle(AcknowledgeEnvelopesCommand request, CancellationToken cancellationToken)
    {
        if (currentUser.DeviceId is not { } deviceId)
        {
            return AuthErrors.DeviceRequired;
        }

        return await messages.DeleteAcknowledgedAsync(deviceId, request.EnvelopeIds, cancellationToken);
    }
}
