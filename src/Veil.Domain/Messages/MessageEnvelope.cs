using Veil.Domain.Common;

namespace Veil.Domain.Messages;

/// <summary>
/// An opaque end-to-end encrypted payload addressed to exactly one recipient device. The server can read the
/// routing envelope and nothing else, and deletes it as soon as the device acknowledges delivery.
/// </summary>
public sealed class MessageEnvelope : AggregateRoot
{
    public const int MaxPayloadBytes = 64 * 1024;
    public const int MaxEnvelopesPerSend = 256;

    private MessageEnvelope()
    {
    }

    private MessageEnvelope(Guid id, Guid conversationId, Guid senderUserId, Guid senderDeviceId, Guid recipientUserId, Guid recipientDeviceId, byte[] payload, DateTimeOffset now, DateTimeOffset expiresAt)
        : base(id)
    {
        ConversationId = conversationId;
        SenderUserId = senderUserId;
        SenderDeviceId = senderDeviceId;
        RecipientUserId = recipientUserId;
        RecipientDeviceId = recipientDeviceId;
        Payload = payload;
        SentAt = now;
        ExpiresAt = expiresAt;
    }

    public Guid ConversationId { get; private set; }
    public Guid SenderUserId { get; private set; }
    public Guid SenderDeviceId { get; private set; }
    public Guid RecipientUserId { get; private set; }
    public Guid RecipientDeviceId { get; private set; }
    public byte[] Payload { get; private set; } = null!;
    public DateTimeOffset SentAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }

    public static Result<MessageEnvelope> Create(Guid conversationId, Guid senderUserId, Guid senderDeviceId, Guid recipientUserId, Guid recipientDeviceId, byte[] payload, DateTimeOffset now, TimeSpan retention)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.Length == 0 || payload.Length > MaxPayloadBytes)
        {
            return MessageErrors.PayloadInvalid;
        }

        var envelope = new MessageEnvelope(NewId(), conversationId, senderUserId, senderDeviceId, recipientUserId, recipientDeviceId, payload, now, now + retention);
        envelope.Raise(new EnvelopeStored(envelope.Id, conversationId, senderUserId, recipientUserId, recipientDeviceId, now));
        return envelope;
    }
}

public static class MessageErrors
{
    public static readonly Error PayloadInvalid = Error.Validation("message.payload_invalid", "Payload must be between 1 byte and 64 KiB.");
    public static readonly Error TooManyEnvelopes = Error.Validation("message.too_many_envelopes", "Too many envelopes in one request.");
    public static readonly Error RecipientNotMember = Error.Forbidden("message.recipient_not_member", "A recipient is not a member of the conversation.");
    public static readonly Error DeviceSetMismatch = Error.Conflict("message.device_set_mismatch", "The recipient device list is stale. Refresh devices and re-encrypt.");
}

public sealed record EnvelopeStored(Guid EnvelopeId, Guid ConversationId, Guid SenderUserId, Guid RecipientUserId, Guid RecipientDeviceId, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);
