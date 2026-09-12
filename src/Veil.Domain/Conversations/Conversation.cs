using Veil.Domain.Common;

namespace Veil.Domain.Conversations;

public enum ConversationType
{
    Direct = 1,
    Group = 2,
}

public enum MemberRole
{
    Member = 1,
    Admin = 2,
    Owner = 3,
}

/// <summary>
/// A direct or group chat. The server knows membership (needed for routing) but nothing about content: even the
/// group title is stored encrypted at rest.
/// </summary>
public sealed class Conversation : AggregateRoot
{
    public const int TitleMaxLength = 128;
    public const int MaxMembers = 256;

    private readonly List<ConversationMember> _members = [];

    private Conversation()
    {
    }

    private Conversation(Guid id, ConversationType type, string? title, Guid createdByUserId, DateTimeOffset now) : base(id)
    {
        Type = type;
        Title = title;
        CreatedByUserId = createdByUserId;
        CreatedAt = now;
    }

    public ConversationType Type { get; private set; }
    public string? Title { get; private set; }
    public Guid CreatedByUserId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public IReadOnlyCollection<ConversationMember> Members => _members.AsReadOnly();

    /// <summary>Deterministic key for a direct chat between two users (ordered pair), used for the uniqueness constraint.</summary>
    public string? DirectKey { get; private set; }

    public static string ComputeDirectKey(Guid a, Guid b) =>
        a.CompareTo(b) < 0 ? $"{a:N}:{b:N}" : $"{b:N}:{a:N}";

    public static Result<Conversation> CreateDirect(Guid initiatorId, Guid otherUserId, DateTimeOffset now)
    {
        if (initiatorId == otherUserId)
        {
            return ConversationErrors.CannotChatWithSelf;
        }

        var conversation = new Conversation(NewId(), ConversationType.Direct, null, initiatorId, now)
        {
            DirectKey = ComputeDirectKey(initiatorId, otherUserId),
        };
        conversation._members.Add(new ConversationMember(conversation.Id, initiatorId, MemberRole.Owner, now));
        conversation._members.Add(new ConversationMember(conversation.Id, otherUserId, MemberRole.Owner, now));
        conversation.Raise(new ConversationCreated(conversation.Id, [initiatorId, otherUserId], now));
        return conversation;
    }

    public static Result<Conversation> CreateGroup(Guid creatorId, string? title, IReadOnlyCollection<Guid> memberIds, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(memberIds);
        var trimmed = title?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > TitleMaxLength)
        {
            return ConversationErrors.TitleInvalid;
        }

        var distinct = memberIds.Where(id => id != creatorId).Distinct().ToList();
        if (distinct.Count + 1 > MaxMembers)
        {
            return ConversationErrors.TooManyMembers;
        }

        var conversation = new Conversation(NewId(), ConversationType.Group, trimmed, creatorId, now);
        conversation._members.Add(new ConversationMember(conversation.Id, creatorId, MemberRole.Owner, now));
        foreach (var id in distinct)
        {
            conversation._members.Add(new ConversationMember(conversation.Id, id, MemberRole.Member, now));
        }

        conversation.Raise(new ConversationCreated(conversation.Id, conversation._members.Select(m => m.UserId).ToList(), now));
        return conversation;
    }

    public bool IsMember(Guid userId) => _members.Any(m => m.UserId == userId);

    public MemberRole? RoleOf(Guid userId) => _members.FirstOrDefault(m => m.UserId == userId)?.Role;

    public Result AddMember(Guid actorId, Guid userId, DateTimeOffset now)
    {
        if (Type != ConversationType.Group)
        {
            return ConversationErrors.NotAGroup;
        }

        if (RoleOf(actorId) is not (MemberRole.Admin or MemberRole.Owner))
        {
            return ConversationErrors.InsufficientRole;
        }

        if (IsMember(userId))
        {
            return ConversationErrors.AlreadyMember;
        }

        if (_members.Count >= MaxMembers)
        {
            return ConversationErrors.TooManyMembers;
        }

        _members.Add(new ConversationMember(Id, userId, MemberRole.Member, now));
        Raise(new MemberAdded(Id, userId, actorId, now));
        return Result.Success();
    }

    public Result RemoveMember(Guid actorId, Guid userId, DateTimeOffset now)
    {
        if (Type != ConversationType.Group)
        {
            return ConversationErrors.NotAGroup;
        }

        var target = _members.FirstOrDefault(m => m.UserId == userId);
        if (target is null)
        {
            return ConversationErrors.NotAMember;
        }

        var actorRole = RoleOf(actorId);
        var isSelf = actorId == userId;
        if (!isSelf && (actorRole is not (MemberRole.Admin or MemberRole.Owner) || target.Role >= actorRole))
        {
            return ConversationErrors.InsufficientRole;
        }

        if (target.Role == MemberRole.Owner && _members.Count(m => m.Role == MemberRole.Owner) == 1 && _members.Count > 1)
        {
            return ConversationErrors.LastOwner;
        }

        _members.Remove(target);
        Raise(new MemberRemoved(Id, userId, actorId, now));
        return Result.Success();
    }

    public Result Rename(Guid actorId, string? title)
    {
        if (Type != ConversationType.Group)
        {
            return ConversationErrors.NotAGroup;
        }

        if (RoleOf(actorId) is not (MemberRole.Admin or MemberRole.Owner))
        {
            return ConversationErrors.InsufficientRole;
        }

        var trimmed = title?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > TitleMaxLength)
        {
            return ConversationErrors.TitleInvalid;
        }

        Title = trimmed;
        return Result.Success();
    }
}

public sealed class ConversationMember
{
    private ConversationMember()
    {
    }

    internal ConversationMember(Guid conversationId, Guid userId, MemberRole role, DateTimeOffset joinedAt)
    {
        ConversationId = conversationId;
        UserId = userId;
        Role = role;
        JoinedAt = joinedAt;
    }

    public Guid ConversationId { get; private set; }
    public Guid UserId { get; private set; }
    public MemberRole Role { get; private set; }
    public DateTimeOffset JoinedAt { get; private set; }
}

public static class ConversationErrors
{
    public static readonly Error NotFound = Error.NotFound("conversation.not_found", "Conversation not found.");
    public static readonly Error CannotChatWithSelf = Error.Validation("conversation.self", "Cannot create a direct conversation with yourself.");
    public static readonly Error TitleInvalid = Error.Validation("conversation.title_invalid", "Group title must be 1-128 characters.");
    public static readonly Error TooManyMembers = Error.Validation("conversation.too_many_members", "Group exceeds the maximum number of members.");
    public static readonly Error NotAGroup = Error.Validation("conversation.not_a_group", "This operation applies to group conversations only.");
    public static readonly Error NotAMember = Error.Forbidden("conversation.not_a_member", "You are not a member of this conversation.");
    public static readonly Error AlreadyMember = Error.Conflict("conversation.already_member", "User is already a member.");
    public static readonly Error InsufficientRole = Error.Forbidden("conversation.insufficient_role", "You do not have permission to do that in this conversation.");
    public static readonly Error LastOwner = Error.Conflict("conversation.last_owner", "The last owner cannot leave; transfer ownership first.");
}

public sealed record ConversationCreated(Guid ConversationId, IReadOnlyList<Guid> MemberIds, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);

public sealed record MemberAdded(Guid ConversationId, Guid UserId, Guid ActorId, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);

public sealed record MemberRemoved(Guid ConversationId, Guid UserId, Guid ActorId, DateTimeOffset OccurredAt) : DomainEvent(OccurredAt);
