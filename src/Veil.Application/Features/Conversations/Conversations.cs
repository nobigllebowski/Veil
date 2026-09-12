using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Contracts;
using Veil.Domain.Audit;
using Veil.Domain.Common;
using Veil.Domain.Conversations;
using Veil.Domain.Users;

namespace Veil.Application.Features.Conversations;

public sealed record CreateDirectConversationCommand(Guid OtherUserId) : ICommand<Result<ConversationSummary>>;

internal sealed class CreateDirectConversationCommandHandler(
    IConversationRepository conversations,
    IUserRepository users,
    ConversationSummaries summaries,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<CreateDirectConversationCommand, Result<ConversationSummary>>
{
    public async Task<Result<ConversationSummary>> Handle(CreateDirectConversationCommand request, CancellationToken cancellationToken)
    {
        if (request.OtherUserId == currentUser.UserId)
        {
            return ConversationErrors.CannotChatWithSelf;
        }

        var other = await users.GetByIdAsync(request.OtherUserId, cancellationToken);
        if (other is null)
        {
            return UserErrors.NotFound;
        }

        var existing = await conversations.GetDirectAsync(Conversation.ComputeDirectKey(currentUser.UserId, other.Id), cancellationToken);
        if (existing is not null)
        {
            return await summaries.BuildAsync(existing, cancellationToken);
        }

        var created = Conversation.CreateDirect(currentUser.UserId, other.Id, time.GetUtcNow());
        if (created.IsFailure)
        {
            return created.Error;
        }

        conversations.Add(created.Value);
        await auditor.RecordAsync(AuditActions.ConversationCreated, currentUser.UserId, new { conversationId = created.Value.Id, type = "direct" }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return await summaries.BuildAsync(created.Value, cancellationToken);
    }
}

public sealed record CreateGroupConversationCommand(string Title, IReadOnlyList<Guid> MemberIds) : ICommand<Result<ConversationSummary>>;

internal sealed class CreateGroupConversationCommandValidator : AbstractValidator<CreateGroupConversationCommand>
{
    public CreateGroupConversationCommandValidator()
    {
        RuleFor(x => x.Title).NotEmpty().MaximumLength(Conversation.TitleMaxLength);
        RuleFor(x => x.MemberIds).NotNull().Must(m => m.Count <= Conversation.MaxMembers);
    }
}

internal sealed class CreateGroupConversationCommandHandler(
    IConversationRepository conversations,
    IUserRepository users,
    ConversationSummaries summaries,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<CreateGroupConversationCommand, Result<ConversationSummary>>
{
    public async Task<Result<ConversationSummary>> Handle(CreateGroupConversationCommand request, CancellationToken cancellationToken)
    {
        var memberIds = request.MemberIds.Where(id => id != currentUser.UserId).Distinct().ToList();
        var found = await users.GetByIdsAsync(memberIds, cancellationToken);
        if (found.Count != memberIds.Count)
        {
            return UserErrors.NotFound;
        }

        var created = Conversation.CreateGroup(currentUser.UserId, request.Title, memberIds, time.GetUtcNow());
        if (created.IsFailure)
        {
            return created.Error;
        }

        conversations.Add(created.Value);
        await auditor.RecordAsync(AuditActions.ConversationCreated, currentUser.UserId, new { conversationId = created.Value.Id, type = "group", members = memberIds.Count + 1 }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return await summaries.BuildAsync(created.Value, cancellationToken);
    }
}

public sealed record ListConversationsQuery : IQuery<Result<IReadOnlyList<ConversationSummary>>>;

internal sealed class ListConversationsQueryHandler(IConversationRepository conversations, ConversationSummaries summaries, ICurrentUser currentUser)
    : IQueryHandler<ListConversationsQuery, Result<IReadOnlyList<ConversationSummary>>>
{
    public async Task<Result<IReadOnlyList<ConversationSummary>>> Handle(ListConversationsQuery request, CancellationToken cancellationToken)
    {
        var list = await conversations.ListForUserAsync(currentUser.UserId, cancellationToken);
        return Result.Success(await summaries.BuildAsync(list, cancellationToken));
    }
}

public sealed record GetConversationQuery(Guid ConversationId) : IQuery<Result<ConversationSummary>>;

internal sealed class GetConversationQueryHandler(IConversationRepository conversations, ConversationSummaries summaries, ICurrentUser currentUser)
    : IQueryHandler<GetConversationQuery, Result<ConversationSummary>>
{
    public async Task<Result<ConversationSummary>> Handle(GetConversationQuery request, CancellationToken cancellationToken)
    {
        var conversation = await conversations.GetByIdAsync(request.ConversationId, cancellationToken);
        if (conversation is null || !conversation.IsMember(currentUser.UserId))
        {
            // Non-members get the same answer as for a non-existent conversation.
            return ConversationErrors.NotFound;
        }

        return await summaries.BuildAsync(conversation, cancellationToken);
    }
}

public sealed record AddMemberCommand(Guid ConversationId, Guid UserId) : ICommand<Result>;

internal sealed class AddMemberCommandHandler(
    IConversationRepository conversations,
    IUserRepository users,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<AddMemberCommand, Result>
{
    public async Task<Result> Handle(AddMemberCommand request, CancellationToken cancellationToken)
    {
        var conversation = await conversations.GetByIdAsync(request.ConversationId, cancellationToken);
        if (conversation is null || !conversation.IsMember(currentUser.UserId))
        {
            return ConversationErrors.NotFound;
        }

        if (await users.GetByIdAsync(request.UserId, cancellationToken) is null)
        {
            return UserErrors.NotFound;
        }

        var result = conversation.AddMember(currentUser.UserId, request.UserId, time.GetUtcNow());
        if (result.IsFailure)
        {
            return result;
        }

        await auditor.RecordAsync(AuditActions.MemberAdded, currentUser.UserId, new { conversationId = conversation.Id, userId = request.UserId }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }
}

/// <summary>Removes a member (or leaves, when <see cref="UserId"/> is the caller).</summary>
public sealed record RemoveMemberCommand(Guid ConversationId, Guid UserId) : ICommand<Result>;

internal sealed class RemoveMemberCommandHandler(
    IConversationRepository conversations,
    ICurrentUser currentUser,
    IAuditor auditor,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ICommandHandler<RemoveMemberCommand, Result>
{
    public async Task<Result> Handle(RemoveMemberCommand request, CancellationToken cancellationToken)
    {
        var conversation = await conversations.GetByIdAsync(request.ConversationId, cancellationToken);
        if (conversation is null || !conversation.IsMember(currentUser.UserId))
        {
            return ConversationErrors.NotFound;
        }

        var result = conversation.RemoveMember(currentUser.UserId, request.UserId, time.GetUtcNow());
        if (result.IsFailure)
        {
            return result;
        }

        await auditor.RecordAsync(AuditActions.MemberRemoved, currentUser.UserId, new { conversationId = conversation.Id, userId = request.UserId }, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }
}
