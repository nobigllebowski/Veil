using Veil.Application.Abstractions.Persistence;
using Veil.Contracts;
using Veil.Domain.Conversations;

namespace Veil.Application.Features.Conversations;

/// <summary>Builds client-facing summaries, batching the user and device lookups for all members.</summary>
internal sealed class ConversationSummaries(IUserRepository users, IDeviceRepository devices)
{
    public async Task<IReadOnlyList<ConversationSummary>> BuildAsync(IReadOnlyCollection<Conversation> conversations, CancellationToken cancellationToken)
    {
        var memberIds = conversations.SelectMany(c => c.Members.Select(m => m.UserId)).Distinct().ToList();
        if (memberIds.Count == 0)
        {
            return [];
        }

        var userMap = (await users.GetByIdsAsync(memberIds, cancellationToken)).ToDictionary(u => u.Id);
        var deviceMap = (await devices.ListActiveByUsersAsync(memberIds, cancellationToken))
            .GroupBy(d => d.UserId)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<Guid>)g.Select(d => d.Id).ToList());

        return conversations.Select(c => new ConversationSummary(
            c.Id,
            c.Type.ToString(),
            c.Title,
            c.CreatedAt,
            c.Members
                .Where(m => userMap.ContainsKey(m.UserId))
                .Select(m => new MemberDto(
                    m.UserId,
                    userMap[m.UserId].Username.Value,
                    userMap[m.UserId].DisplayName,
                    m.Role.ToString(),
                    deviceMap.GetValueOrDefault(m.UserId, [])))
                .ToList())).ToList();
    }

    public async Task<ConversationSummary> BuildAsync(Conversation conversation, CancellationToken cancellationToken) =>
        (await BuildAsync([conversation], cancellationToken))[0];
}
