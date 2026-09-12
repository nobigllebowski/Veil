using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Veil.Application.Abstractions.Security;
using Veil.Infrastructure.Security;

namespace Veil.Api.Auth;

/// <summary>Reads identity from the validated bearer token of the current HTTP request or SignalR connection.</summary>
internal sealed class CurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    private ClaimsPrincipal? Principal => accessor.HttpContext?.User;

    public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated == true;

    public Guid UserId => TryGetUserId(Principal) ?? throw new InvalidOperationException("No authenticated user.");

    public Guid? DeviceId => TryGetDeviceId(Principal);

    public static Guid? TryGetUserId(ClaimsPrincipal? principal) =>
        Guid.TryParse(principal?.FindFirstValue(JwtRegisteredClaimNames.Sub), out var id) ? id : null;

    public static Guid? TryGetDeviceId(ClaimsPrincipal? principal) =>
        Guid.TryParse(principal?.FindFirstValue(VeilClaims.DeviceId), out var id) ? id : null;
}
