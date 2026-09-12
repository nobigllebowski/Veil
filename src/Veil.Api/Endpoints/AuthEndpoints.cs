using Veil.Api.Auth;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Features.Auth;
using Veil.Application.Features.Keys;
using Veil.Application.Features.Users;
using Veil.Contracts;

namespace Veil.Api.Endpoints;

internal static class AuthEndpoints
{
    public static RouteGroupBuilder MapAuthEndpoints(this RouteGroupBuilder api)
    {
        var group = api.MapGroup("/auth").WithTags("Auth");

        group.MapPost("/register", async (RegisterRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RegisterCommand(request.Username, request.Email, request.Password, request.DisplayName), ct))
                    .ToHttp(profile => Results.Created($"/api/v1/users/{profile.Id}", profile)))
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Auth)
            .Produces<UserProfile>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status409Conflict)
            .WithSummary("Create an account.");

        group.MapPost("/login", async (LoginRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new LoginCommand(request.Username, request.Password, request.TotpCode, request.DeviceId), ct)).ToOk())
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Auth)
            .Produces<TokenPair>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .WithSummary("Exchange credentials (and an optional TOTP code) for tokens.");

        group.MapPost("/refresh", async (RefreshRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RefreshSessionCommand(request.RefreshToken), ct)).ToOk())
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Auth)
            .Produces<TokenPair>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .WithSummary("Rotate a refresh token. Reuse of a consumed token revokes the whole family.");

        group.MapPost("/logout", async (LogoutRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new LogoutCommand(request.RefreshToken), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent)
            .WithSummary("Revoke the presented refresh-token family.");

        group.MapPost("/logout-all", async (ISender sender, CancellationToken ct) =>
                (await sender.Send(new LogoutEverywhereCommand(), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent)
            .WithSummary("Revoke every session of the current user, including outstanding access tokens.");

        group.MapPost("/password", async (ChangePasswordRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new ChangePasswordCommand(request.CurrentPassword, request.NewPassword), ct)).ToOk())
            .Produces<TokenPair>()
            .WithSummary("Change password; all other sessions are revoked.");

        group.MapPost("/totp/enroll", async (ISender sender, CancellationToken ct) =>
                (await sender.Send(new BeginTotpEnrollmentCommand(), ct)).ToOk())
            .Produces<TotpEnrollment>()
            .WithSummary("Start TOTP enrollment and get the otpauth:// URI.");

        group.MapPost("/totp/confirm", async (ConfirmTotpRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new ConfirmTotpEnrollmentCommand(request.Code), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent)
            .WithSummary("Confirm TOTP enrollment with a live code.");

        group.MapPost("/totp/disable", async (DisableTotpRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new DisableTotpCommand(request.Password, request.Code), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent)
            .WithSummary("Disable TOTP (requires password and a live code).");

        return api;
    }
}

internal static class UserEndpoints
{
    public static RouteGroupBuilder MapUserEndpoints(this RouteGroupBuilder api)
    {
        var group = api.MapGroup("/users").WithTags("Users");

        group.MapGet("/me", async (ISender sender, CancellationToken ct) => (await sender.Send(new GetMeQuery(), ct)).ToOk())
            .Produces<UserProfile>();

        group.MapPatch("/me", async (UpdateProfileRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new UpdateProfileCommand(request.DisplayName), ct)).ToOk())
            .Produces<UserProfile>();

        group.MapGet("/by-username/{username}", async (string username, ISender sender, CancellationToken ct) =>
                (await sender.Send(new LookupUserQuery(username), ct)).ToOk())
            .RequireRateLimiting(RateLimitPolicies.Lookup)
            .Produces<PublicUser>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .WithSummary("Exact-match user lookup.");

        group.MapGet("/{userId:guid}/prekeys", async (Guid userId, ISender sender, CancellationToken ct) =>
                (await sender.Send(new GetPreKeyBundlesQuery(userId), ct)).ToOk())
            .RequireAuthorization(AuthPolicies.DeviceBound)
            .RequireRateLimiting(RateLimitPolicies.Keys)
            .Produces<IReadOnlyList<PreKeyBundleDto>>()
            .WithSummary("Fetch a pre-key bundle for every active device of a user (consumes one one-time pre-key per device).");

        return api;
    }
}
