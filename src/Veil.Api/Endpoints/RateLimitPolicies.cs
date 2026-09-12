using System.Globalization;
using System.Threading.RateLimiting;
using Veil.Api.Auth;
using Veil.Api.Options;

namespace Veil.Api.Endpoints;

/// <summary>
/// Layered rate limits: a global per-caller cap, per-IP limits on unauthenticated auth endpoints (credential
/// stuffing, enumeration), and per-user limits on key fetches (one-time pre-key exhaustion) and lookups.
/// </summary>
internal static class RateLimitPolicies
{
    public const string Auth = "auth";
    public const string Keys = "keys";
    public const string Lookup = "lookup";
    public const string Messaging = "messaging";

    public static IServiceCollection AddVeilRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RateLimitOptions>().Bind(configuration.GetSection(RateLimitOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
        var limits = configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>() ?? new RateLimitOptions();

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, cancellationToken) =>
            {
                var retryAfterSeconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? Math.Max(1, (int)retryAfter.TotalSeconds) : 60;
                context.HttpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);

                context.HttpContext.Response.ContentType = "application/problem+json";
                await context.HttpContext.Response.WriteAsJsonAsync(new
                {
                    type = "https://veil.dev/errors/rate_limited",
                    title = "Too many requests.",
                    status = StatusCodes.Status429TooManyRequests,
                    code = "rate_limited",
                }, cancellationToken);
            };

            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                RateLimitPartition.GetTokenBucketLimiter(PartitionKey(context), _ => TokenBucket(limits.GlobalPerMinute)));

            options.AddPolicy(Auth, context => RateLimitPartition.GetSlidingWindowLimiter(IpKey(context), _ => SlidingWindow(limits.AuthPerMinute)));
            options.AddPolicy(Keys, context => RateLimitPartition.GetTokenBucketLimiter(PartitionKey(context), _ => TokenBucket(limits.KeysPerMinute)));
            options.AddPolicy(Lookup, context => RateLimitPartition.GetSlidingWindowLimiter(PartitionKey(context), _ => SlidingWindow(limits.LookupPerMinute)));
            options.AddPolicy(Messaging, context => RateLimitPartition.GetTokenBucketLimiter(PartitionKey(context), _ => TokenBucket(limits.MessagingPerMinute)));
        });

        return services;
    }

    private static TokenBucketRateLimiterOptions TokenBucket(int perMinute) => new()
    {
        TokenLimit = perMinute,
        TokensPerPeriod = perMinute,
        ReplenishmentPeriod = TimeSpan.FromMinutes(1),
        QueueLimit = 0,
        AutoReplenishment = true,
    };

    private static SlidingWindowRateLimiterOptions SlidingWindow(int perMinute) => new()
    {
        PermitLimit = perMinute,
        Window = TimeSpan.FromMinutes(1),
        SegmentsPerWindow = 6,
        QueueLimit = 0,
    };

    private static string PartitionKey(HttpContext context) =>
        CurrentUser.TryGetUserId(context.User) is { } userId ? $"user:{userId:N}" : IpKey(context);

    private static string IpKey(HttpContext context) => $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
}
