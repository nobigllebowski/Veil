using System.ComponentModel.DataAnnotations;

namespace Veil.Api.Options;

/// <summary>Per-minute permits for each limiter. Tuned down for tests, up for large deployments.</summary>
public sealed class RateLimitOptions
{
    public const string SectionName = "RateLimiting";

    [Range(1, 1_000_000)]
    public int GlobalPerMinute { get; set; } = 300;

    [Range(1, 1_000_000)]
    public int AuthPerMinute { get; set; } = 10;

    [Range(1, 1_000_000)]
    public int KeysPerMinute { get; set; } = 30;

    [Range(1, 1_000_000)]
    public int LookupPerMinute { get; set; } = 60;

    [Range(1, 1_000_000)]
    public int MessagingPerMinute { get; set; } = 120;
}
