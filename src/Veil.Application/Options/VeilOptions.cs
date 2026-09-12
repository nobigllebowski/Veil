using System.ComponentModel.DataAnnotations;

namespace Veil.Application.Options;

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    [Required]
    public string Issuer { get; set; } = "veil";

    [Required]
    public string Audience { get; set; } = "veil-clients";

    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    [Range(typeof(TimeSpan), "01:00:00", "90.00:00:00")]
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    [Range(3, 20)]
    public int MaxFailedLoginAttempts { get; set; } = 5;

    [Range(typeof(TimeSpan), "00:01:00", "1.00:00:00")]
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    [Required]
    public string TotpIssuer { get; set; } = "Veil";
}

public sealed class MessagingOptions
{
    public const string SectionName = "Messaging";

    /// <summary>How long undelivered envelopes are kept before being purged.</summary>
    [Range(typeof(TimeSpan), "01:00:00", "365.00:00:00")]
    public TimeSpan EnvelopeRetention { get; set; } = TimeSpan.FromDays(30);

    [Range(1, 500)]
    public int MaxPendingFetch { get; set; } = 100;
}
