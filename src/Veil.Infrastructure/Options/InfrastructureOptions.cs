using System.ComponentModel.DataAnnotations;

namespace Veil.Infrastructure.Options;

/// <summary>
/// Key material for server-side cryptography. Every value must come from a secret store or environment variable
/// in production; the repository ships only clearly-marked development keys.
/// </summary>
public sealed class SecurityOptions
{
    public const string SectionName = "Security";

    /// <summary>Base64, 32 bytes. Master key for AES-256-GCM field encryption (e-mail, TOTP secrets, group titles).</summary>
    [Required]
    public string FieldEncryptionKey { get; set; } = string.Empty;

    /// <summary>Base64, 32 bytes. HMAC key for blind indexes over encrypted columns.</summary>
    [Required]
    public string BlindIndexKey { get; set; } = string.Empty;

    /// <summary>Random salt mixed into IP-address hashes stored in audit and token records.</summary>
    [Required]
    [MinLength(16)]
    public string IpHashSalt { get; set; } = string.Empty;

    /// <summary>PKCS#8 PEM of the ECDSA P-256 key that signs access tokens. Optional in Development (ephemeral key is generated).</summary>
    public string? JwtSigningKeyPem { get; set; }

    public string JwtSigningKeyId { get; set; } = "veil-es256-1";

    public Argon2Options Argon2 { get; set; } = new();
}

/// <summary>Argon2id cost parameters (OWASP 2024 baseline: 64 MiB, 3 iterations, 4 lanes).</summary>
public sealed class Argon2Options
{
    [Range(8 * 1024, 4 * 1024 * 1024)]
    public int MemoryKiB { get; set; } = 64 * 1024;

    [Range(1, 20)]
    public int Iterations { get; set; } = 3;

    [Range(1, 16)]
    public int Parallelism { get; set; } = 4;
}

public sealed class OutboxOptions
{
    public const string SectionName = "Outbox";

    [Range(typeof(TimeSpan), "00:00:00.100", "00:01:00")]
    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(2);

    [Range(1, 500)]
    public int BatchSize { get; set; } = 50;

    [Range(1, 100)]
    public int MaxAttempts { get; set; } = 10;
}
