using System.Net.Mail;
using Veil.Domain.Common;

namespace Veil.Domain.Users;

/// <summary>Normalized (lower-cased, trimmed) e-mail address. Stored encrypted; looked up through a blind index.</summary>
public sealed record EmailAddress
{
    public const int MaxLength = 254;

    private EmailAddress(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<EmailAddress> Create(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return UserErrors.EmailInvalid;
        }

        var normalized = raw.Trim().ToLowerInvariant();
        if (normalized.Length > MaxLength || !MailAddress.TryCreate(normalized, out var parsed) || parsed.Address != normalized)
        {
            return UserErrors.EmailInvalid;
        }

        return new EmailAddress(normalized);
    }

    public static EmailAddress FromTrusted(string value) => new(value);

    public override string ToString() => Value;
}
