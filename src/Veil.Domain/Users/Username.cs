using System.Text.RegularExpressions;
using Veil.Domain.Common;

namespace Veil.Domain.Users;

/// <summary>Case-insensitive handle: 3–32 chars of [a-z0-9_.], stored lower-case. Also used as the identifier in safety numbers.</summary>
public sealed partial record Username
{
    public const int MinLength = 3;
    public const int MaxLength = 32;

    private Username(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<Username> Create(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return UserErrors.UsernameInvalid;
        }

        var normalized = raw.Trim().ToLowerInvariant();
        return Pattern().IsMatch(normalized) ? new Username(normalized) : UserErrors.UsernameInvalid;
    }

    public static Username FromTrusted(string value) => new(value);

    public override string ToString() => Value;

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9_.]{1,30})[a-z0-9]$")]
    private static partial Regex Pattern();
}
