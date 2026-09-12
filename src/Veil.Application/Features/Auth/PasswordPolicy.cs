namespace Veil.Application.Features.Auth;

/// <summary>
/// NIST SP 800-63B-aligned policy: length is what matters, composition rules are not enforced, and a short
/// deny-list blocks the most common long passwords. Screening against breach corpora belongs in a dedicated service.
/// </summary>
public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    private static readonly HashSet<string> DenyList = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "password12345", "123456789012", "1234567890123", "qwertyuiop12", "qwertyuiopasdf",
        "iloveyou1234", "adminadmin123", "letmeinletmein", "welcome12345", "changeme1234", "passwordpassword",
        "1q2w3e4r5t6y", "abcdefghijkl", "administrator", "1234qwer1234", "qwerty123456", "password!123",
    };

    public static bool IsAcceptable(string? password, string? username = null)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinLength || password.Length > MaxLength)
        {
            return false;
        }

        if (DenyList.Contains(password))
        {
            return false;
        }

        if (password.Distinct().Count() < 4)
        {
            return false;
        }

        if (!string.IsNullOrEmpty(username) && password.Contains(username, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }
}
