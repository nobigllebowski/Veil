using Veil.Domain.Common;

namespace Veil.Domain.Users;

public static class UserErrors
{
    public static readonly Error UsernameInvalid = Error.Validation("user.username_invalid", "Username must be 3-32 characters of letters, digits, dots or underscores.");
    public static readonly Error EmailInvalid = Error.Validation("user.email_invalid", "E-mail address is invalid.");
    public static readonly Error DisplayNameInvalid = Error.Validation("user.display_name_invalid", "Display name must be 1-64 characters.");
    public static readonly Error UsernameTaken = Error.Conflict("user.username_taken", "This username is already taken.");
    public static readonly Error NotFound = Error.NotFound("user.not_found", "User not found.");
    public static readonly Error TotpAlreadyEnabled = Error.Conflict("user.totp_already_enabled", "Two-factor authentication is already enabled.");
    public static readonly Error TotpNotPending = Error.Conflict("user.totp_not_pending", "Two-factor setup has not been started.");
    public static readonly Error TotpNotEnabled = Error.Conflict("user.totp_not_enabled", "Two-factor authentication is not enabled.");
}
