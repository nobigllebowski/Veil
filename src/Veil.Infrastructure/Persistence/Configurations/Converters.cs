using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Veil.Domain.Users;
using Veil.Infrastructure.Security;

namespace Veil.Infrastructure.Persistence.Configurations;

internal static class Converters
{
    public static readonly ValueConverter<uint, long> UIntToLong = new(v => v, v => (uint)v);

    public static readonly ValueConverter<Username, string> UsernameConverter = new(u => u.Value, v => Username.FromTrusted(v));

    /// <summary>Encrypts a string column with AES-256-GCM, bound to the given purpose.</summary>
    public static ValueConverter<string, string> EncryptedString(IFieldEncryptor encryptor, string purpose) =>
        new(plain => encryptor.Protect(plain, purpose), cipher => encryptor.Unprotect(cipher, purpose));

    public static ValueConverter<string?, string?> EncryptedNullableString(IFieldEncryptor encryptor, string purpose) =>
        new(plain => plain == null ? null : encryptor.Protect(plain, purpose), cipher => cipher == null ? null : encryptor.Unprotect(cipher, purpose));

    public static ValueConverter<EmailAddress, string> EncryptedEmail(IFieldEncryptor encryptor, string purpose) =>
        new(email => encryptor.Protect(email.Value, purpose), cipher => EmailAddress.FromTrusted(encryptor.Unprotect(cipher, purpose)));
}
