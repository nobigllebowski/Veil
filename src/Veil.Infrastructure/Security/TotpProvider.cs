using System.Globalization;
using OtpNet;
using StackExchange.Redis;
using Veil.Application.Abstractions.Security;

namespace Veil.Infrastructure.Security;

/// <summary>RFC 6238 TOTP (SHA-1, 30 s, 6 digits – what every authenticator app supports) with one-time acceptance per time-step.</summary>
public sealed class TotpProvider(IConnectionMultiplexer redis, TimeProvider time) : ITotpProvider
{
    private const int StepSeconds = 30;
    private static readonly VerificationWindow Window = new(previous: 1, future: 1);

    public string GenerateSecret() => Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));

    public string BuildOtpAuthUri(string issuer, string account, string secret) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period={StepSeconds}";

    public async Task<bool> VerifyAsync(Guid userId, string secret, string code, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(code);

        byte[] key;
        try
        {
            key = Base32Encoding.ToBytes(secret);
        }
        catch (ArgumentException)
        {
            return false;
        }

        var totp = new Totp(key, step: StepSeconds, totpSize: 6);
        if (!totp.VerifyTotp(time.GetUtcNow().UtcDateTime, code, out var matchedStep, Window))
        {
            return false;
        }

        // Each time-step may authenticate once: an observed code cannot be replayed within its validity window.
        var replayKey = $"totp:used:{userId:N}:{matchedStep.ToString(CultureInfo.InvariantCulture)}";
        var database = redis.GetDatabase();
        return await database.StringSetAsync(replayKey, "1", TimeSpan.FromSeconds(StepSeconds * 4), When.NotExists);
    }
}
