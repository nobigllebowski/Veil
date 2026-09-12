using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Veil.Application.Abstractions.Security;
using Veil.Infrastructure.Options;

namespace Veil.Api.Auth;

/// <summary>Transport facts about the caller. Raw IP addresses are never persisted; only a salted hash is.</summary>
internal sealed class ClientContext(IHttpContextAccessor accessor, IOptions<SecurityOptions> options) : IClientContext
{
    private string? _ipHash;

    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();

    public string? IpHash
    {
        get
        {
            if (_ipHash is null && IpAddress is { } ip)
            {
                var input = Encoding.UTF8.GetBytes(options.Value.IpHashSalt + "|" + ip);
                _ipHash = Base64Url.EncodeToString(SHA256.HashData(input).AsSpan(0, 24));
            }

            return _ipHash;
        }
    }

    public string? UserAgent
    {
        get
        {
            var value = accessor.HttpContext?.Request.Headers.UserAgent.ToString();
            return string.IsNullOrEmpty(value) ? null : value.Length > 256 ? value[..256] : value;
        }
    }
}
