using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Veil.Contracts;
using Veil.Crypto.Keys;

namespace Veil.Client.Sdk;

/// <summary>
/// Typed HTTP client for the Veil API. Transparently refreshes the access token before expiry and once on 401.
/// </summary>
public sealed class VeilApiClient(HttpClient http) : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public string? AccessToken { get; private set; }
    public DateTimeOffset AccessTokenExpiresAt { get; private set; }
    public string? RefreshToken { get; private set; }
    public Guid? DeviceId { get; private set; }

    /// <summary>Invoked whenever tokens change so callers can persist them.</summary>
    public event Action<TokenPair>? TokensChanged;

    public void UseTokens(TokenPair tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        AccessToken = tokens.AccessToken;
        AccessTokenExpiresAt = tokens.AccessTokenExpiresAt;
        RefreshToken = tokens.RefreshToken;
        DeviceId = tokens.DeviceId;
        TokensChanged?.Invoke(tokens);
    }

    public void UseRefreshToken(string refreshToken, Guid? deviceId)
    {
        RefreshToken = refreshToken;
        DeviceId = deviceId;
        AccessToken = null;
        AccessTokenExpiresAt = DateTimeOffset.MinValue;
    }

    public void ClearTokens()
    {
        AccessToken = null;
        RefreshToken = null;
        DeviceId = null;
    }

    // ---- Auth -------------------------------------------------------------------------------------------

    public Task<UserProfile> RegisterAsync(string username, string email, string password, string? displayName, CancellationToken ct = default) =>
        PostAsync<UserProfile>("api/v1/auth/register", new RegisterRequest(username, email, password, displayName), authenticated: false, ct);

    public async Task<TokenPair> LoginAsync(string username, string password, string? totpCode = null, Guid? deviceId = null, CancellationToken ct = default)
    {
        var tokens = await PostAsync<TokenPair>("api/v1/auth/login", new LoginRequest(username, password, totpCode, deviceId), authenticated: false, ct);
        UseTokens(tokens);
        return tokens;
    }

    public async Task<TokenPair> RefreshAsync(CancellationToken ct = default)
    {
        await _refreshLock.WaitAsync(ct);
        try
        {
            if (RefreshToken is null)
            {
                throw new VeilApiException(HttpStatusCode.Unauthorized, null);
            }

            var tokens = await PostAsync<TokenPair>("api/v1/auth/refresh", new RefreshRequest(RefreshToken), authenticated: false, ct);
            UseTokens(tokens);
            return tokens;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        await SendAsync(HttpMethod.Post, "api/v1/auth/logout", new LogoutRequest(RefreshToken), authenticated: true, ct);
        ClearTokens();
    }

    public Task LogoutEverywhereAsync(CancellationToken ct = default) =>
        SendAsync(HttpMethod.Post, "api/v1/auth/logout-all", null, authenticated: true, ct);

    public async Task<TokenPair> ChangePasswordAsync(string currentPassword, string newPassword, CancellationToken ct = default)
    {
        var tokens = await PostAsync<TokenPair>("api/v1/auth/password", new ChangePasswordRequest(currentPassword, newPassword), authenticated: true, ct);
        UseTokens(tokens);
        return tokens;
    }

    public Task<TotpEnrollment> BeginTotpEnrollmentAsync(CancellationToken ct = default) =>
        PostAsync<TotpEnrollment>("api/v1/auth/totp/enroll", null, authenticated: true, ct);

    public Task ConfirmTotpAsync(string code, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Post, "api/v1/auth/totp/confirm", new ConfirmTotpRequest(code), authenticated: true, ct);

    public Task DisableTotpAsync(string password, string code, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Post, "api/v1/auth/totp/disable", new DisableTotpRequest(password, code), authenticated: true, ct);

    // ---- Users ------------------------------------------------------------------------------------------

    public Task<UserProfile> GetMeAsync(CancellationToken ct = default) => GetAsync<UserProfile>("api/v1/users/me", ct);

    public Task<UserProfile> UpdateProfileAsync(string displayName, CancellationToken ct = default) =>
        SendAsync<UserProfile>(HttpMethod.Patch, "api/v1/users/me", new UpdateProfileRequest(displayName), authenticated: true, ct);

    public async Task<PublicUser?> LookupUserAsync(string username, CancellationToken ct = default)
    {
        try
        {
            return await GetAsync<PublicUser>($"api/v1/users/by-username/{Uri.EscapeDataString(username)}", ct);
        }
        catch (VeilApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public Task<PresenceResponse> GetPresenceAsync(IEnumerable<Guid> userIds, CancellationToken ct = default) =>
        GetAsync<PresenceResponse>("api/v1/users/presence?" + string.Join('&', userIds.Select(id => "userIds=" + id)), ct);

    public Task<IReadOnlyList<PreKeyBundleDto>> GetPreKeyBundlesAsync(Guid userId, CancellationToken ct = default) =>
        GetAsync<IReadOnlyList<PreKeyBundleDto>>($"api/v1/users/{userId}/prekeys", ct);

    // ---- Devices ----------------------------------------------------------------------------------------

    public async Task<DeviceRegistration> RegisterDeviceAsync(string name, PublishedKeys keys, IEnumerable<OneTimePreKeyUpload> oneTimePreKeys, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var request = new RegisterDeviceRequest(
            name,
            new IdentityKeysDto(keys.Identity.SigningKey, keys.Identity.DhKey, keys.Identity.DhKeySignature),
            keys.SignedPreKeyId,
            keys.SignedPreKey,
            keys.SignedPreKeySignature,
            keys.KemPreKeyId,
            keys.KemPreKey,
            keys.KemPreKeySignature,
            oneTimePreKeys.ToList());

        var registration = await PostAsync<DeviceRegistration>("api/v1/devices/", request, authenticated: true, ct);
        UseTokens(registration.Tokens);
        return registration;
    }

    public Task<IReadOnlyList<DeviceSummary>> ListDevicesAsync(CancellationToken ct = default) =>
        GetAsync<IReadOnlyList<DeviceSummary>>("api/v1/devices/", ct);

    public Task RevokeDeviceAsync(Guid deviceId, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Delete, $"api/v1/devices/{deviceId}", null, authenticated: true, ct);

    public async Task<int> GetOneTimePreKeyCountAsync(CancellationToken ct = default) =>
        (await GetAsync<CountResponse>("api/v1/devices/me/prekeys/count", ct)).Count;

    public async Task<int> UploadOneTimePreKeysAsync(IReadOnlyList<OneTimePreKeyUpload> keys, CancellationToken ct = default) =>
        (await PostAsync<CountResponse>("api/v1/devices/me/prekeys", new UploadOneTimePreKeysRequest(keys), authenticated: true, ct)).Count;

    public Task RotateSignedPreKeyAsync(uint keyId, byte[] publicKey, byte[] signature, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Put, "api/v1/devices/me/signed-prekey", new RotatePreKeyRequest(keyId, publicKey, signature), authenticated: true, ct);

    public Task RotateKemPreKeyAsync(uint keyId, byte[] publicKey, byte[] signature, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Put, "api/v1/devices/me/kem-prekey", new RotatePreKeyRequest(keyId, publicKey, signature), authenticated: true, ct);

    // ---- Conversations ----------------------------------------------------------------------------------

    public Task<IReadOnlyList<ConversationSummary>> ListConversationsAsync(CancellationToken ct = default) =>
        GetAsync<IReadOnlyList<ConversationSummary>>("api/v1/conversations/", ct);

    public Task<ConversationSummary> GetConversationAsync(Guid id, CancellationToken ct = default) =>
        GetAsync<ConversationSummary>($"api/v1/conversations/{id}", ct);

    public Task<ConversationSummary> CreateDirectConversationAsync(Guid otherUserId, CancellationToken ct = default) =>
        PostAsync<ConversationSummary>("api/v1/conversations/direct", new CreateDirectConversationRequest(otherUserId), authenticated: true, ct);

    public Task<ConversationSummary> CreateGroupConversationAsync(string title, IReadOnlyList<Guid> memberIds, CancellationToken ct = default) =>
        PostAsync<ConversationSummary>("api/v1/conversations/group", new CreateGroupConversationRequest(title, memberIds), authenticated: true, ct);

    public Task AddMemberAsync(Guid conversationId, Guid userId, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Post, $"api/v1/conversations/{conversationId}/members", new AddMemberRequest(userId), authenticated: true, ct);

    public Task RemoveMemberAsync(Guid conversationId, Guid userId, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Delete, $"api/v1/conversations/{conversationId}/members/{userId}", null, authenticated: true, ct);

    // ---- Messages ---------------------------------------------------------------------------------------

    public Task<SendReceipt> SendEnvelopesAsync(Guid conversationId, IReadOnlyList<OutgoingEnvelope> envelopes, CancellationToken ct = default) =>
        PostAsync<SendReceipt>("api/v1/messages/", new SendEnvelopesRequest(conversationId, envelopes), authenticated: true, ct);

    public Task<IReadOnlyList<PendingEnvelopeDto>> FetchPendingAsync(CancellationToken ct = default) =>
        GetAsync<IReadOnlyList<PendingEnvelopeDto>>("api/v1/messages/pending", ct);

    public async Task<int> AcknowledgeAsync(IReadOnlyList<Guid> envelopeIds, CancellationToken ct = default) =>
        envelopeIds.Count == 0 ? 0 : (await PostAsync<CountResponse>("api/v1/messages/ack", new AcknowledgeRequest(envelopeIds), authenticated: true, ct)).Count;

    // ---- Plumbing ---------------------------------------------------------------------------------------

    private Task<T> GetAsync<T>(string path, CancellationToken ct) => SendAsync<T>(HttpMethod.Get, path, null, authenticated: true, ct);

    private Task<T> PostAsync<T>(string path, object? body, bool authenticated, CancellationToken ct) => SendAsync<T>(HttpMethod.Post, path, body, authenticated, ct);

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body, bool authenticated, CancellationToken ct)
    {
        using var response = await SendCoreAsync(method, path, body, authenticated, ct);
        return await response.Content.ReadFromJsonAsync<T>(Json, ct) ?? throw new VeilApiException("Empty response body.");
    }

    private async Task SendAsync(HttpMethod method, string path, object? body, bool authenticated, CancellationToken ct)
    {
        using var response = await SendCoreAsync(method, path, body, authenticated, ct);
    }

    private async Task<HttpResponseMessage> SendCoreAsync(HttpMethod method, string path, object? body, bool authenticated, CancellationToken ct)
    {
        if (authenticated)
        {
            await EnsureFreshAccessTokenAsync(ct);
        }

        var response = await IssueAsync(method, path, body, authenticated, ct);
        if (response.StatusCode == HttpStatusCode.Unauthorized && authenticated && RefreshToken is not null)
        {
            response.Dispose();
            await RefreshAsync(ct);
            response = await IssueAsync(method, path, body, authenticated, ct);
        }

        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        ApiProblem? problem = null;
        if (response.Content.Headers.ContentType?.MediaType is "application/problem+json" or "application/json")
        {
            try
            {
                problem = await response.Content.ReadFromJsonAsync<ApiProblem>(Json, ct);
            }
            catch (JsonException)
            {
                // Non-JSON body: fall through with a null problem.
            }
        }

        var status = response.StatusCode;
        response.Dispose();
        throw new VeilApiException(status, problem);
    }

    private async Task<HttpResponseMessage> IssueAsync(HttpMethod method, string path, object? body, bool authenticated, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType(), options: Json);
        }

        if (authenticated && AccessToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
        }

        return await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
    }

    public void Dispose() => _refreshLock.Dispose();

    private async Task EnsureFreshAccessTokenAsync(CancellationToken ct)
    {
        if (RefreshToken is not null && (AccessToken is null || AccessTokenExpiresAt <= DateTimeOffset.UtcNow.AddSeconds(30)))
        {
            await RefreshAsync(ct);
        }
    }
}
