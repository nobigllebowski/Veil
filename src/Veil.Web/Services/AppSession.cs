using System.Net;
using Veil.Client.Sdk;
using Veil.Contracts;
using Veil.Crypto.Primitives;

namespace Veil.Web.Services;

public enum SessionPhase
{
    Booting,
    SignedOut,
    Locked,
    Ready,
}

public sealed record Toast(Guid Id, string Text, bool IsError);

/// <summary>
/// The client's single source of truth: authentication and local-state lifecycle, the E2EE messenger, the
/// real-time connection, conversation/presence/typing caches, and change notifications for the UI.
/// </summary>
public sealed class AppSession(HttpClient http, BrowserStorage storage, ApiEndpoint endpoint) : IAsyncDisposable
{
    private static readonly TimeSpan TypingTimeout = TimeSpan.FromSeconds(5);

    private readonly Dictionary<Guid, MemberDto> _members = new();
    private readonly Dictionary<Guid, Dictionary<Guid, DateTimeOffset>> _typing = new();
    private readonly HashSet<Guid> _online = new();
    private readonly List<Toast> _toasts = [];
    private readonly SemaphoreSlim _pullGate = new(1, 1);
    private CancellationTokenSource? _fallbackPolling;
    private DateTimeOffset _lastTypingSent = DateTimeOffset.MinValue;
    private Guid _lastTypingConversation;

    public SessionPhase Phase { get; private set; } = SessionPhase.Booting;
    public string? Username { get; private set; }
    public UserProfile? Profile { get; private set; }
    public VeilApiClient? Api { get; private set; }
    public VeilMessenger? Messenger { get; private set; }
    public RealtimeClient? Realtime { get; private set; }
    public IReadOnlyList<ConversationSummary> Conversations { get; private set; } = [];
    public IReadOnlyList<Toast> Toasts => _toasts;
    public bool RealtimeConnected { get; private set; }
    public Guid UserId => Messenger?.State.UserId ?? Guid.Empty;

    /// <summary>Raised whenever anything the UI shows may have changed.</summary>
    public event Action? Changed;

    /// <summary>Raised for every new text message stored in history (own or received).</summary>
    public event Action<StoredMessage>? MessageArrived;

    // ---- Lifecycle -------------------------------------------------------------------------------------

    public async Task InitializeAsync()
    {
        if (Phase != SessionPhase.Booting)
        {
            return;
        }

        var active = await storage.GetSessionAsync("veil.active");
        if (active is not null)
        {
            var cachedKey = await storage.GetSessionAsync(BrowserStateStore.SessionKey(active));
            if (cachedKey is not null && await TryOpenAsync(active, Convert.FromBase64String(cachedKey), password: null))
            {
                return;
            }
        }

        var accounts = await BrowserStateStore.KnownAccountsAsync(storage);
        Phase = accounts.Count > 0 ? SessionPhase.Locked : SessionPhase.SignedOut;
        Notify();
    }

    public Task<IReadOnlyList<string>> KnownAccountsAsync() => BrowserStateStore.KnownAccountsAsync(storage);

    public async Task RegisterAsync(string username, string email, string password, string? displayName)
    {
        using var api = new VeilApiClient(http);
        await api.RegisterAsync(username, email, password, displayName);
    }

    /// <summary>Password (+ optional TOTP) sign-in. Reuses the encrypted local state when this browser already has one.</summary>
    public async Task LoginAsync(string username, string password, string? totpCode)
    {
        var api = new VeilApiClient(http);
        await api.LoginAsync(username, password, totpCode);
        var profile = await api.GetMeAsync();

        var salt = await BrowserStateStore.GetOrCreateSaltAsync(storage, profile.Username);
        var key = BrowserStateStore.DeriveKey(password, salt);
        var store = new BrowserStateStore(storage, profile.Username, key);

        ClientState? state = null;
        if (await BrowserStateStore.ExistsAsync(storage, profile.Username))
        {
            try
            {
                state = await store.LoadAsync();
            }
            catch (UnauthorizedAccessException)
            {
                // Password changed since the state was written: the old keys are unrecoverable, start a fresh device.
                await BrowserStateStore.WipeAsync(storage, profile.Username);
                salt = await BrowserStateStore.GetOrCreateSaltAsync(storage, profile.Username);
                key = BrowserStateStore.DeriveKey(password, salt);
                store = new BrowserStateStore(storage, profile.Username, key);
                AddToast("Local data was encrypted with an old password and has been reset. This browser is now a new device.", isError: false);
            }
        }

        state ??= new ClientState { ServerUrl = endpoint.BaseAddress.ToString(), UserId = profile.Id, Username = profile.Username };
        var messenger = new VeilMessenger(api, state, store);

        if (!messenger.HasDevice)
        {
            await messenger.RegisterDeviceAsync(await storage.DeviceNameAsync());
        }
        else
        {
            // Prefer the device-bound refresh token; fall back to a device-bound login when it expired.
            try
            {
                await api.RefreshAsync();
            }
            catch (VeilApiException)
            {
                await api.LoginAsync(username, password, totpCode, state.DeviceId);
                state.RefreshToken = api.RefreshToken;
                await store.SaveAsync(state);
            }
        }

        await storage.SetSessionAsync("veil.active", profile.Username);
        await storage.SetSessionAsync(BrowserStateStore.SessionKey(profile.Username), Convert.ToBase64String(key));
        await BecomeReadyAsync(api, messenger, profile);
    }

    /// <summary>Decrypts existing local state with the password; no server round-trip unless the refresh token expired.</summary>
    public async Task UnlockAsync(string username, string password)
    {
        var salt = await BrowserStateStore.GetOrCreateSaltAsync(storage, username);
        var key = BrowserStateStore.DeriveKey(password, salt);
        if (!await TryOpenAsync(username, key, password))
        {
            throw new UnauthorizedAccessException("Wrong password.");
        }
    }

    public async Task LogoutAsync(bool wipeLocalData)
    {
        var username = Username;
        try
        {
            if (Api is not null)
            {
                await Api.LogoutAsync();
            }
        }
        catch (VeilApiException)
        {
            // Best effort: the refresh token expires on its own.
        }

        await TeardownAsync();
        if (username is not null)
        {
            await storage.RemoveSessionAsync(BrowserStateStore.SessionKey(username));
            if (wipeLocalData)
            {
                await BrowserStateStore.WipeAsync(storage, username);
            }
        }

        await storage.RemoveSessionAsync("veil.active");
        var accounts = await BrowserStateStore.KnownAccountsAsync(storage);
        Phase = accounts.Count > 0 ? SessionPhase.Locked : SessionPhase.SignedOut;
        Notify();
    }

    // ---- Conversations ---------------------------------------------------------------------------------

    public async Task RefreshConversationsAsync()
    {
        if (Api is null)
        {
            return;
        }

        var list = await Api.ListConversationsAsync();
        Conversations = list
            .OrderByDescending(c => LastActivity(c))
            .ToList();

        foreach (var member in list.SelectMany(c => c.Members))
        {
            _members[member.UserId] = member;
        }

        var others = _members.Keys.Where(id => id != UserId).ToList();
        if (others.Count > 0)
        {
            try
            {
                var presence = await Api.GetPresenceAsync(others);
                _online.Clear();
                _online.UnionWith(presence.OnlineUserIds);
            }
            catch (VeilApiException)
            {
                // presence is decorative
            }
        }

        Notify();
    }

    public ConversationSummary? FindConversation(Guid id) => Conversations.FirstOrDefault(c => c.Id == id);

    public async Task<ConversationSummary> StartDirectAsync(string username)
    {
        var api = RequireApi();
        var user = await api.LookupUserAsync(username) ?? throw new InvalidOperationException($"No user named @{username}.");
        var conversation = await api.CreateDirectConversationAsync(user.Id);
        await RefreshConversationsAsync();
        return conversation;
    }

    public async Task<ConversationSummary> CreateGroupAsync(string title, IEnumerable<string> usernames)
    {
        var api = RequireApi();
        var ids = new List<Guid>();
        foreach (var name in usernames.Select(n => n.Trim().TrimStart('@')).Where(n => n.Length > 0).Distinct())
        {
            var user = await api.LookupUserAsync(name) ?? throw new InvalidOperationException($"No user named @{name}.");
            ids.Add(user.Id);
        }

        var conversation = await api.CreateGroupConversationAsync(title, ids);
        await RefreshConversationsAsync();
        return conversation;
    }

    public async Task AddMemberAsync(Guid conversationId, string username)
    {
        var api = RequireApi();
        var user = await api.LookupUserAsync(username.Trim().TrimStart('@')) ?? throw new InvalidOperationException($"No user named @{username}.");
        await api.AddMemberAsync(conversationId, user.Id);
        await RefreshConversationsAsync();
    }

    public async Task LeaveAsync(Guid conversationId)
    {
        await RequireApi().RemoveMemberAsync(conversationId, UserId);
        await RefreshConversationsAsync();
    }

    // ---- Messaging -------------------------------------------------------------------------------------

    public async Task SendAsync(Guid conversationId, string text)
    {
        var messenger = RequireMessenger();
        await messenger.SendTextAsync(conversationId, text);
        Notify();
    }

    public async Task PullAsync()
    {
        if (Messenger is null || !await _pullGate.WaitAsync(0))
        {
            return;
        }

        try
        {
            var received = await Messenger.PullAsync();
            foreach (var message in received)
            {
                if (message.SenderUserId != UserId)
                {
                    await storage.NotifyAsync(DisplayNameOf(message.SenderUserId), message.Message.Body);
                }
            }

            if (received.Count > 0)
            {
                Conversations = Conversations.OrderByDescending(LastActivity).ToList();
            }
        }
        catch (Exception ex) when (ex is VeilApiException or HttpRequestException or Veil.Crypto.CryptoException)
        {
            AddToast("Could not fetch new messages: " + ex.Message, isError: true);
        }
        finally
        {
            _pullGate.Release();
            Notify();
        }
    }

    public Task MarkReadAsync(Guid conversationId) => Messenger?.MarkReadAsync(conversationId) ?? Task.CompletedTask;

    public async Task SendTypingAsync(Guid conversationId)
    {
        if (Realtime is null || !RealtimeConnected)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_lastTypingConversation == conversationId && now - _lastTypingSent < TimeSpan.FromSeconds(3))
        {
            return;
        }

        _lastTypingSent = now;
        _lastTypingConversation = conversationId;
        try
        {
            await Realtime.SendTypingAsync(conversationId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // typing indicators are best effort
            _ = ex;
        }
    }

    public IReadOnlyList<Guid> TypingIn(Guid conversationId)
    {
        if (!_typing.TryGetValue(conversationId, out var users))
        {
            return [];
        }

        var now = DateTimeOffset.UtcNow;
        return users.Where(kv => kv.Value > now).Select(kv => kv.Key).ToList();
    }

    public bool IsOnline(Guid userId) => _online.Contains(userId);

    public string DisplayNameOf(Guid userId) =>
        userId == UserId ? "You" : _members.TryGetValue(userId, out var m) ? m.DisplayName : userId.ToString("N")[..8];

    public string UsernameOf(Guid userId) => _members.TryGetValue(userId, out var m) ? m.Username : userId.ToString("N")[..8];

    public string TitleOf(ConversationSummary conversation) =>
        conversation.Type == "Direct"
            ? conversation.Members.FirstOrDefault(m => m.UserId != UserId)?.DisplayName ?? "Direct chat"
            : conversation.Title ?? "Group";

    public MemberDto? PeerOf(ConversationSummary conversation) =>
        conversation.Type == "Direct" ? conversation.Members.FirstOrDefault(m => m.UserId != UserId) : null;

    public StoredMessage? LastMessage(Guid conversationId)
    {
        var history = Messenger?.History(conversationId);
        return history is { Count: > 0 } ? history[^1] : null;
    }

    public int Unread(Guid conversationId) => Messenger?.UnreadCount(conversationId) ?? 0;

    public void AddToast(string text, bool isError)
    {
        _toasts.Add(new Toast(Guid.NewGuid(), text, isError));
        if (_toasts.Count > 4)
        {
            _toasts.RemoveAt(0);
        }

        Notify();
    }

    public void DismissToast(Guid id)
    {
        _toasts.RemoveAll(t => t.Id == id);
        Notify();
    }

    public async ValueTask DisposeAsync()
    {
        await TeardownAsync();
        _pullGate.Dispose();
    }

    // ---- Internals -------------------------------------------------------------------------------------

    private async Task<bool> TryOpenAsync(string username, byte[] key, string? password)
    {
        var store = new BrowserStateStore(storage, username, key);
        ClientState? state;
        try
        {
            state = await store.LoadAsync();
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }

        if (state is null)
        {
            return false;
        }

        var api = new VeilApiClient(http);
        var messenger = new VeilMessenger(api, state, store);
        UserProfile profile;
        try
        {
            await api.RefreshAsync();
            profile = await api.GetMeAsync();
        }
        catch (VeilApiException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized && password is not null)
        {
            try
            {
                await api.LoginAsync(username, password, null, state.DeviceId);
            }
            catch (VeilApiException loginFailure) when (loginFailure.Code == "auth.totp_required")
            {
                messenger.Dispose();
                api.Dispose();
                throw new InvalidOperationException("Your server session expired and this account uses two-factor authentication: please sign in again from the login page.");
            }

            state.RefreshToken = api.RefreshToken;
            await store.SaveAsync(state);
            profile = await api.GetMeAsync();
        }
        catch (VeilApiException)
        {
            messenger.Dispose();
            api.Dispose();
            return false;
        }

        await storage.SetSessionAsync("veil.active", username);
        await storage.SetSessionAsync(BrowserStateStore.SessionKey(username), Convert.ToBase64String(key));
        await BecomeReadyAsync(api, messenger, profile);
        return true;
    }

    private async Task BecomeReadyAsync(VeilApiClient api, VeilMessenger messenger, UserProfile profile)
    {
        await TeardownAsync();

        Api = api;
        Messenger = messenger;
        Profile = profile;
        Username = profile.Username;
        messenger.Warning += w => AddToast(w, isError: true);
        messenger.IdentityChanged += c => AddToast($"Safety number with {DisplayNameOf(c.UserId)} changed. Verify it before trusting new messages.", isError: true);
        messenger.MessageStored += m => MessageArrived?.Invoke(m);
        messenger.MessageUpdated += _ => Notify();

        Phase = SessionPhase.Ready;
        Notify();

        await RefreshConversationsAsync();
        await PullAsync();
        await ConnectRealtimeAsync();
        await storage.RequestNotificationsAsync();
    }

    private async Task ConnectRealtimeAsync()
    {
        if (Api is null)
        {
            return;
        }

        var realtime = new RealtimeClient(endpoint.BaseAddress, () => Task.FromResult(Api.AccessToken), useMessagePack: false);
        realtime.EnvelopeAvailable += notification => _ = PullAsync();
        realtime.ConversationChanged += notification => _ = RefreshConversationsAsync();
        realtime.DeviceListChanged += () => Notify();
        realtime.Typing += n =>
        {
            if (!_typing.TryGetValue(n.ConversationId, out var users))
            {
                users = new Dictionary<Guid, DateTimeOffset>();
                _typing[n.ConversationId] = users;
            }

            users[n.UserId] = DateTimeOffset.UtcNow + TypingTimeout;
            Notify();
            _ = ClearTypingLaterAsync();
        };
        realtime.PresenceChanged += n =>
        {
            if (n.IsOnline)
            {
                _online.Add(n.UserId);
            }
            else
            {
                _online.Remove(n.UserId);
            }

            Notify();
        };
        realtime.Reconnected += () =>
        {
            RealtimeConnected = true;
            _ = PullAsync();
            _ = RefreshConversationsAsync();
        };
        realtime.Closed += () =>
        {
            RealtimeConnected = false;
            Notify();
        };

        Realtime = realtime;
        try
        {
            await realtime.ConnectAsync();
            RealtimeConnected = true;
            Notify();

            // Anything that happened between the initial fetch and the hub connection produced no notification: catch up once.
            await RefreshConversationsAsync();
            await PullAsync();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            RealtimeConnected = false;
            AddToast("Live updates are unavailable; messages will refresh on demand. " + ex.Message, isError: true);
        }

        _fallbackPolling = new CancellationTokenSource();
        _ = PollInBackgroundAsync(_fallbackPolling.Token);
        Notify();
    }

    /// <summary>
    /// Safety net behind the hub: a quick poll while real-time is down, a slow one while it is up, so a missed
    /// notification (dropped connection, backplane hiccup) delays a message instead of losing it until the next reload.
    /// </summary>
    private async Task PollInBackgroundAsync(CancellationToken ct)
    {
        var tick = 0;
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
            while (await timer.WaitForNextTickAsync(ct))
            {
                tick++;
                if (Phase != SessionPhase.Ready)
                {
                    continue;
                }

                if (!RealtimeConnected || tick % 6 == 0)
                {
                    await PullAsync();
                    if (!RealtimeConnected || tick % 12 == 0)
                    {
                        try
                        {
                            await RefreshConversationsAsync();
                        }
                        catch (Exception ex) when (ex is VeilApiException or HttpRequestException)
                        {
                            // the next tick retries
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // signed out
        }
    }

    private async Task ClearTypingLaterAsync()
    {
        await Task.Delay(TypingTimeout + TimeSpan.FromMilliseconds(200));
        Notify();
    }

    private async Task TeardownAsync()
    {
        if (_fallbackPolling is not null)
        {
            await _fallbackPolling.CancelAsync();
            _fallbackPolling.Dispose();
            _fallbackPolling = null;
        }

        if (Realtime is not null)
        {
            await Realtime.DisposeAsync();
            Realtime = null;
        }

        Messenger?.Dispose();
        Messenger = null;
        Api?.Dispose();
        Api = null;
        Profile = null;
        Username = null;
        Conversations = [];
        _members.Clear();
        _online.Clear();
        _typing.Clear();
        RealtimeConnected = false;
    }

    private DateTimeOffset LastActivity(ConversationSummary conversation) =>
        LastMessage(conversation.Id)?.SentAt ?? conversation.CreatedAt;

    private VeilApiClient RequireApi() => Api ?? throw new InvalidOperationException("Not signed in.");

    private VeilMessenger RequireMessenger() => Messenger ?? throw new InvalidOperationException("Not signed in.");

    private void Notify() => Changed?.Invoke();

    public static string Initials(string name)
    {
        var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length switch
        {
            0 => "?",
            1 => parts[0][..Math.Min(2, parts[0].Length)].ToUpperInvariant(),
            _ => string.Concat(parts[0][0], parts[1][0]).ToUpperInvariant(),
        };
    }

    public static string Hue(Guid id) => (BitConverter.ToUInt32(id.ToByteArray(), 0) % 360).ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static string Fingerprint(Veil.Crypto.Keys.IdentityPublicKeys identity) => CryptoBytes.ToHex(identity.Fingerprint())[..16];
}
