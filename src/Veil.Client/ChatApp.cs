using System.Globalization;
using Spectre.Console;
using Veil.Client.Sdk;
using Veil.Contracts;
using Veil.Crypto.Primitives;

namespace Veil.Client;

/// <summary>Interactive terminal session: login/registration, device setup, a chat REPL and live delivery.</summary>
internal sealed class ChatApp(Uri server, DirectoryInfo stateDir, bool insecure) : IAsyncDisposable
{
    private readonly HttpClient _http = CreateHttp(server, insecure);
    private VeilApiClient? _api;
    private VeilMessenger? _messenger;
    private RealtimeClient? _realtime;
    private ConversationSummary? _current;
    private readonly Dictionary<Guid, string> _usernames = new();

    public async Task RunAsync(CancellationToken ct)
    {
        AnsiConsole.Write(new FigletText("Veil").Color(Color.MediumPurple));
        AnsiConsole.MarkupLine($"[grey]server:[/] {Markup.Escape(server.ToString())}   [grey]protocol:[/] PQXDH (X25519 + ML-KEM-768) · Double Ratchet · AES-256-GCM");
        if (insecure)
        {
            AnsiConsole.MarkupLine("[yellow]TLS certificate validation is disabled (--insecure). Never use this outside local development.[/]");
        }

        _api = new VeilApiClient(_http);
        await SignInAsync(ct);
        await ConnectRealtimeAsync(ct);
        await PullAndPrintAsync(ct);
        PrintHelp();

        while (!ct.IsCancellationRequested)
        {
            var prompt = _current is null ? "[grey](no conversation)[/] > " : $"[mediumpurple]{Markup.Escape(Describe(_current))}[/] > ";
            var line = AnsiConsole.Prompt(new TextPrompt<string>(prompt).AllowEmpty());
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                if (!await HandleAsync(line.Trim(), ct))
                {
                    break;
                }
            }
            catch (VeilApiException ex)
            {
                AnsiConsole.MarkupLine($"[red]API error {(int)ex.StatusCode}[/] {Markup.Escape(ex.Message)} [grey]{Markup.Escape(ex.Code ?? string.Empty)}[/]");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(ex.Message)}");
            }
        }
    }

    private async Task<bool> HandleAsync(string line, CancellationToken ct)
    {
        if (!line.StartsWith('/'))
        {
            if (_current is null)
            {
                AnsiConsole.MarkupLine("[yellow]Open a conversation first: /chat <username>[/]");
                return true;
            }

            await _messenger!.SendTextAsync(_current.Id, line, ct);
            AnsiConsole.MarkupLine($"[grey]{DateTime.Now:HH:mm}[/] [green]you:[/] {Markup.Escape(line)}");
            return true;
        }

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        switch (parts[0].ToLowerInvariant())
        {
            case "/help":
                PrintHelp();
                break;
            case "/chat" when parts.Length == 2:
                await OpenDirectAsync(parts[1], ct);
                break;
            case "/group" when parts.Length >= 3:
                await CreateGroupAsync(parts[1], parts[2..], ct);
                break;
            case "/list":
                await ListConversationsAsync(ct);
                break;
            case "/open" when parts.Length == 2 && int.TryParse(parts[1], CultureInfo.InvariantCulture, out var index):
                await OpenByIndexAsync(index, ct);
                break;
            case "/devices":
                await ListDevicesAsync(ct);
                break;
            case "/safety":
                await ShowSafetyNumbersAsync(ct);
                break;
            case "/pull":
                await PullAndPrintAsync(ct);
                break;
            case "/totp":
                await EnrollTotpAsync(ct);
                break;
            case "/logout":
                await _api!.LogoutAsync(ct);
                AnsiConsole.MarkupLine("[grey]Logged out. Local encrypted state is kept; sessions resume on next login.[/]");
                return false;
            case "/quit" or "/exit":
                return false;
            default:
                AnsiConsole.MarkupLine("[yellow]Unknown command. /help lists the available ones.[/]");
                break;
        }

        return true;
    }

    private async Task SignInAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(stateDir.FullName);
        var username = AnsiConsole.Prompt(new TextPrompt<string>("Username:").Validate(u => u.Length >= 3 ? ValidationResult.Success() : ValidationResult.Error("at least 3 characters")));
        var statePath = Path.Combine(stateDir.FullName, $"{server.Host}_{server.Port}", $"{username.ToLowerInvariant()}.veil");

        if (File.Exists(statePath))
        {
            var passphrase = AnsiConsole.Prompt(new TextPrompt<string>("Local state passphrase:").Secret());
            var store = new EncryptedFileStateStore(statePath, passphrase);
            var state = await store.LoadAsync(ct) ?? throw new InvalidOperationException("State file is empty.");
            _messenger = new VeilMessenger(_api!, state, store);
            AttachMessengerEvents();

            try
            {
                await _api!.RefreshAsync(ct);
                AnsiConsole.MarkupLine($"[green]Welcome back, {Markup.Escape(state.Username)}.[/]");
            }
            catch (VeilApiException)
            {
                AnsiConsole.MarkupLine("[yellow]Session expired; please log in again.[/]");
                await LoginAsync(state.Username, state.DeviceId, ct);
            }

            await store.SaveAsync(state, ct);
            return;
        }

        var choice = AnsiConsole.Prompt(new SelectionPrompt<string>().Title("No local state for this user on this server.").AddChoices("Log in to an existing account", "Create a new account"));
        UserProfile profile;
        if (choice.StartsWith("Create", StringComparison.Ordinal))
        {
            var email = AnsiConsole.Prompt(new TextPrompt<string>("E-mail:"));
            var password = AnsiConsole.Prompt(new TextPrompt<string>("Password (12+ characters):").Secret());
            var displayName = AnsiConsole.Prompt(new TextPrompt<string>("Display name:").AllowEmpty());
            profile = await _api!.RegisterAsync(username, email, password, string.IsNullOrWhiteSpace(displayName) ? null : displayName, ct);
            await _api.LoginAsync(username, password, null, null, ct);
        }
        else
        {
            await LoginAsync(username, null, ct);
            profile = await _api!.GetMeAsync(ct);
        }

        var newPassphrase = AnsiConsole.Prompt(new TextPrompt<string>("Choose a passphrase for the local encrypted state:").Secret());
        var newStore = new EncryptedFileStateStore(statePath, newPassphrase);
        var newState = new ClientState { ServerUrl = server.ToString(), UserId = profile.Id, Username = profile.Username };
        _messenger = new VeilMessenger(_api!, newState, newStore);
        AttachMessengerEvents();

        var deviceName = AnsiConsole.Prompt(new TextPrompt<string>("Name this device:").DefaultValue(Environment.MachineName));
        await AnsiConsole.Status().StartAsync("Generating identity, pre-keys and ML-KEM-768 key pair…", async _ =>
        {
            await _messenger.RegisterDeviceAsync(deviceName, ct);
        });

        AnsiConsole.MarkupLine($"[green]Device registered.[/] Identity fingerprint: [grey]{CryptoBytes.ToHex(_messenger.Identity!.Fingerprint())[..32]}…[/]");
        AnsiConsole.MarkupLine($"[grey]State saved to {Markup.Escape(statePath)}[/]");
    }

    private async Task LoginAsync(string username, Guid? deviceId, CancellationToken ct)
    {
        while (true)
        {
            var password = AnsiConsole.Prompt(new TextPrompt<string>("Password:").Secret());
            try
            {
                await _api!.LoginAsync(username, password, null, deviceId, ct);
                return;
            }
            catch (VeilApiException ex) when (ex.Code == "auth.totp_required")
            {
                var code = AnsiConsole.Prompt(new TextPrompt<string>("Two-factor code:"));
                await _api!.LoginAsync(username, password, code, deviceId, ct);
                return;
            }
            catch (VeilApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                AnsiConsole.MarkupLine($"[red]{Markup.Escape(ex.Message)}[/]");
            }
        }
    }

    private async Task ConnectRealtimeAsync(CancellationToken ct)
    {
        _realtime = new RealtimeClient(server, () => Task.FromResult(_api!.AccessToken), insecure ? CreateInsecureHandler() : null);
        _realtime.EnvelopeAvailable += notification => _ = PullAndPrintAsync(CancellationToken.None);
        _realtime.ConversationChanged += n => AnsiConsole.MarkupLine($"[grey]conversation {n.ConversationId:N} {Markup.Escape(n.Change)}[/]");
        _realtime.DeviceListChanged += () => AnsiConsole.MarkupLine("[grey]your device list changed[/]");
        _realtime.Typing += n => AnsiConsole.MarkupLine($"[grey]{Markup.Escape(NameOf(n.UserId))} is typing…[/]");
        _realtime.Reconnected += () => _ = PullAndPrintAsync(CancellationToken.None);

        try
        {
            await _realtime.ConnectAsync(ct);
            AnsiConsole.MarkupLine("[grey]Real-time channel connected.[/]");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AnsiConsole.MarkupLine($"[yellow]Real-time channel unavailable ({Markup.Escape(ex.Message)}); use /pull to fetch messages.[/]");
        }
    }

    private async Task PullAndPrintAsync(CancellationToken ct)
    {
        if (_messenger is null || !_messenger.HasDevice)
        {
            return;
        }

        IReadOnlyList<IncomingMessage> messages;
        try
        {
            messages = await _messenger.PullAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AnsiConsole.MarkupLine($"[red]Pull failed:[/] {Markup.Escape(ex.Message)}");
            return;
        }

        foreach (var m in messages)
        {
            var sender = await NameOfAsync(m.SenderUserId, ct);
            var where = _current?.Id == m.ConversationId ? string.Empty : $" [grey](in {m.ConversationId.ToString("N")[..8]})[/]";
            AnsiConsole.MarkupLine($"[grey]{m.Message.SentAt.ToLocalTime():HH:mm}[/] [cyan]{Markup.Escape(sender)}:[/] {Markup.Escape(m.Message.Body)}{where}");
        }
    }

    private async Task OpenDirectAsync(string username, CancellationToken ct)
    {
        var user = await _api!.LookupUserAsync(username, ct);
        if (user is null)
        {
            AnsiConsole.MarkupLine("[yellow]No such user.[/]");
            return;
        }

        _usernames[user.Id] = user.Username;
        _current = await _api.CreateDirectConversationAsync(user.Id, ct);
        AnsiConsole.MarkupLine($"[green]Chatting with {Markup.Escape(user.DisplayName)} (@{Markup.Escape(user.Username)}).[/] Type a message, or /safety to verify keys.");
    }

    private async Task CreateGroupAsync(string title, string[] usernames, CancellationToken ct)
    {
        var ids = new List<Guid>();
        foreach (var name in usernames)
        {
            var user = await _api!.LookupUserAsync(name, ct);
            if (user is null)
            {
                AnsiConsole.MarkupLine($"[yellow]Unknown user {Markup.Escape(name)}; skipped.[/]");
                continue;
            }

            _usernames[user.Id] = user.Username;
            ids.Add(user.Id);
        }

        _current = await _api!.CreateGroupConversationAsync(title, ids, ct);
        AnsiConsole.MarkupLine($"[green]Group '{Markup.Escape(title)}' created with {_current.Members.Count} members.[/]");
    }

    private async Task ListConversationsAsync(CancellationToken ct)
    {
        var list = await _api!.ListConversationsAsync(ct);
        var table = new Table().AddColumns("#", "Type", "Title / peer", "Members", "Devices");
        for (var i = 0; i < list.Count; i++)
        {
            var c = list[i];
            foreach (var m in c.Members)
            {
                _usernames[m.UserId] = m.Username;
            }

            table.AddRow((i + 1).ToString(CultureInfo.InvariantCulture), c.Type, Markup.Escape(Describe(c)), c.Members.Count.ToString(CultureInfo.InvariantCulture), c.Members.Sum(m => m.DeviceIds.Count).ToString(CultureInfo.InvariantCulture));
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]/open <#> switches conversation.[/]");
    }

    private async Task OpenByIndexAsync(int index, CancellationToken ct)
    {
        var list = await _api!.ListConversationsAsync(ct);
        if (index < 1 || index > list.Count)
        {
            AnsiConsole.MarkupLine("[yellow]No such conversation.[/]");
            return;
        }

        _current = list[index - 1];
        foreach (var m in _current.Members)
        {
            _usernames[m.UserId] = m.Username;
        }
    }

    private async Task ListDevicesAsync(CancellationToken ct)
    {
        var table = new Table().AddColumns("Device", "Name", "Last active", "One-time pre-keys", "Current");
        foreach (var d in await _api!.ListDevicesAsync(ct))
        {
            table.AddRow(d.Id.ToString("N")[..8], Markup.Escape(d.Name), d.LastActiveAt.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), d.OneTimePreKeysRemaining.ToString(CultureInfo.InvariantCulture), d.IsCurrent ? "●" : string.Empty);
        }

        AnsiConsole.Write(table);
    }

    private async Task ShowSafetyNumbersAsync(CancellationToken ct)
    {
        if (_current is null)
        {
            AnsiConsole.MarkupLine("[yellow]Open a conversation first.[/]");
            return;
        }

        foreach (var member in _current.Members.Where(m => m.UserId != _messenger!.State.UserId))
        {
            foreach (var deviceId in member.DeviceIds)
            {
                var identity = _messenger!.KnownIdentityOf(member.UserId, deviceId);
                if (identity is null)
                {
                    AnsiConsole.MarkupLine($"[grey]{Markup.Escape(member.Username)}/{deviceId.ToString("N")[..8]}: no session yet — send a message first.[/]");
                    continue;
                }

                var number = _messenger.SafetyNumberWith(member.Username, identity);
                AnsiConsole.MarkupLine($"[cyan]{Markup.Escape(member.Username)}[/] device {deviceId.ToString("N")[..8]}:\n  [bold]{number}[/]");
            }
        }

        AnsiConsole.MarkupLine("[grey]Compare these digits with your contact over a trusted channel. Matching numbers rule out a man-in-the-middle, the server included.[/]");
        await Task.CompletedTask;
    }

    private async Task EnrollTotpAsync(CancellationToken ct)
    {
        var enrollment = await _api!.BeginTotpEnrollmentAsync(ct);
        AnsiConsole.MarkupLine($"Add this to your authenticator app:\n  [bold]{Markup.Escape(enrollment.OtpAuthUri)}[/]");
        var code = AnsiConsole.Prompt(new TextPrompt<string>("Enter the 6-digit code to confirm:"));
        await _api.ConfirmTotpAsync(code, ct);
        AnsiConsole.MarkupLine("[green]Two-factor authentication enabled.[/]");
    }

    private void AttachMessengerEvents()
    {
        _messenger!.Warning += w => AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(w)}[/]");
        _messenger.MessageUpdated += m => AnsiConsole.MarkupLine($"[grey]✓✓ delivered: {Markup.Escape(m.Body.Length > 24 ? m.Body[..24] + "…" : m.Body)}[/]");
        _messenger.IdentityChanged += change =>
            AnsiConsole.MarkupLine($"[red bold]Identity key of {Markup.Escape(NameOf(change.UserId))} device {change.DeviceId.ToString("N")[..8]} changed![/] Verify the safety number before trusting new messages.");
    }

    private string Describe(ConversationSummary c) =>
        c.Type == "Direct"
            ? "@" + (c.Members.FirstOrDefault(m => m.UserId != _messenger?.State.UserId)?.Username ?? "?")
            : c.Title ?? "(untitled group)";

    private string NameOf(Guid userId) => _usernames.GetValueOrDefault(userId, userId.ToString("N")[..8]);

    private async Task<string> NameOfAsync(Guid userId, CancellationToken ct)
    {
        if (_usernames.TryGetValue(userId, out var known))
        {
            return known;
        }

        foreach (var c in await _api!.ListConversationsAsync(ct))
        {
            foreach (var m in c.Members)
            {
                _usernames[m.UserId] = m.Username;
            }
        }

        return NameOf(userId);
    }

    private static void PrintHelp() =>
        AnsiConsole.MarkupLine("""
            [grey]Commands:[/] /chat <user> · /group <title> <user>… · /list · /open <#> · /devices · /safety · /pull · /totp · /logout · /quit
            [grey]Anything else is sent, end-to-end encrypted, to the open conversation.[/]
            """);

    private static HttpClient CreateHttp(Uri server, bool insecure)
    {
        var handler = insecure ? CreateInsecureHandler() : new HttpClientHandler();
        return new HttpClient(handler) { BaseAddress = server, Timeout = TimeSpan.FromSeconds(30) };
    }

    private static HttpClientHandler CreateInsecureHandler() => new()
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
    };

    public async ValueTask DisposeAsync()
    {
        if (_realtime is not null)
        {
            await _realtime.DisposeAsync();
        }

        _messenger?.Dispose();
        _api?.Dispose();
        _http.Dispose();
    }
}
