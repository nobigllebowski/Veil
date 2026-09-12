using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Veil.Contracts;

namespace Veil.Client.Sdk;

/// <summary>SignalR client for <c>/hubs/chat</c>: routing notifications only; content still travels through the encrypted envelope API.</summary>
public sealed class RealtimeClient : IAsyncDisposable
{
    private readonly HubConnection _connection;
    private readonly PeriodicTimer _heartbeat = new(TimeSpan.FromSeconds(60));
    private Task? _heartbeatLoop;
    private readonly CancellationTokenSource _cts = new();

    public RealtimeClient(Uri serverUrl, Func<Task<string?>> accessTokenProvider, HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(serverUrl);
        _connection = new HubConnectionBuilder()
            .WithUrl(new Uri(serverUrl, "hubs/chat"), options =>
            {
                options.AccessTokenProvider = accessTokenProvider;
                if (handler is not null)
                {
                    options.HttpMessageHandlerFactory = _ => handler;
                }
            })
            .AddMessagePackProtocol()
            .WithAutomaticReconnect()
            .Build();

        _connection.On<EnvelopeAvailableNotification>("EnvelopeAvailable", n => EnvelopeAvailable?.Invoke(n));
        _connection.On<ConversationChangedNotification>("ConversationChanged", n => ConversationChanged?.Invoke(n));
        _connection.On("DeviceListChanged", () => DeviceListChanged?.Invoke());
        _connection.On<TypingNotification>("Typing", n => Typing?.Invoke(n));
        _connection.Reconnected += _ => { Reconnected?.Invoke(); return Task.CompletedTask; };
    }

    public event Action<EnvelopeAvailableNotification>? EnvelopeAvailable;
    public event Action<ConversationChangedNotification>? ConversationChanged;
    public event Action? DeviceListChanged;
    public event Action<TypingNotification>? Typing;
    public event Action? Reconnected;

    public HubConnectionState State => _connection.State;

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        await _connection.StartAsync(ct);
        _heartbeatLoop ??= RunHeartbeatAsync();
    }

    public Task SendTypingAsync(Guid conversationId, CancellationToken ct = default) =>
        _connection.InvokeAsync("Typing", conversationId, ct);

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _heartbeat.Dispose();
        if (_heartbeatLoop is not null)
        {
            try
            {
                await _heartbeatLoop;
            }
            catch (OperationCanceledException)
            {
                // expected on shutdown
            }
        }

        await _connection.DisposeAsync();
        _cts.Dispose();
    }

    private async Task RunHeartbeatAsync()
    {
        while (await _heartbeat.WaitForNextTickAsync(_cts.Token))
        {
            if (_connection.State == HubConnectionState.Connected)
            {
                try
                {
                    await _connection.InvokeAsync("Heartbeat", _cts.Token);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Presence is best-effort; a missed heartbeat only delays the online indicator.
                }
            }
        }
    }
}
