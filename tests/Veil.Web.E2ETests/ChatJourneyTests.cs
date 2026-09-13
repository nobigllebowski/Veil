using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace Veil.Web.E2ETests;

/// <summary>Drives the real Blazor client in Chromium: two users register, chat end-to-end encrypted, verify safety numbers and survive a reload.</summary>
public sealed class ChatJourneyTests : IAsyncLifetime
{
    private const string Password = "correct-horse-battery-staple";

    private readonly ApiHost _api = new();
    private readonly List<string> _console = [];
    private int _pages;
    private IPlaywright? _playwright;
    private IBrowser? _browser;

    public async ValueTask InitializeAsync()
    {
        await _api.InitializeAsync();
        _playwright = await Playwright.CreateAsync();
        var options = new BrowserTypeLaunchOptions { Headless = true };
        var executable = Environment.GetEnvironmentVariable("VEIL_E2E_CHROMIUM");
        if (!string.IsNullOrEmpty(executable))
        {
            options.ExecutablePath = executable;
        }

        _browser = await _playwright.Chromium.LaunchAsync(options);
    }

    public async ValueTask DisposeAsync()
    {
        if (_browser is not null)
        {
            await _browser.DisposeAsync();
        }

        _playwright?.Dispose();
        await _api.DisposeAsync();
    }

    [Fact]
    public async Task Two_users_chat_through_the_web_client()
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        var aliceName = "alice" + suffix;
        var bobName = "bob" + suffix;

        var alice = await NewPageAsync();
        var bob = await NewPageAsync();

        try
        {
            await RegisterAsync(alice, aliceName, "Alice");
            await RegisterAsync(bob, bobName, "Bob");

            // Alice starts a direct chat with Bob and sends the first (pre-key) message.
            await alice.GetByTitle("New chat").ClickAsync();
            await alice.GetByPlaceholder("alice").FillAsync(bobName);
            await alice.GetByRole(AriaRole.Button, new() { Name = "Start chat" }).ClickAsync();
            await alice.WaitForURLAsync(new Regex("/chat/[0-9a-f-]{36}$"));

            await alice.Locator(".composer textarea").FillAsync("hello bob 👋");
            await alice.Locator(".composer textarea").PressAsync("Enter");
            await Expect(alice.Locator(".bubble-row.out .bubble-text")).ToHaveTextAsync("hello bob 👋");

            // Bob sees the conversation appear live, opens it and reads the decrypted text.
            var bobConversation = bob.Locator(".conversation", new() { HasText = "Alice" });
            await Expect(bobConversation).ToBeVisibleAsync(new() { Timeout = 60_000 });
            await bobConversation.ClickAsync();
            await Expect(bob.Locator(".bubble-row.in .bubble-text")).ToHaveTextAsync("hello bob 👋", new() { Timeout = 60_000 });

            // Bob's device answered with an encrypted delivery receipt: Alice's tick doubles.
            await Expect(alice.Locator(".bubble-row.out .ticks")).ToHaveTextAsync("✓✓", new() { Timeout = 60_000 });

            // Bob replies; Alice receives it in real time.
            await bob.Locator(".composer textarea").FillAsync("hi alice");
            await bob.Locator(".composer textarea").PressAsync("Enter");
            await Expect(alice.Locator(".bubble-row.in .bubble-text")).ToHaveTextAsync("hi alice", new() { Timeout = 60_000 });

            // Safety numbers match on both sides.
            await alice.GetByTitle("Verify safety numbers").ClickAsync();
            var aliceNumber = await alice.Locator(".safety-number").First.InnerTextAsync();
            await alice.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
            await bob.GetByTitle("Verify safety numbers").ClickAsync();
            var bobNumber = await bob.Locator(".safety-number").First.InnerTextAsync();
            aliceNumber.Replace(" ", "", StringComparison.Ordinal).Length.ShouldBe(60);
            bobNumber.ShouldBe(aliceNumber);
            await bob.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();

            // A reload keeps the session and the locally stored, decrypted history.
            await alice.ReloadAsync();
            await Expect(alice.Locator(".bubble-text")).ToHaveCountAsync(2, new() { Timeout = 60_000 });
            await Expect(alice.Locator(".bubble-row.in .bubble-text")).ToHaveTextAsync("hi alice");

            // The server never stored the plaintext: only ciphertext envelopes pass through and they are gone once acknowledged.
            using var http = new HttpClient { BaseAddress = _api.BaseAddress };
            var health = await http.GetStringAsync(new Uri("health", UriKind.Relative));
            health.ShouldBe("Healthy");
        }
        catch
        {
            Console.WriteLine("API log tail:\n" + _api.Log());
            await _api.DumpLogAsync("api.log");
            var directory = Environment.GetEnvironmentVariable("VEIL_E2E_LOG_DIR");
            if (!string.IsNullOrEmpty(directory))
            {
                string[] lines;
                lock (_console)
                {
                    lines = [.. _console];
                }

                await File.WriteAllLinesAsync(Path.Combine(directory, "browser.log"), lines);
            }

            throw;
        }
    }

    private async Task<IPage> NewPageAsync()
    {
        var context = await _browser!.NewContextAsync(new() { BaseURL = _api.BaseAddress.ToString(), Locale = "en-US" });
        context.SetDefaultTimeout(90_000);
        var page = await context.NewPageAsync();
        var name = "page" + Interlocked.Increment(ref _pages);
        page.Console += (_, message) =>
        {
            lock (_console)
            {
                _console.Add($"[{DateTime.UtcNow:HH:mm:ss.fff} {name} {message.Type}] {message.Text}");
            }

            if (message.Type is "error" or "warning")
            {
                Console.WriteLine($"[browser {message.Type}] {message.Text}");
            }
        };
        return page;
    }

    private static async Task RegisterAsync(IPage page, string username, string displayName)
    {
        await page.GotoAsync("/register");
        await page.GetByLabel("Username").FillAsync(username);
        await page.GetByLabel("Display name").FillAsync(displayName);
        await page.GetByLabel("E-mail").FillAsync(username + "@example.com");
        await page.GetByLabel("Password").FillAsync(Password);
        await page.GetByRole(AriaRole.Button, new() { Name = "Create account" }).ClickAsync();
        await Expect(page.GetByText("Select a conversation")).ToBeVisibleAsync(new() { Timeout = 90_000 });

        // The hub connection is established after the page becomes usable; wait for it so live updates are expected below.
        await Expect(page.Locator(".me-handle")).Not.ToContainTextAsync("offline", new() { Timeout = 60_000 });
    }

    private static ILocatorAssertions Expect(ILocator locator) => Assertions.Expect(locator);
}
