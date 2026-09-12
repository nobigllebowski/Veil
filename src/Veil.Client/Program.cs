using System.CommandLine;
using Spectre.Console;
using Veil.Client;

var serverOption = new Option<Uri>("--server", "-s") { Description = "Base URL of the Veil API, e.g. https://localhost:7443", DefaultValueFactory = _ => new Uri("https://localhost:7443") };
var stateDirOption = new Option<DirectoryInfo>("--state-dir") { Description = "Directory for encrypted local state.", DefaultValueFactory = _ => new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".veil")) };
var insecureOption = new Option<bool>("--insecure") { Description = "Accept the ASP.NET Core development certificate (local testing only)." };

var root = new RootCommand("Veil — end-to-end encrypted messenger (PQXDH + Double Ratchet).")
{
    serverOption,
    stateDirOption,
    insecureOption,
};

root.SetAction(async (parseResult, cancellationToken) =>
{
    var server = parseResult.GetValue(serverOption)!;
    var stateDir = parseResult.GetValue(stateDirOption)!;
    var insecure = parseResult.GetValue(insecureOption);

    try
    {
        await using var app = new ChatApp(server, stateDir, insecure);
        await app.RunAsync(cancellationToken);
        return 0;
    }
    catch (OperationCanceledException)
    {
        return 130;
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[red]Fatal:[/] {Markup.Escape(ex.Message)}");
        return 1;
    }
});

return await root.Parse(args).InvokeAsync();
