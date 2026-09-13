using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Veil.Web;
using Veil.Web.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// The UI is served by the API itself, so the API base address is simply the page origin.
var apiBase = new Uri(builder.Configuration["ApiBaseUrl"] ?? builder.HostEnvironment.BaseAddress);
builder.Services.AddSingleton(new ApiEndpoint(apiBase));
builder.Services.AddScoped(_ => new HttpClient { BaseAddress = apiBase, Timeout = TimeSpan.FromSeconds(60) });
builder.Services.AddScoped<BrowserStorage>();
builder.Services.AddScoped<AppSession>();

await builder.Build().RunAsync();
