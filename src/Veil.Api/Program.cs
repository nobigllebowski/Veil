using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Scalar.AspNetCore;
using Serilog;
using Serilog.Formatting.Compact;
using Veil.Api;
using Veil.Api.Auth;
using Veil.Api.Endpoints;
using Veil.Api.Hubs;
using Veil.Api.Middleware;
using Veil.Application;
using Veil.Application.Abstractions.Realtime;
using Veil.Application.Abstractions.Security;
using Veil.Infrastructure;
using Veil.Infrastructure.Persistence;
using Veil.ServiceDefaults;

var builder = WebApplication.CreateBuilder(args);

// ---- Logging: structured, PII-free ------------------------------------------------------------------------
builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithMachineName()
        .Enrich.WithProperty("Application", "veil-api");

    if (context.HostingEnvironment.IsDevelopment())
    {
        configuration.WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}");
    }
    else
    {
        configuration.WriteTo.Console(new CompactJsonFormatter());
    }

    var otlp = context.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
    if (!string.IsNullOrWhiteSpace(otlp))
    {
        configuration.WriteTo.OpenTelemetry(options => options.Endpoint = otlp);
    }
});

builder.AddServiceDefaults();

// ---- Kestrel hardening ------------------------------------------------------------------------------------
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.Limits.MaxRequestBodySize = 20 * 1024 * 1024; // 256 envelopes x 64 KiB, base64-encoded
    kestrel.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
});

// ---- Application services ---------------------------------------------------------------------------------
builder.Services
    .AddVeilApplication()
    .AddVeilInfrastructure(builder.Configuration)
    .AddVeilAuthentication()
    .AddVeilRateLimiting(builder.Configuration)
    .AddVeilOpenApi();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, CurrentUser>();
builder.Services.AddScoped<IClientContext, ClientContext>();
builder.Services.AddSingleton<IRealtimeNotifier, SignalRRealtimeNotifier>();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddProblemDetails(options =>
    options.CustomizeProblemDetails = context =>
    {
        context.ProblemDetails.Extensions["traceId"] = context.HttpContext.TraceIdentifier;
        context.ProblemDetails.Instance ??= context.HttpContext.Request.Path;
    });
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

var redisConfigured = Veil.Infrastructure.DependencyInjection.IsRedisConfigured(builder.Configuration);

var signalR = builder.Services.AddSignalR(options =>
    {
        options.EnableDetailedErrors = builder.Environment.IsDevelopment();
        options.MaximumReceiveMessageSize = 64 * 1024;
        options.KeepAliveInterval = TimeSpan.FromSeconds(15);
        options.ClientTimeoutInterval = TimeSpan.FromSeconds(60);
    })
    .AddMessagePackProtocol();

if (redisConfigured)
{
    signalR.AddStackExchangeRedis(builder.Configuration.GetConnectionString("Redis")!, options => options.Configuration.ChannelPrefix = StackExchange.Redis.RedisChannel.Literal("veil"));
}

builder.Services.AddDataProtection()
    .SetApplicationName("veil")
    .PersistKeysToDbContext<VeilDbContext>();

builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
{
    var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
    if (origins.Length > 0)
    {
        policy.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod().AllowCredentials().WithExposedHeaders("Retry-After");
    }
}));

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    foreach (var proxy in builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [])
    {
        options.KnownProxies.Add(System.Net.IPAddress.Parse(proxy));
    }
});

var healthChecks = builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("Postgres")!, name: "postgres", tags: ["ready"]);
if (redisConfigured)
{
    healthChecks.AddRedis(builder.Configuration.GetConnectionString("Redis")!, name: "redis", tags: ["ready"]);
}

if (!builder.Environment.IsDevelopment())
{
    builder.Services.AddHsts(options =>
    {
        options.Preload = true;
        options.IncludeSubDomains = true;
        options.MaxAge = TimeSpan.FromDays(365);
    });
}

var app = builder.Build();

// ---- Pipeline ---------------------------------------------------------------------------------------------
app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Configuration.GetValue<bool>("ReverseProxy:Enabled"))
{
    app.UseForwardedHeaders();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

if (app.Configuration.GetValue("Https:Redirect", true))
{
    app.UseHttpsRedirection();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseSerilogRequestLogging(options => options.GetLevel = (ctx, _, ex) =>
    ex is not null || ctx.Response.StatusCode >= 500 ? Serilog.Events.LogEventLevel.Error
    : ctx.Request.Path.StartsWithSegments("/health") || ctx.Request.Path.StartsWithSegments("/alive") ? Serilog.Events.LogEventLevel.Verbose
    : Serilog.Events.LogEventLevel.Information);
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultEndpoints();
app.MapVeilApi();
app.MapHub<ChatHub>("/hubs/chat");

if (app.Configuration.GetValue("OpenApi:Enabled", app.Environment.IsDevelopment()))
{
    app.MapOpenApi().AllowAnonymous();
    app.MapScalarApiReference(options => options.WithTitle("Veil Messenger API").WithTheme(ScalarTheme.Kepler)).AllowAnonymous();
}

if (!await StartupChecks.RunAsync(app))
{
    return 1;
}

await app.RunAsync();
return 0;

/// <summary>Entry point marker for integration tests.</summary>
public partial class Program;
