namespace Veil.Api.Middleware;

/// <summary>
/// Defence-in-depth response headers with a policy per surface: the JSON API gets a "deny everything" CSP and
/// <c>no-store</c>; the Blazor WebAssembly client gets the minimum it needs (<c>wasm-unsafe-eval</c> for the
/// runtime, inline styles for component CSS); the interactive API reference under <c>/scalar</c> gets its CDN.
/// </summary>
internal sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private const string ApiCsp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    private const string UiCsp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";
    private const string DocsCsp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

    private static readonly string[] ApiPrefixes = ["/api", "/hubs", "/health", "/alive", "/openapi", "/.well-known"];

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(static state =>
        {
            var ctx = (HttpContext)state;
            var headers = ctx.Response.Headers;
            var surface = Classify(ctx.Request.Path);

            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
            headers["Cross-Origin-Opener-Policy"] = "same-origin";
            headers["Cross-Origin-Resource-Policy"] = "same-origin";
            headers["Content-Security-Policy"] = surface switch
            {
                Surface.Docs => DocsCsp,
                Surface.Ui => UiCsp,
                _ => ApiCsp,
            };

            if (surface == Surface.Api && !headers.ContainsKey("Cache-Control"))
            {
                headers["Cache-Control"] = "no-store";
            }

            return Task.CompletedTask;
        }, context);

        return next(context);
    }

    private static Surface Classify(PathString path)
    {
        if (path.StartsWithSegments("/scalar", StringComparison.OrdinalIgnoreCase))
        {
            return Surface.Docs;
        }

        foreach (var prefix in ApiPrefixes)
        {
            if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return Surface.Api;
            }
        }

        return Surface.Ui;
    }

    private enum Surface
    {
        Api,
        Ui,
        Docs,
    }
}
