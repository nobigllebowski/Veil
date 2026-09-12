namespace Veil.Api.Endpoints;

internal static class ApiEndpoints
{
    public static WebApplication MapVeilApi(this WebApplication app)
    {
        var api = app.MapGroup("/api/v1").RequireAuthorization();

        api.MapAuthEndpoints()
           .MapUserEndpoints()
           .MapDeviceEndpoints()
           .MapConversationEndpoints()
           .MapMessageEndpoints();

        app.MapWellKnownEndpoints();
        return app;
    }
}
