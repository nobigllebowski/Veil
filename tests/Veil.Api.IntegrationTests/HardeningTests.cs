using System.Net;
using System.Net.Http.Json;
using Veil.Client.Sdk;
using Veil.Contracts;

namespace Veil.Api.IntegrationTests;

[Collection(ApiCollection.Name)]
public class HardeningTests(VeilApiFactory factory)
{
    [Fact]
    public async Task Every_response_carries_defensive_headers()
    {
        using var client = factory.CreateClient();
        var response = await client.GetAsync(new Uri("/api/v1/users/me", UriKind.Relative));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        response.Headers.GetValues("X-Content-Type-Options").ShouldBe(["nosniff"]);
        response.Headers.GetValues("X-Frame-Options").ShouldBe(["DENY"]);
        response.Headers.GetValues("Referrer-Policy").ShouldBe(["no-referrer"]);
        response.Headers.GetValues("Content-Security-Policy").Single().ShouldContain("default-src 'none'");
        response.Headers.GetValues("Cross-Origin-Opener-Policy").ShouldBe(["same-origin"]);
        response.Headers.CacheControl!.NoStore.ShouldBeTrue();
        response.Headers.Contains("Server").ShouldBeFalse();
    }

    [Fact]
    public async Task Errors_are_rfc9457_problem_details_without_stack_traces()
    {
        using var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/register", UriKind.Relative), new RegisterRequest("x", "nope", "short", null));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType!.MediaType.ShouldBe("application/problem+json");
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();
        problem!.Code.ShouldBe("validation.failed");
        problem.Errors!.Keys.ShouldContain("username");
        problem.Errors.Keys.ShouldContain("password");
        problem.TraceId.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task Malformed_json_is_a_clean_400()
    {
        using var client = factory.CreateClient();
        using var content = new StringContent("{not json", System.Text.Encoding.UTF8, "application/json");
        var response = await client.PostAsync(new Uri("/api/v1/auth/login", UriKind.Relative), content);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.ShouldNotContain("   at ");
    }

    [Fact]
    public async Task Device_scoped_endpoints_reject_user_only_sessions()
    {
        using var persona = await TestPersona.CreateAsync(factory, "hard", registerDevice: false);

        var ex = await Should.ThrowAsync<VeilApiException>(() => persona.Api.FetchPendingAsync());
        ex.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Health_and_discovery_endpoints_are_public()
    {
        using var client = factory.CreateClient();
        (await client.GetAsync(new Uri("/health", UriKind.Relative))).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await client.GetAsync(new Uri("/alive", UriKind.Relative))).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await client.GetAsync(new Uri("/.well-known/veil-configuration", UriKind.Relative))).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await client.GetAsync(new Uri("/openapi/v1.json", UriKind.Relative))).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Auth_endpoints_are_rate_limited_per_ip()
    {
        using var limited = factory.WithWebHostBuilder(builder => builder.UseSetting("RateLimiting:AuthPerMinute", "3"));
        using var client = limited.CreateClient();

        HttpStatusCode last = HttpStatusCode.OK;
        for (var i = 0; i < 4; i++)
        {
            using var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), new LoginRequest("ghost", "irrelevant-password", null, null));
            last = response.StatusCode;
            if (last == HttpStatusCode.TooManyRequests)
            {
                response.Headers.RetryAfter.ShouldNotBeNull();
                var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();
                problem!.Code.ShouldBe("rate_limited");
            }
        }

        last.ShouldBe(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task Non_members_cannot_see_a_conversation_exists()
    {
        using var alice = await TestPersona.CreateAsync(factory, "priv");
        using var bob = await TestPersona.CreateAsync(factory, "priv");
        using var eve = await TestPersona.CreateAsync(factory, "priv");
        var conversation = await alice.Api.CreateDirectConversationAsync(bob.UserId);

        var ex = await Should.ThrowAsync<VeilApiException>(() => eve.Api.GetConversationAsync(conversation.Id));
        ex.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }
}
