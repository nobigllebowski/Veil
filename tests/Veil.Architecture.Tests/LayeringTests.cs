using System.Reflection;
using NetArchTest.Rules;
using Veil.Application.Abstractions.Messaging;

namespace Veil.Architecture.Tests;

/// <summary>Executable architecture rules: dependency direction and handler conventions.</summary>
public class LayeringTests
{
    private static readonly Assembly Crypto = typeof(Veil.Crypto.ProtocolConstants).Assembly;
    private static readonly Assembly Contracts = typeof(Veil.Contracts.TokenPair).Assembly;
    private static readonly Assembly Domain = typeof(Veil.Domain.Common.Entity).Assembly;
    private static readonly Assembly Application = typeof(Veil.Application.DependencyInjection).Assembly;
    private static readonly Assembly Infrastructure = typeof(Veil.Infrastructure.DependencyInjection).Assembly;
    private static readonly Assembly Api = typeof(Program).Assembly;
    private static readonly Assembly Sdk = typeof(Veil.Client.Sdk.VeilMessenger).Assembly;

    [Fact]
    public void Crypto_is_a_leaf_library()
    {
        var result = Types.InAssembly(Crypto)
            .ShouldNot().HaveDependencyOnAny("Veil.Domain", "Veil.Application", "Veil.Infrastructure", "Veil.Api", "Veil.Contracts", "Microsoft.AspNetCore", "Microsoft.EntityFrameworkCore")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Contracts_have_no_project_dependencies()
    {
        var result = Types.InAssembly(Contracts).ShouldNot().HaveDependencyOnAny("Veil.Crypto", "Veil.Domain", "Veil.Application", "Veil.Infrastructure", "Veil.Api").GetResult();
        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Domain_depends_only_on_crypto()
    {
        var result = Types.InAssembly(Domain)
            .ShouldNot().HaveDependencyOnAny("Veil.Application", "Veil.Infrastructure", "Veil.Api", "Veil.Contracts", "Microsoft.EntityFrameworkCore", "Microsoft.AspNetCore", "Npgsql")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Application_does_not_know_infrastructure_or_the_web_host()
    {
        var result = Types.InAssembly(Application)
            .ShouldNot().HaveDependencyOnAny("Veil.Infrastructure", "Veil.Api", "Microsoft.EntityFrameworkCore", "Microsoft.AspNetCore", "Npgsql", "StackExchange.Redis")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Infrastructure_does_not_depend_on_the_api()
    {
        var result = Types.InAssembly(Infrastructure).ShouldNot().HaveDependencyOn("Veil.Api").GetResult();
        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Client_sdk_never_references_server_layers()
    {
        var result = Types.InAssembly(Sdk)
            .ShouldNot().HaveDependencyOnAny("Veil.Domain", "Veil.Application", "Veil.Infrastructure", "Veil.Api")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Handlers_are_internal_and_sealed()
    {
        var result = Types.InAssembly(Application)
            .That().ImplementInterface(typeof(IRequestHandler<,>)).And().AreClasses()
            .Should().BeSealed().And().NotBePublic()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    [Fact]
    public void Endpoints_and_middleware_in_the_api_are_internal()
    {
        var result = Types.InAssembly(Api)
            .That().ResideInNamespaceStartingWith("Veil.Api.Endpoints").Or().ResideInNamespaceStartingWith("Veil.Api.Middleware")
            .And().AreClasses()
            .Should().NotBePublic()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(Describe(result));
    }

    private static string Describe(NetArchTest.Rules.TestResult result) =>
        result.IsSuccessful ? "ok" : "Violations: " + string.Join(", ", result.FailingTypeNames ?? []);
}
