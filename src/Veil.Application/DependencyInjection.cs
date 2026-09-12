using System.Reflection;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Veil.Application.Abstractions.Events;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Behaviors;
using Veil.Application.Features.Auth;
using Veil.Application.Features.Conversations;

namespace Veil.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddVeilApplication(this IServiceCollection services)
    {
        var assembly = typeof(DependencyInjection).Assembly;

        services.AddScoped<ISender, Sender>();
        services.AddScoped<TokenIssuance>();
        services.AddScoped<ConversationSummaries>();
        services.AddScoped(typeof(IPipelineBehavior<,>), typeof(LoggingBehavior<,>));
        services.AddScoped(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
        services.AddValidatorsFromAssembly(assembly, includeInternalTypes: true);

        RegisterImplementations(services, assembly, typeof(IRequestHandler<,>));
        RegisterImplementations(services, assembly, typeof(IDomainEventHandler<>));

        return services;
    }

    private static void RegisterImplementations(IServiceCollection services, Assembly assembly, Type openInterface)
    {
        var registrations =
            from type in assembly.GetTypes()
            where type is { IsAbstract: false, IsInterface: false, IsGenericTypeDefinition: false }
            from contract in type.GetInterfaces()
            where contract.IsGenericType && contract.GetGenericTypeDefinition() == openInterface
            select (contract, type);

        foreach (var (contract, implementation) in registrations)
        {
            services.AddScoped(contract, implementation);
        }
    }
}
