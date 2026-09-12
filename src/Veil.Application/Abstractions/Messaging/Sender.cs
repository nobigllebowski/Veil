using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;

namespace Veil.Application.Abstractions.Messaging;

/// <summary>
/// Minimal in-process dispatcher: resolves the handler for the request's runtime type and wraps it with the
/// registered <see cref="IPipelineBehavior{TRequest,TResponse}"/>s (first registered = outermost).
/// </summary>
internal sealed class Sender(IServiceProvider provider) : ISender
{
    private static readonly ConcurrentDictionary<Type, RequestHandlerBase> Wrappers = new();

    public Task<TResponse> Send<TResponse>(IRequest<TResponse> request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var wrapper = (RequestHandlerWrapper<TResponse>)Wrappers.GetOrAdd(
            request.GetType(),
            static requestType => (RequestHandlerBase)Activator.CreateInstance(
                typeof(RequestHandlerWrapperImpl<,>).MakeGenericType(requestType, typeof(TResponse)))!);

        return wrapper.Handle(request, provider, cancellationToken);
    }

    private abstract class RequestHandlerBase;

    private abstract class RequestHandlerWrapper<TResponse> : RequestHandlerBase
    {
        public abstract Task<TResponse> Handle(IRequest<TResponse> request, IServiceProvider provider, CancellationToken cancellationToken);
    }

    private sealed class RequestHandlerWrapperImpl<TRequest, TResponse> : RequestHandlerWrapper<TResponse>
        where TRequest : IRequest<TResponse>
    {
        public override Task<TResponse> Handle(IRequest<TResponse> request, IServiceProvider provider, CancellationToken cancellationToken)
        {
            var typed = (TRequest)request;
            var handler = provider.GetRequiredService<IRequestHandler<TRequest, TResponse>>();

            Func<Task<TResponse>> pipeline = () => handler.Handle(typed, cancellationToken);
            foreach (var behavior in provider.GetServices<IPipelineBehavior<TRequest, TResponse>>().Reverse())
            {
                var next = pipeline;
                pipeline = () => behavior.Handle(typed, next, cancellationToken);
            }

            return pipeline();
        }
    }
}
