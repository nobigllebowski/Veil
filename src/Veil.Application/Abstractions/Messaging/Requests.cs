namespace Veil.Application.Abstractions.Messaging;

/// <summary>Marker for anything dispatched through <see cref="ISender"/>.</summary>
public interface IRequest<TResponse>;

/// <summary>A request that changes state.</summary>
public interface ICommand<TResponse> : IRequest<TResponse>;

/// <summary>A request that only reads state.</summary>
public interface IQuery<TResponse> : IRequest<TResponse>;

public interface IRequestHandler<in TRequest, TResponse> where TRequest : IRequest<TResponse>
{
    Task<TResponse> Handle(TRequest request, CancellationToken cancellationToken);
}

public interface ICommandHandler<in TCommand, TResponse> : IRequestHandler<TCommand, TResponse> where TCommand : ICommand<TResponse>;

public interface IQueryHandler<in TQuery, TResponse> : IRequestHandler<TQuery, TResponse> where TQuery : IQuery<TResponse>;

/// <summary>Cross-cutting step wrapped around every handler (validation, logging, metrics...).</summary>
public interface IPipelineBehavior<in TRequest, TResponse> where TRequest : IRequest<TResponse>
{
    Task<TResponse> Handle(TRequest request, Func<Task<TResponse>> next, CancellationToken cancellationToken);
}

public interface ISender
{
    Task<TResponse> Send<TResponse>(IRequest<TResponse> request, CancellationToken cancellationToken = default);
}
