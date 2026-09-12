using FluentValidation;
using Veil.Application.Abstractions.Messaging;
using Veil.Domain.Common;

namespace Veil.Application.Behaviors;

/// <summary>Runs every FluentValidation validator for the request and short-circuits with a <see cref="ValidationError"/>.</summary>
internal sealed class ValidationBehavior<TRequest, TResponse>(IEnumerable<IValidator<TRequest>> validators)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    public async Task<TResponse> Handle(TRequest request, Func<Task<TResponse>> next, CancellationToken cancellationToken)
    {
        var validatorList = validators.ToList();
        if (validatorList.Count == 0)
        {
            return await next();
        }

        var context = new ValidationContext<TRequest>(request);
        var results = await Task.WhenAll(validatorList.Select(v => v.ValidateAsync(context, cancellationToken)));
        var failures = results.SelectMany(r => r.Errors).Where(f => f is not null).ToList();
        if (failures.Count == 0)
        {
            return await next();
        }

        var error = new ValidationError(failures
            .Select(f => Error.Validation(ToSnakeCase(f.PropertyName), f.ErrorMessage))
            .Distinct()
            .ToList());

        return ResultFactory.Failure<TResponse>(error);
    }

    private static string ToSnakeCase(string value) =>
        string.IsNullOrEmpty(value)
            ? "request"
            : string.Concat(value.Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
}

internal static class ResultFactory
{
    /// <summary>Builds a failed <see cref="Result"/> / <see cref="Result{T}"/> of the requested response type.</summary>
    public static TResponse Failure<TResponse>(Error error)
    {
        var responseType = typeof(TResponse);
        if (responseType == typeof(Result))
        {
            return (TResponse)(object)Result.Failure(error);
        }

        if (responseType.IsGenericType && responseType.GetGenericTypeDefinition() == typeof(Result<>))
        {
            var method = typeof(Result)
                .GetMethod(nameof(Result.Failure), 1, [typeof(Error)])!
                .MakeGenericMethod(responseType.GetGenericArguments()[0]);
            return (TResponse)method.Invoke(null, [error])!;
        }

        throw new ValidationException(error.Message);
    }
}
