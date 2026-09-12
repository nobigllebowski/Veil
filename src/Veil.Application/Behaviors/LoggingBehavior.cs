using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Veil.Application.Abstractions.Messaging;
using Veil.Domain.Common;

namespace Veil.Application.Behaviors;

/// <summary>Structured, PII-free logging and tracing around every request. Logs request type and outcome, never payloads.</summary>
internal sealed class LoggingBehavior<TRequest, TResponse>(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    private static readonly ActivitySource ActivitySource = new("Veil.Application");

    public async Task<TResponse> Handle(TRequest request, Func<Task<TResponse>> next, CancellationToken cancellationToken)
    {
        var name = typeof(TRequest).Name;
        using var activity = ActivitySource.StartActivity(name);
        var started = Stopwatch.GetTimestamp();

        try
        {
            var response = await next();
            var elapsed = Stopwatch.GetElapsedTime(started);

            if (response is Result { IsFailure: true } failed)
            {
                activity?.SetStatus(ActivityStatusCode.Error, failed.Error.Code);
                activity?.SetTag("veil.error_code", failed.Error.Code);
                logger.LogInformation("{Request} failed with {ErrorCode} in {ElapsedMs:F1} ms", name, failed.Error.Code, elapsed.TotalMilliseconds);
            }
            else
            {
                logger.LogDebug("{Request} succeeded in {ElapsedMs:F1} ms", name, elapsed.TotalMilliseconds);
            }

            return response;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.GetType().Name);
            logger.LogError(ex, "{Request} threw {ExceptionType}", name, ex.GetType().Name);
            throw;
        }
    }
}
