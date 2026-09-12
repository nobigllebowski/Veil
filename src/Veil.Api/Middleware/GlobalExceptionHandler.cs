using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Veil.Api.Middleware;

/// <summary>Turns unhandled exceptions into RFC 9457 problem details without leaking internals.</summary>
internal sealed class GlobalExceptionHandler(IProblemDetailsService problemDetails, ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var (status, title, code) = exception switch
        {
            OperationCanceledException => (StatusCodes.Status499ClientClosedRequest, "Request was cancelled.", "request.cancelled"),
            DbUpdateConcurrencyException => (StatusCodes.Status409Conflict, "The resource was modified concurrently. Retry the request.", "concurrency.conflict"),
            DbUpdateException => (StatusCodes.Status409Conflict, "The request conflicts with existing data.", "persistence.conflict"),
            BadHttpRequestException bad => (bad.StatusCode, "The request is malformed.", "request.malformed"),
            _ => (StatusCodes.Status500InternalServerError, "An unexpected error occurred.", "internal.error"),
        };

        if (status >= 500)
        {
            logger.LogError(exception, "Unhandled exception for {Method} {Path}", httpContext.Request.Method, httpContext.Request.Path);
        }

        httpContext.Response.StatusCode = status;
        var problem = new ProblemDetails
        {
            Status = status,
            Title = title,
            Type = $"https://veil.dev/errors/{code}",
            Instance = httpContext.Request.Path,
        };
        problem.Extensions["code"] = code;

        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problem,
            Exception = exception,
        });
    }
}
