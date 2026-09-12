using Microsoft.AspNetCore.Mvc;
using Veil.Application.Features.Messages;
using Veil.Domain.Common;

namespace Veil.Api.Endpoints;

/// <summary>Maps domain <see cref="Result"/>s onto HTTP responses with RFC 9457 problem details for failures.</summary>
internal static class ResultExtensions
{
    public static IResult ToHttp(this Result result, Func<IResult> onSuccess) =>
        result.IsSuccess ? onSuccess() : Problem(result.Error);

    public static IResult ToHttp<T>(this Result<T> result, Func<T, IResult> onSuccess) =>
        result.IsSuccess ? onSuccess(result.Value) : Problem(result.Error);

    public static IResult ToOk<T>(this Result<T> result) => result.ToHttp(value => Results.Ok(value));

    public static IResult ToNoContent(this Result result) => result.ToHttp(Results.NoContent);

    public static IResult Problem(Error error)
    {
        var status = error.Type switch
        {
            ErrorType.Validation => StatusCodes.Status400BadRequest,
            ErrorType.NotFound => StatusCodes.Status404NotFound,
            ErrorType.Conflict => StatusCodes.Status409Conflict,
            ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
            ErrorType.Forbidden => StatusCodes.Status403Forbidden,
            ErrorType.RateLimited => StatusCodes.Status429TooManyRequests,
            _ => StatusCodes.Status500InternalServerError,
        };

        var extensions = new Dictionary<string, object?> { ["code"] = error.Code };

        switch (error)
        {
            case ValidationError validation:
                extensions["errors"] = validation.Errors
                    .GroupBy(e => e.Code)
                    .ToDictionary(g => g.Key, g => g.Select(e => e.Message).ToArray());
                break;
            case DeviceSetMismatchError mismatch:
                extensions["mismatches"] = mismatch.Mismatches;
                break;
        }

        return Results.Problem(
            statusCode: status,
            title: error.Message,
            type: $"https://veil.dev/errors/{error.Code}",
            extensions: extensions);
    }

    public static ProblemDetails ProblemDetailsFor(Error error) =>
        new()
        {
            Status = StatusCodes.Status400BadRequest,
            Title = error.Message,
            Type = $"https://veil.dev/errors/{error.Code}",
        };
}
