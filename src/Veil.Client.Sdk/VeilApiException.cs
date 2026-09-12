using System.Net;
using Veil.Contracts;

namespace Veil.Client.Sdk;

/// <summary>Raised for any non-success HTTP response; carries the server's problem details.</summary>
public sealed class VeilApiException : Exception
{
    public VeilApiException(HttpStatusCode statusCode, ApiProblem? problem)
        : base(problem?.Title ?? $"Request failed with status {(int)statusCode}.")
    {
        StatusCode = statusCode;
        Problem = problem;
    }

    public VeilApiException() { }
    public VeilApiException(string message) : base(message) { }
    public VeilApiException(string message, Exception innerException) : base(message, innerException) { }

    public HttpStatusCode StatusCode { get; }
    public ApiProblem? Problem { get; }
    public string? Code => Problem?.Code;
    public bool IsDeviceSetMismatch => Code == "message.device_set_mismatch";
}
