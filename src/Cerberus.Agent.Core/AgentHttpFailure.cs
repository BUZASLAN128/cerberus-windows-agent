using System.Net.Http;

namespace Cerberus.Agent.Core;

internal static class AgentHttpFailure
{
    public static HttpRequestException Create(string operation, HttpResponseMessage response)
        => new(
            $"{operation} failed ({(int)response.StatusCode}).",
            inner: null,
            statusCode: response.StatusCode);
}
