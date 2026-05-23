using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class RetryHelperTests
{
    [Fact]
    public async Task WithRetryAsync_DoesNotImmediatelyRetryRateLimits()
    {
        var attempts = 0;

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            RetryHelper.WithRetryAsync<string>(
                () =>
                {
                    attempts++;
                    throw new HttpRequestException("rate limited", null, HttpStatusCode.TooManyRequests);
                },
                maxRetries: 3,
                baseDelayMs: 1));

        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task WithRetryAsync_RetriesServerOutages()
    {
        var attempts = 0;

        var result = await RetryHelper.WithRetryAsync(
            () =>
            {
                attempts++;
                if (attempts == 1)
                    throw new HttpRequestException("unavailable", null, HttpStatusCode.ServiceUnavailable);
                return Task.FromResult("ok");
            },
            maxRetries: 3,
            baseDelayMs: 1);

        Assert.Equal("ok", result);
        Assert.Equal(2, attempts);
    }

    [Fact]
    public async Task WithRetryAsync_DoesNotRetryClientAuthorizationFailures()
    {
        var attempts = 0;

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            RetryHelper.WithRetryAsync<string>(
                () =>
                {
                    attempts++;
                    throw new HttpRequestException("forbidden", null, HttpStatusCode.Forbidden);
                },
                maxRetries: 3,
                baseDelayMs: 1));

        Assert.Equal(1, attempts);
    }
}
