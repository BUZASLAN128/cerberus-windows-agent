using System.Net;
using System.Reflection;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Key validation before the request, adopt probe failure classification and the --enroll-rollback switch.
public sealed class EnrollHeadlessSupportTests
{
    [Fact]
    public async Task Key_that_cannot_be_fingerprinted_fails_before_the_proof_is_sent()
    {
        var handler = new HeadlessEnrollmentTests.FakeHandler();
        var store = new HeadlessEnrollmentTests.MemoryStore();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.example") };

        var result = await new HeadlessEnrollment(http, new BrokenKeys())
            .RunAsync(HeadlessEnrollmentTests.Proof(), HeadlessEnrollmentTests.Options(), new AgentLifecycleSnapshot(), false, store, default);

        Assert.Equal(HeadlessEnrollmentExit.BadInput, result.ExitCode);
        Assert.Equal("key_invalid", result.Code);
        Assert.Empty(handler.Requests);
        Assert.Equal(0, store.SaveCount);
    }

    // The probe refreshes the staged token and the backend may rotate it: only a request that provably never reached
    // the server (DNS, connect) may be sent again.
    [Theory]
    [InlineData(HttpRequestError.NameResolutionError, null, true)]
    [InlineData(HttpRequestError.ConnectionError, null, true)]
    [InlineData(HttpRequestError.ConnectionError, 503, false)]
    [InlineData(HttpRequestError.Unknown, null, false)]
    [InlineData(HttpRequestError.SecureConnectionError, null, false)]
    [InlineData(HttpRequestError.ResponseEnded, null, false)]
    [InlineData(HttpRequestError.Unknown, 408, false)]
    [InlineData(HttpRequestError.Unknown, 429, false)]
    [InlineData(HttpRequestError.Unknown, 500, false)]
    [InlineData(HttpRequestError.Unknown, 503, false)]
    [InlineData(HttpRequestError.Unknown, 400, false)]
    [InlineData(HttpRequestError.Unknown, 401, false)]
    [InlineData(HttpRequestError.Unknown, 403, false)]
    [InlineData(HttpRequestError.Unknown, 404, false)]
    public void Adopt_probe_is_retried_only_when_the_request_never_reached_the_server(HttpRequestError error, int? status, bool transient)
    {
        var ex = new HttpRequestException(error, "probe", null, status is { } s ? (HttpStatusCode)s : null);

        Assert.Equal(transient, IsTransientProbeFailure(ex, default));
    }

    [Fact]
    public void Adopt_probe_timeout_cancellation_and_other_errors_are_not_retried()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.False(IsTransientProbeFailure(new TaskCanceledException("http timeout"), default));
        Assert.False(IsTransientProbeFailure(new TimeoutException("probe"), default));
        Assert.False(IsTransientProbeFailure(new OperationCanceledException(cancelled.Token), cancelled.Token));
        Assert.False(IsTransientProbeFailure(new InvalidDataException("endpoint"), default));
    }

    [Fact]
    public void Enroll_rollback_switch_is_parsed_and_off_by_default()
    {
        Assert.True(Args.Parse(["--enroll-rollback"]).EnrollRollback);
        Assert.False(Args.Parse(["--enroll-headless", "--proof-stdin"]).EnrollRollback);
        Assert.False(Args.Parse([]).EnrollRollback);
    }

    private static bool IsTransientProbeFailure(Exception ex, CancellationToken ct)
    {
        var method = typeof(AgentLocalControlService).GetMethod("IsTransientProbeFailure", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (bool)method.Invoke(null, [ex, ct])!;
    }

    private sealed class BrokenKeys : IKeyPairGenerator
    {
        public (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize) => ("not a key", "not a key");
    }
}
