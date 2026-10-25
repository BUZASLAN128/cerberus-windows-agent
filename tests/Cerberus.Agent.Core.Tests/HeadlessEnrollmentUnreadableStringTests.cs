using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>JSON strings that parse but cannot be read (lone surrogates) never crash the enroll run.</summary>
public sealed class HeadlessEnrollmentUnreadableStringTests
{
    private const string BadCodeBody = "{\"detail\":{\"code\":\"\\ud800\"}}";

    [Fact]
    public async Task Error_body_with_unreadable_detail_code_400_exits_three()
    {
        var handler = new HeadlessEnrollmentTests.FakeHandler().Reply(400, BadCodeBody);
        var store = new HeadlessEnrollmentTests.MemoryStore();

        var result = await Run(handler, store, HeadlessEnrollmentTests.Proof());

        Assert.Equal(HeadlessEnrollmentExit.Rejected, result.ExitCode);
        Assert.Single(handler.Requests);
        Assert.Equal(0, store.SaveCount);
    }

    [Fact]
    public async Task Error_body_with_unreadable_detail_code_503_is_retried_like_any_503()
    {
        var handler = new HeadlessEnrollmentTests.FakeHandler().Reply(503, BadCodeBody).Reply(503, BadCodeBody).Reply(503, BadCodeBody);
        var store = new HeadlessEnrollmentTests.MemoryStore();

        var result = await Run(handler, store, HeadlessEnrollmentTests.Proof());

        Assert.Equal(HeadlessEnrollmentExit.Unavailable, result.ExitCode);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal(0, store.SaveCount);
    }

    [Fact]
    public async Task Proof_with_unreadable_agent_id_claim_exits_two_without_a_request()
    {
        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var proof = B64("{\"alg\":\"HS256\"}") + "." + B64("{\"agent_id\":\"\\ud800\",\"sub\":\"x\"}") + ".c2lnbmF0dXJl";
        var handler = new HeadlessEnrollmentTests.FakeHandler();
        var store = new HeadlessEnrollmentTests.MemoryStore();

        var result = await Run(handler, store, proof);

        Assert.Equal(HeadlessEnrollmentExit.BadInput, result.ExitCode);
        Assert.Equal("proof_invalid", result.Code);
        Assert.Empty(handler.Requests);
        Assert.Null(store.Saved);
    }

    private static Task<HeadlessEnrollmentResult> Run(HeadlessEnrollmentTests.FakeHandler handler, HeadlessEnrollmentTests.MemoryStore store, string proof)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.example") };
        return new HeadlessEnrollment(http, time: new HeadlessEnrollmentTests.ImmediateTimeProvider())
            .RunAsync(proof, HeadlessEnrollmentTests.Options(), new AgentLifecycleSnapshot(), false, store, CancellationToken.None);
    }
}
