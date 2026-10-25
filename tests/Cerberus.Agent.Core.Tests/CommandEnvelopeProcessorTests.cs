using System.Net;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Envelope inline phase against an ephemeral key, a recording backend and a fake clock.
/// Unit/support tier: the order table, replay states and the byte-identical ack/result contract.
/// </summary>
public sealed partial class CommandEnvelopeProcessorTests
{
    private const long T0 = EnvelopeHarness.T0;
    private static readonly Lazy<TestSigner> OtherSigner = new(() => new TestSigner(2048));

    private static readonly Dictionary<string, (Action<EnvelopeParts> Edit, string Code, bool Ack)> RejectRows = new()
    {
        ["2_malformed_version"] = (p => p.WireVersion = 2, "envelope_malformed", false),
        ["2_malformed_base64"] = (p => p.WireSignedBytesB64 = "@@@@", "envelope_malformed", false),
        ["3_outer_delegation"] = (p => p.WireDelegation = "x", "delegation_unsupported", false),
        ["5_key_unknown"] = (p => p.WireKeyId = "ffffffffffffffff", "key_unknown", false),
        ["6_signature_invalid"] = (p => p.SignWith = OtherSigner.Value, "signature_invalid", false),
        ["7_malformed_signed_nonce"] = (p => p.Nonce = "a:b", "envelope_malformed", false),
        ["8_agent_mismatch"] = (p => p.AgentId = "agent-other", "agent_mismatch", false),
        ["9_outer_mismatch"] = (p => p.OuterType = "collect_facts", "envelope_mismatch", true),
        ["10_signed_delegation"] = (p => p.Delegation = "abc", "delegation_unsupported", true),
        ["11_type_not_allowed"] = (p => p.Type = "run_script", "type_not_allowed", true),
        ["12_payload_invalid"] = (p => p.PayloadJson = "{\"x\":1}", "payload_invalid", true),
        ["14_ttl_invalid"] = (p => p.Expires = p.Issued + 301, "ttl_invalid", true),
        ["14_not_yet_valid"] = (p => { p.Issued = T0 + 61; p.Expires = p.Issued + 120; }, "not_yet_valid", true),
        ["14_expired"] = (p => { p.Issued = T0 - 400; p.Expires = T0 - 100; }, "expired", true),
    };

    public static IEnumerable<object[]> RejectRowNames() => RejectRows.Keys.Select(k => new object[] { k });

    [Fact]
    public async Task AcceptedCommand_LogsAcceptedAndFinishedWithoutArgumentsOrOutput()
    {
        await using var h = EnvelopeHarness.Create();
        h.Facts.Body = (_, _) => Task.FromResult(new CommandResult("DONE", 0, "STDOUT-SECRET", "STDERR-SECRET", new { v = "BODY-SECRET" }));
        var cmd = h.Cmd(p => { p.Type = "collect_facts"; p.PayloadJson = "{\"sections\":[\"identity\"]}"; });

        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Record(cmd)?.ResultSubmitted == true, "result submitted");

        var accepted = Assert.Single(h.Log.Lines, l => l.Contains("Command accepted"));
        var finished = Assert.Single(h.Log.Lines, l => l.Contains("Command finished"));
        Assert.Equal($"INFO Command accepted id={cmd.Id} type=collect_facts", accepted);
        Assert.Matches($@"^INFO Command finished id={cmd.Id} type=collect_facts status=DONE duration_ms=\d+$", finished);
        foreach (var line in new[] { accepted, finished })
        {
            Assert.DoesNotContain("identity", line);
            Assert.DoesNotContain("SECRET", line);
        }
    }

    [Theory]
    [MemberData(nameof(RejectRowNames))]
    public async Task OrderTable_RowRejectsWithItsCodeAndNothingRuns(string row)
    {
        var (edit, code, ack) = RejectRows[row];
        await using var h = EnvelopeHarness.Create();
        var cmd = h.Cmd(edit);

        await h.Process(cmd);

        Assert.Equal(1, h.Rejections(code));
        Assert.Equal(0, h.Ping.Calls + h.Facts.Calls + h.State.Calls);
        Assert.Empty(h.Store.Records(h.AgentId));
        if (!ack)
        {
            Assert.Empty(h.Backend.Requests);
            return;
        }

        var sent = Assert.Single(h.Backend.Acks);
        Assert.Equal(CommandEnvelope.BuildAckBody(EnvelopeHarness.ShaOf(cmd), accepted: false, code), sent.Body);
        Assert.Empty(h.Backend.Results);
    }

    [Fact]
    public async Task AcceptedPing_AcksFirstThenSubmitsTheStoredResultBytes()
    {
        await using var h = EnvelopeHarness.Create();
        var cmd = h.Cmd();
        var sha = EnvelopeHarness.ShaOf(cmd);

        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Record(cmd)?.ResultSubmitted == true, "result submitted");

        Assert.Equal("ack", h.Backend.Requests[0].Leaf);
        Assert.Equal(CommandEnvelope.BuildAckBody(sha, accepted: true, null), h.Backend.Requests[0].Body);
        Assert.Equal($"/api/v1/agents/{h.AgentId}/commands/{cmd.Id}/ack", h.Backend.Requests[0].Path);
        var result = Assert.Single(h.Backend.Results);
        Assert.Equal("DONE", result.Json.GetProperty("status").GetString());
        Assert.Equal(sha, result.Json.GetProperty("envelope_sha256").GetString());
        var record = h.Record(cmd)!;
        Assert.Equal(EnvelopeRecordStates.Done, record.State);
        Assert.Equal(result.Body, Convert.FromBase64String(record.ResultB64!));
        Assert.Equal(CommandEnvelope.Sha256Hex(result.Body), record.ResultSha256);
        Assert.Equal(1, h.Ping.Calls);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public async Task Rsa2048And3072Anchors_AcceptASignedPing(int bits)
    {
        var signer = new TestSigner(bits);
        await using var h = EnvelopeHarness.Create(o => o.Anchors = new[] { signer.Anchor });
        h.Signer = signer;

        await h.Process(h.Cmd());

        Assert.Equal("accepted", h.Backend.Acks.Single().Json.GetProperty("decision").GetString());
        Assert.Equal(0, h.Rejections("signature_invalid") + h.Rejections("key_unknown") + h.Rejections("no_trust_anchor"));
    }

    [Fact]
    public async Task SubTwoThousandBitAnchor_IsNeverTrusted()
    {
        var weak = new TestSigner(1024);
        var strong = TestSigner.Default;

        await using (var alone = EnvelopeHarness.Create(o => o.Anchors = new[] { weak.Anchor }))
        {
            alone.Signer = weak;
            await alone.Process(alone.Cmd());
            Assert.Equal(1, alone.Rejections("no_trust_anchor"));
            Assert.Empty(alone.Backend.Requests);
        }

        await using var beside = EnvelopeHarness.Create(o => o.Anchors = new[] { strong.Anchor, weak.Anchor });
        beside.Signer = weak;
        await beside.Process(beside.Cmd());
        Assert.Equal(1, beside.Rejections("key_unknown"));
        Assert.Equal(0, beside.Ping.Calls);
        Assert.Empty(beside.Backend.Requests);
    }

    [Fact]
    public async Task ZeroAnchors_RejectsAnEnvelopeAndNeverFallsBackToTheUnsignedCopy()
    {
        var legacy = new CountingProcessor();
        await using var h = EnvelopeHarness.Create(o => { o.Anchors = Array.Empty<CommandTrustAnchor>(); o.Legacy = legacy; });

        await h.Process(h.Cmd());

        Assert.Equal(1, h.Rejections("no_trust_anchor"));
        Assert.Equal(0, legacy.Calls);
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Requests);
    }

    [Fact]
    public async Task EntryWithoutEnvelope_NeverReachesAnEnvelopeHandler()
    {
        var legacy = new CountingProcessor();
        await using var h = EnvelopeHarness.Create(o => o.Legacy = legacy);
        var unsigned = new AgentCommand("u-1", "ping", "u-1", new { });

        await h.Process(unsigned);

        Assert.Equal(0, h.Ping.Calls + h.Facts.Calls + h.State.Calls);
        Assert.Empty(h.Backend.Requests);
#if CERBERUS_SERVER_PROFILE
        Assert.Equal(1, h.Rejections("unsigned"));
        Assert.Equal(0, legacy.Calls);
#else
        Assert.Equal(0, h.Rejections("unsigned"));
        Assert.Equal(1, legacy.Calls);
#endif
    }

#if !CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task Desktop_EntryWithoutEnvelope_GivesByteIdenticalLegacyAckAndResultCalls()
    {
        var command = new AgentCommand("legacy-1", "echo", "legacy-1", new { value = 1 });
        LegacyHeartbeatCommandProcessor NewLegacy(AgentApiClient api)
            => new(api, new CommandDispatcher(new[] { new FakeCommandHandler("echo") },
                new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"),
                    10, TimeSpan.FromMinutes(5))), TimeSpan.FromSeconds(5), 1);

        await using var direct = EnvelopeHarness.Create();
        await NewLegacy(direct.Api).ProcessAsync(new[] { command }, CancellationToken.None);
        await using var wrapped = EnvelopeHarness.Create(o => o.LegacyFactory = NewLegacy);
        await wrapped.Process(command);

        static List<(string Path, string Body)> Calls(EnvelopeHarness h)
            => h.Backend.Requests.Select(r => (r.Path, Convert.ToBase64String(r.Body))).ToList();
        Assert.NotEmpty(Calls(direct));
        Assert.Equal(Calls(direct), Calls(wrapped));
        Assert.Equal(0, wrapped.Rejections("unsigned"));
    }
#endif

    [Fact]
    public async Task CorruptStore_RejectsEnvelopesIssuedBeforeTheResetOnly()
    {
        await using var h = EnvelopeHarness.Create(o => o.CorruptStoreContent = "{not json");
        var before = h.Cmd(p => { p.Issued = T0 - 30; p.Expires = T0 + 90; });
        var after = h.Cmd();

        await h.Process(before, after);

        Assert.Equal(T0, h.Store.ResetAt);
        Assert.Equal(1, h.Rejections("issued_before_reset"));
        Assert.Null(h.Record(before));
        Assert.NotNull(h.Record(after));
        Assert.Contains(Directory.GetFiles(Path.GetDirectoryName(h.StorePath)!), f => f.Contains(".corrupt-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReusedNonce_IsRejectedForAnotherIdAndStoresNothing()
    {
        await using var h = EnvelopeHarness.Create();
        var first = h.Cmd(p => p.Nonce = "shared");
        var second = h.Cmd(p => p.Nonce = "shared");

        await h.Process(first);
        await h.Process(second);

        Assert.Equal(1, h.Rejections("nonce_reused"));
        Assert.Null(h.Record(second));
        Assert.Equal("rejected", h.Backend.Acks.Last().Json.GetProperty("decision").GetString());
        await Wait.UntilAsync(() => h.Ping.Calls == 1, "first ping run");
    }

    [Fact]
    public async Task FullStoreOfLiveRecords_RejectsWithReplayStoreFull()
    {
        var path = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), CommandReplayStore.FileName);
        StoreFileWriter.Write(path, 0, Enumerable.Range(0, CommandReplayStore.MaxRecords).Select(i =>
            StoreFileWriter.Record(EnvelopeHarness.DefaultAgent, $"00000000-0000-4000-9000-{i:D12}", $"live-{i}",
                expiresAt: T0 + 120, issuedAt: T0)));
        await using var h = EnvelopeHarness.Create(o => o.StorePath = path);
        var cmd = h.Cmd();

        await h.Process(cmd);

        Assert.Equal(1, h.Rejections("replay_store_full"));
        Assert.Equal("replay_store_full", h.Backend.Acks.Single().Json.GetProperty("reason").GetString());
        Assert.Equal(0, h.Ping.Calls);
    }

    [Fact]
    public async Task UnwritableStore_RejectsWithReplayStoreUnavailableAndRunsNothing()
    {
        var blocker = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N") + ".file");
        Directory.CreateDirectory(Path.GetDirectoryName(blocker)!);
        await File.WriteAllTextAsync(blocker, "x");
        await using var h = EnvelopeHarness.Create(o => o.StorePath = Path.Combine(blocker, CommandReplayStore.FileName));

        await h.Process(h.Cmd());

        Assert.Equal(1, h.Rejections("replay_store_unavailable"));
        Assert.Equal("rejected", h.Backend.Acks.Single().Json.GetProperty("decision").GetString());
        Assert.Equal(0, h.Ping.Calls);
        File.Delete(blocker);
    }

    [Fact]
    public async Task AgentState_RunsInlineFirstAndQuarantineRejectsALaterQueuedType()
    {
        await using var h = EnvelopeHarness.Create();
        h.State.Body = (_, _) =>
        {
            h.Quarantined = true;
            return Task.FromResult(FakeCommandHandler.Done());
        };
        var facts = h.Cmd(p => p.Type = "collect_facts");
        var state = h.Cmd(p => { p.Type = "agent_state"; p.PayloadJson = "{\"state_seq\":1,\"quarantine\":{\"active\":true}}"; });
        var ping = h.Cmd();

        await h.Process(facts, ping, state);

        Assert.Equal(1, h.State.Calls);
        Assert.Equal(state.Id, h.Backend.Acks[0].CommandId);
        Assert.Equal("accepted", h.Backend.Acks[0].Json.GetProperty("decision").GetString());
        var rejected = h.Backend.Acks.Single(a => a.CommandId == facts.Id);
        Assert.Equal("quarantined", rejected.Json.GetProperty("reason").GetString());
        Assert.Equal(0, h.Facts.Calls);
        Assert.Equal("accepted", h.Backend.Acks.Single(a => a.CommandId == ping.Id).Json.GetProperty("decision").GetString());
    }

    [Fact]
    public async Task QuarantineAppliedAfterTheAck_FailsAQueuedEntryBeforeItStarts()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var facts = h.Cmd(p => p.Type = "collect_facts");
        await h.Process(facts);
        h.Quarantined = true;

        h.Queue.Start();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "result");

        var result = h.Backend.Results.Single().Json;
        Assert.Equal("FAILED", result.GetProperty("status").GetString());
        Assert.Equal("quarantined", result.GetProperty("stderr").GetString());
        Assert.Equal(0, h.Facts.Calls);
    }

    [Fact]
    public async Task RebindToAnotherAgent_KeepsRecordsApartAndReadsTheIdPerCall()
    {
        await using var h = EnvelopeHarness.Create();
        var forA = h.Cmd(p => { p.Id = "00000000-0000-4000-8000-0000000000aa"; p.Nonce = "n-shared"; });
        await h.Process(forA);
        await Wait.UntilAsync(() => h.Record(forA)?.ResultSubmitted == true, "agent A result");

        h.AgentId = "agent-0002";
        await h.Process(forA);
        Assert.Equal(1, h.Rejections("agent_mismatch"));

        var forB = h.Cmd(p => { p.Id = "00000000-0000-4000-8000-0000000000aa"; p.Nonce = "n-shared"; });
        await h.Process(forB);
        await Wait.UntilAsync(() => h.Record(forB)?.ResultSubmitted == true, "agent B result");

        Assert.Equal(0, h.Rejections("id_conflict") + h.Rejections("nonce_reused"));
        Assert.Equal(2, h.Ping.Calls);
        Assert.Contains(h.Backend.Acks, a => a.Path.StartsWith("/api/v1/agents/agent-0002/", StringComparison.Ordinal));
        Assert.NotNull(h.Store.Find("agent-0001", forA.Id));
    }

    private sealed class CountingProcessor : IHeartbeatCommandProcessor
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
        {
            Interlocked.Increment(ref _calls);
            return Task.CompletedTask;
        }
    }
}
