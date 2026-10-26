using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Unit/support checks for the install-time health rollback seams that run without the SYSTEM service or the MSI.</summary>
public sealed class AgentUpdateRollbackPolicyTests
{
    private static readonly DateTimeOffset Started = DateTimeOffset.Parse("2026-10-26T10:00:00Z");

    [Theory]
    [InlineData(true, AgentLifecycleState.Active, true)]
    [InlineData(false, AgentLifecycleState.Active, false)]
    [InlineData(true, AgentLifecycleState.Degraded, false)]
    [InlineData(true, AgentLifecycleState.AuthSuspect, false)]
    [InlineData(true, AgentLifecycleState.BlockedConfig, false)]
    [InlineData(true, AgentLifecycleState.NeedsReenrollment, false)]
    [InlineData(true, AgentLifecycleState.Retired, false)]
    [InlineData(false, AgentLifecycleState.Degraded, false)]
    public void RequiresBackendContact_OnlyForAutomaticFromActive(bool automatic, AgentLifecycleState state, bool expected)
        => Assert.Equal(expected, AgentUpdateRollbackPolicy.RequiresBackendContact(automatic, state));

    [Fact]
    public void IsCurrentAttemptRecord_WithoutInstallerStartIsNeverCurrent()
        => Assert.False(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started, null));

    [Fact]
    public void IsCurrentAttemptRecord_IncludesTheStartInstantAndExcludesOneTickBefore()
    {
        Assert.True(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started, Started));
        Assert.True(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started.AddTicks(1), Started));
        Assert.False(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started.AddTicks(-1), Started));
    }

    [Theory]
    [InlineData(7L, "msi_failed", 9L, true, 9L)]
    [InlineData(7L, "msi_failed", 5L, true, 7L)]
    [InlineData(7L, "msi_failed", 7L, true, 7L)]
    [InlineData(0L, "msi_failed", 5L, true, 5L)]
    [InlineData(7L, "msi_failed", 9L, false, 7L)]
    [InlineData(7L, "download_failed", 9L, true, 7L)]
    [InlineData(7L, null, 9L, true, 7L)]
    [InlineData(0L, "msi_failed", 9L, false, 0L)]
    public void NextFailedInstallSequence_PinsOnlyARecordedMsiRollbackAndNeverLowers(
        long previous, string? errorCode, long plan, bool rollbackRecorded, long expected)
        => Assert.Equal(expected, AgentUpdateRollbackPolicy.NextFailedInstallSequence(previous, errorCode, plan, rollbackRecorded));

    [Theory]
    [InlineData(false, 5L, null)]
    [InlineData(true, 0L, null)]
    [InlineData(true, 5L, 5L)]
    [InlineData(true, 1L, 1L)]
    public void SkipSequenceFor_OnlyAutomaticWithAPinnedSequence(bool automatic, long failed, long? expected)
        => Assert.Equal(expected, AgentUpdateRollbackPolicy.SkipSequenceFor(automatic, failed));

    [Theory]
    [InlineData(null, true, 3L, false)]
    [InlineData(0L, true, 3L, false)]
    [InlineData(5L, false, 3L, false)]
    [InlineData(5L, false, 5L, false)]
    [InlineData(5L, true, 4L, true)]
    [InlineData(5L, true, 5L, true)]
    [InlineData(5L, true, 6L, false)]
    public void SkipsSequence_StopsExactlyAtTheFailedSequence(long? skip, bool isV2, long sequence, bool expected)
        => Assert.Equal(expected, AgentUpdateRollbackPolicy.SkipsSequence(skip, isV2, sequence));

    [Fact]
    public void LocalControl_ReadinessIsAllowedForUnprivilegedCallersLikeStatus()
    {
        Assert.True(AgentLocalControlProtocol.IsAllowed(new("status"), false));
        Assert.True(AgentLocalControlProtocol.IsAllowed(new("readiness"), false));
        Assert.True(AgentLocalControlProtocol.IsAllowed(new("readiness"), true));
        Assert.False(AgentLocalControlProtocol.IsAllowed(new("readiness", Guid.NewGuid().ToString("N")), false));
    }

    [Fact]
    public async Task LocalControl_ResponseWithoutBackendContactOmitsTheField()
    {
        using var stream = new MemoryStream();
        await AgentLocalControlProtocol.WriteAsync(stream, new AgentLocalControlResponse(true, "ok", "Active"), default);

        using var document = JsonDocument.Parse(FramePayload(stream));
        Assert.False(document.RootElement.TryGetProperty("lastBackendContactUtc", out _));
        Assert.True(document.RootElement.TryGetProperty("code", out _));

        // The reader rejects unmapped members, so a response without the field must stay readable by the same options.
        stream.Position = 0;
        var read = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(stream, default);
        Assert.Null(read.LastBackendContactUtc);
    }

    [Fact]
    public async Task LocalControl_ResponseWithBackendContactRoundTripsTheValue()
    {
        var contact = new DateTimeOffset(2026, 10, 26, 10, 0, 5, TimeSpan.Zero).AddTicks(1234);
        using var stream = new MemoryStream();
        await AgentLocalControlProtocol.WriteAsync(stream, new AgentLocalControlResponse(true, "ok", LastBackendContactUtc: contact), default);

        using (var document = JsonDocument.Parse(FramePayload(stream)))
            Assert.True(document.RootElement.TryGetProperty("lastBackendContactUtc", out _));

        stream.Position = 0;
        var read = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(stream, default);
        Assert.Equal(contact, read.LastBackendContactUtc);
    }

    [Fact]
    public void BackendContact_MarkSuccessRecordsTheCurrentTime()
    {
        var before = DateTimeOffset.UtcNow;
        AgentBackendContact.MarkSuccess();
        var after = DateTimeOffset.UtcNow;

        var recorded = Assert.NotNull(AgentBackendContact.LastSuccessUtc);
        Assert.InRange(recorded, before.AddSeconds(-1), after.AddSeconds(1));
        Assert.Equal(TimeSpan.Zero, recorded.Offset);
    }

    [Fact]
    public void Journal_FailedInstallSequenceSurvivesAWriteReadRoundTrip()
    {
        var root = NewRoot();
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, new AgentUpdateJournal { FailedInstallSequence = 42 });
        Assert.Equal(42, new AgentUpdateJournalStore(root).Read().FailedInstallSequence);
    }

    [Fact]
    public void Journal_WithoutTheFieldReadsAsZero()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { FailedInstallSequence = 42 });
        var node = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        Assert.True(node.Remove("failedInstallSequence"));
        File.WriteAllText(path, node.ToJsonString());

        Assert.Equal(0, new AgentUpdateJournalStore(root).Read().FailedInstallSequence);
    }

    [Fact]
    public void Journal_NegativeFailedInstallSequenceIsInvalidAndPreserved()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { FailedInstallSequence = -1 });
        var before = File.ReadAllBytes(path);

        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    private static byte[] FramePayload(MemoryStream stream)
    {
        var bytes = stream.ToArray();
        Assert.Equal(bytes.Length - 4, BitConverter.ToInt32(bytes, 0));
        return bytes[4..];
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-rollback-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
