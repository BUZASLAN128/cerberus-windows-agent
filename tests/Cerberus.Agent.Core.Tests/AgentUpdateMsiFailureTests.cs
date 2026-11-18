using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateMsiFailureTests
{
    private const int FatalMsiExit = 1603;
    private const string Note1310 = "MSI (s) (AB:CD) [01:02:03:456]: Note: 1: 1310 2: synthetic.file";
    private static readonly Guid RollbackProduct = Guid.Parse("cf25d448-1309-41dd-af37-982dbceb96c0");
    private static readonly DateTimeOffset RollbackStart = new(2026, 11, 18, 10, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("CustomAction SyntheticAction returned actual error code 1310 (note: synthetic detail)")]
    [InlineData("MSI (c) (AB:CD) [01:02:03:456]: MainEngineThread is returning 1336")]
    [InlineData(Note1310)]
    [InlineData("DEBUG: Error 1336: Geçici dizin")]
    public void Utf16Log_FindsEnvironmentMarkers(string marker)
    {
        using var log = Utf16Log("Note: 1: 2205 2: synthetic\r\n" + marker);
        Assert.Equal(AgentUpdateMsiFailureKind.Environment, Classify(log));
        Assert.True(log.CanRead);
    }

    [Theory]
    [InlineData(1601)]
    [InlineData(1622)]
    [InlineData(1632)]
    public void PreTransactionExitCodes_LabelEnvironmentWithoutALog(int exitCode)
        => Assert.Equal(AgentUpdateMsiFailureKind.Environment, AgentUpdateMsiFailure.Classify(exitCode, null, null));

    [Fact]
    public void Busy1618_WinsOverEnvironmentAndHelperRollback()
    {
        using var log = Utf16Log(Note1310);
        Assert.Equal(AgentUpdateMsiFailureKind.Busy,
            AgentUpdateMsiFailure.Classify(1618, log, AgentInstallerHealthPhase.ServiceState));
        Assert.Equal(0, log.Position);
    }

    [Theory]
    [InlineData("grant_floor", "Terminal")]
    [InlineData("grant_version", "Terminal")]
    [InlineData("grant_product_code", "Terminal")]
    [InlineData("grant_msi_hash", "Terminal")]
    [InlineData("grant_expired", "Retry")]
    [InlineData("grant_boot_id", "Retry")]
    [InlineData("grant_attempt_id", "Retry")]
    [InlineData("grant_profile", "Alert")]
    [InlineData("grant_schema", "Alert")]
    [InlineData("grant_parse", "Alert")]
    [InlineData("grant_path", "Alert")]
    [InlineData("grant_consume", "Alert")]
    public void BoundRollbackGrantDenialPrecedesMsiLogAndUsesExactDisposition(string reason, string disposition)
    {
        using var fixture = new GrantResultFixture();
        fixture.Write(RollbackProduct, AgentUpdateRollbackGrantResult.Denied(reason), RollbackStart.AddSeconds(1));
        using var log = Utf16Log(Note1310);

        var (kind, refusal) = fixture.Classify(FatalMsiExit, log);

        Assert.Equal(AgentUpdateMsiFailureKind.GrantRefused, kind);
        Assert.NotNull(refusal);
        Assert.Equal(reason, refusal.ReasonCode);
        Assert.Equal(disposition, refusal.Disposition.ToString());
        Assert.Equal(0, log.Position);
    }

    [Theory]
    [InlineData("unknown_code", "\"grant_future\"")]
    [InlineData("non_string", "42")]
    [InlineData("missing_code", null)]
    public void BoundUnknownGrantDenialReturnsGenericAlertWithoutEchoingReason(string condition, string? reasonJson)
    {
        using var fixture = new GrantResultFixture();
        var reason = condition == "missing_code" ? "" : $",\"reason_code\":{reasonJson}";
        File.WriteAllText(fixture.ReceiptPath, $$"""{"result":"denied","utc":"2026-11-18T10:00:01Z"{{reason}}}""");
        using var log = Utf16Log(Note1310);

        var (kind, refusal) = fixture.Classify(FatalMsiExit, log);

        Assert.Equal(AgentUpdateMsiFailureKind.GrantRefused, kind);
        Assert.Equal(new AgentUpdateGrantRefusal("grant_unknown", AgentUpdateGrantRefusalDisposition.Alert), refusal);
        Assert.Equal(0, log.Position);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("wrong_product")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("non_utc")]
    [InlineData("admitted")]
    [InlineData("unsafe")]
    [InlineData("malformed")]
    public void UnboundGrantResultFallsBackToOrdinaryMsiClassification(string condition)
    {
        using var fixture = new GrantResultFixture();
        var denied = AgentUpdateRollbackGrantResult.Denied("grant_floor");
        var recordedUtc = condition switch
        {
            "stale" => RollbackStart.AddTicks(-1),
            "future" => RollbackStart.AddMinutes(2),
            "non_utc" => RollbackStart.AddSeconds(1).ToOffset(TimeSpan.FromHours(3)),
            _ => RollbackStart.AddSeconds(1),
        };
        if (condition == "malformed")
            File.WriteAllText(fixture.ReceiptPath, "{");
        else if (condition != "missing")
            fixture.Write(condition == "wrong_product" ? Guid.NewGuid() : RollbackProduct,
                condition == "admitted" ? AgentUpdateRollbackGrantResult.Accepted : denied, recordedUtc);
        using var log = Utf16Log(Note1310);

        var result = fixture.Classify(FatalMsiExit, log, trusted: condition != "unsafe");

        Assert.Equal((AgentUpdateMsiFailureKind.Environment, null), result);
    }

    [Fact]
    public void RollbackBusyNeverReadsGrantResultOrMsiLog()
    {
        using var fixture = new GrantResultFixture();
        fixture.Write(RollbackProduct, AgentUpdateRollbackGrantResult.Denied("grant_floor"), RollbackStart.AddSeconds(1));
        using var log = Utf16Log(Note1310);

        var result = fixture.Classify(1618, log);

        Assert.Equal((AgentUpdateMsiFailureKind.Busy, null), result);
        Assert.Equal(0, fixture.ValidationCount);
        Assert.Equal(0, log.Position);
    }

    [Fact]
    public void NonPipeRecordPlusLog1310_StillPins()
    {
        using var log = Utf16Log(Note1310);
        foreach (var phase in Enum.GetValues<AgentInstallerHealthPhase>())
        {
            log.Position = 0;
            var pin = AgentUpdateRollbackPolicy.NextFailedInstallSequence(4, AgentUpdateErrorCodes.MsiFailed, 7, phase);
            var expected = pin == 7 ? AgentUpdateMsiFailureKind.HealthRollback : AgentUpdateMsiFailureKind.Environment;
            Assert.Equal(expected, Classify(log, phase));
        }
    }

    [Theory]
    [InlineData("Note: 1: 1311 2: 1310")]
    [InlineData("DEBUG: Error 1335: 1336")]
    [InlineData("Note: 1: 2205 2: 1310")]
    [InlineData("Note: 1: 13100")]
    [InlineData("DEBUG: Error 13360: synthetic")]
    [InlineData("CustomAction SyntheticAction returned actual error code 112")]
    [InlineData("MainEngineThread is returning 39")]
    [InlineData("Property(S): SYNTHETIC = DEBUG: Error 1336: property data")]
    [InlineData("Action ended 01:02:03: SyntheticAction. Return value 3.")]
    public void UnlistedCodesAndEmbeddedNoise_LeaveGenericFailure(string line)
    {
        using var log = Utf16Log(line);
        Assert.Equal(AgentUpdateMsiFailureKind.InstallerFailed, Classify(log));
    }

    [Fact]
    public void MissingOrUnreadableLog_LeavesGenericFailureAndPreservesRollback()
    {
        using var log = new UnreadableLogStream();
        Assert.Equal(AgentUpdateMsiFailureKind.InstallerFailed, Classify(null));
        Assert.Equal(AgentUpdateMsiFailureKind.InstallerFailed, Classify(log));
        Assert.Equal(AgentUpdateMsiFailureKind.HealthRollback, Classify(null, AgentInstallerHealthPhase.ServiceState));
        Assert.Equal(AgentUpdateMsiFailureKind.HealthRollback, Classify(log, AgentInstallerHealthPhase.ServiceState));
    }

    [Theory]
    [InlineData("Note: 1: 1310\n", 14, AgentUpdateMsiFailureKind.Environment)]
    [InlineData("Note: 1: 13100\n", 13, AgentUpdateMsiFailureKind.InstallerFailed)]
    [InlineData("Note: 1: 1310\n", 0, AgentUpdateMsiFailureKind.InstallerFailed)]
    public void LogReader_StopsAt64MiBAndRejectsACutCode(
        string tail, int tailBytesInBudget, AgentUpdateMsiFailureKind expected)
    {
        const int budget = 64 * 1024 * 1024;
        using var log = new BoundaryLogStream(budget - tailBytesInBudget, tail);
        Assert.Equal(expected, Classify(log));
        Assert.Equal(budget, log.BytesRead);
    }

    [Fact]
    public void Updater_RecordsEnvironmentAsABoundLabelWithoutChangingPinOrCadence()
    {
        var root = ServerPackageStaticTests.FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(root, "src", "Cerberus.Agent.Updater", "Program.cs"));
        var classification = source.IndexOf("var isEnvironmentFailure =", StringComparison.Ordinal);
        Assert.True(classification >= 0);
        var writeStart = source.IndexOf("journalStore.ChangeAttempt(attemptId,", classification, StringComparison.Ordinal);
        Assert.True(writeStart >= 0);
        var writeEnd = source.IndexOf("WriteInstallerResult(installerResult, log)", writeStart, StringComparison.Ordinal);
        Assert.True(writeEnd >= 0);
        var write = source[writeStart..writeEnd];

        Assert.Contains("isEnvironmentFailure = installerResult.ErrorCode == AgentUpdateErrorCodes.MsiFailed &&", source[classification..writeStart]);
        Assert.Contains("ClassifyMsiFailure(exitCode, msiLogPath, rollbackPhase) == AgentUpdateMsiFailureKind.Environment", source[classification..writeStart]);
        Assert.Contains("FailureCode = isEnvironmentFailure ? AgentUpdateErrorCodes.MsiEnvironment : before.FailureCode", write);
        Assert.Contains("FailureAttemptId = isEnvironmentFailure ? attemptId : before.FailureAttemptId", write);
        Assert.Contains("FailureInstallerResultId = isEnvironmentFailure ? installerResult.ResultId : before.FailureInstallerResultId", write);
        Assert.Contains("InstallerResult = installerResult,", write);
        Assert.Contains("AgentUpdateRollbackPolicy.NextFailedInstallSequence(before.FailedInstallSequence,", write);
        Assert.Contains("installerResult.ErrorCode, plan.Sequence, rollbackPhase)", write);
        Assert.DoesNotContain("NextCheckUtc", write);
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed, AgentUpdateInstallerResult.FromMsiExitCode(FatalMsiExit, null, null).ErrorCode);
    }

    private static AgentUpdateMsiFailureKind Classify(Stream? log, AgentInstallerHealthPhase? phase = null)
        => AgentUpdateMsiFailure.Classify(FatalMsiExit, log, phase);

    private static MemoryStream Utf16Log(string text)
        => new([.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(text)], writable: false);

    private sealed class GrantResultFixture : IDisposable
    {
        private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("cerberus-grant-classifier-");
        private readonly string _transactions;

        public GrantResultFixture() => _transactions = _root.CreateSubdirectory("installer-transactions").FullName;

        public string ReceiptPath => Path.Combine(_transactions, RollbackProduct.ToString("N") + ".rollback-grant.json");
        public int ValidationCount { get; private set; }

        public void Write(Guid productCode, AgentUpdateRollbackGrantResult result, DateTimeOffset utc)
            => AgentUpdateRollbackGrant.WriteResultRecord(_root.FullName, _transactions, productCode, result, utc);

        public (AgentUpdateMsiFailureKind Kind, AgentUpdateGrantRefusal? GrantRefusal) Classify(
            int exitCode, Stream log, bool trusted = true)
            => AgentUpdateMsiFailure.ClassifyRollback(exitCode, log, _root.FullName, RollbackProduct, RollbackStart,
                RollbackStart.AddMinutes(1), (path, root, allowMissing) =>
                {
                    ValidationCount++;
                    Assert.Equal(ReceiptPath, path);
                    Assert.Equal(_root.FullName, root);
                    Assert.True(allowMissing);
                    if (!trusted)
                        throw new InvalidOperationException("Synthetic protected path refusal.");
                });

        public void Dispose() => _root.Delete(recursive: true);
    }

    private sealed class UnreadableLogStream : MemoryStream
    {
        public override int Read(Span<byte> buffer) => throw new IOException("Synthetic read failure.");
    }

    private sealed class BoundaryLogStream(int prefixLength, string tail) : MemoryStream
    {
        private readonly byte[] _tail = Encoding.ASCII.GetBytes(tail);

        public int BytesRead { get; private set; }
        public override bool CanSeek => false;

        public override int Read(Span<byte> buffer)
        {
            const int lineLength = 1024;
            var prefix = Math.Clamp(prefixLength - BytesRead, 0, buffer.Length);
            buffer[..prefix].Fill((byte)'x');
            for (var end = lineLength - 1 - BytesRead % lineLength; end < prefix; end += lineLength)
                buffer[end] = (byte)'\n';
            if (prefix > 0 && BytesRead + prefix == prefixLength)
                buffer[prefix - 1] = (byte)'\n';

            var tailOffset = Math.Max(0, BytesRead - prefixLength);
            var tailCount = Math.Min(buffer.Length - prefix, _tail.Length - tailOffset);
            _tail.AsSpan(tailOffset, tailCount).CopyTo(buffer[prefix..]);
            var read = prefix + tailCount;
            BytesRead += read;
            return read;
        }
    }
}
