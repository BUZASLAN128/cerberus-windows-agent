using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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
        => Assert.False(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started, null, "1.2.3", "1.2.3"));

    [Fact]
    public void IsCurrentAttemptRecord_IncludesTheStartInstantAndExcludesOneTickBefore()
    {
        Assert.True(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started, Started, "1.2.3", "1.2.3"));
        Assert.True(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started.AddTicks(1), Started, "1.2.3", "1.2.3"));
        Assert.False(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started.AddTicks(-1), Started, "1.2.3", "1.2.3"));
    }

    [Theory]
    [InlineData("1.2.2")]
    [InlineData("1.2.3.0")]
    [InlineData("1.2.3 ")]
    [InlineData(null)]
    public void IsCurrentAttemptRecord_VersionMismatchOrMissingNeverBindsEvenWhenTheTimestampIsCurrent(string? recordVersion)
        => Assert.False(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started.AddMinutes(1), Started, recordVersion, "1.2.3"));

    [Fact]
    public void IsCurrentAttemptRecord_VersionComparisonIsOrdinal()
        => Assert.False(AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(Started, Started, "1.2.3-RC1", "1.2.3-rc1"));

    [Theory]
    [InlineData(7L, "msi_failed", 9L, AgentInstallerHealthPhase.Stability, 9L)]
    [InlineData(7L, "msi_failed", 9L, AgentInstallerHealthPhase.ResponseVersion, 9L)]
    [InlineData(7L, "msi_failed", 5L, AgentInstallerHealthPhase.Stability, 7L)]
    [InlineData(7L, "msi_failed", 7L, AgentInstallerHealthPhase.Stability, 7L)]
    [InlineData(0L, "msi_failed", 5L, AgentInstallerHealthPhase.ServiceState, 5L)]
    [InlineData(7L, "msi_failed", 9L, AgentInstallerHealthPhase.BackendContact, 7L)]
    [InlineData(0L, "msi_failed", 9L, AgentInstallerHealthPhase.BackendContact, 0L)]
    [InlineData(7L, "msi_failed", 9L, null, 7L)]
    [InlineData(0L, "msi_failed", 9L, null, 0L)]
    [InlineData(7L, "download_failed", 9L, AgentInstallerHealthPhase.Stability, 7L)]
    [InlineData(7L, null, 9L, AgentInstallerHealthPhase.Stability, 7L)]
    public void NextFailedInstallSequence_PinsOnlyAMsiRollbackWithAKnownPinningPhaseAndNeverLowers(
        long previous, string? errorCode, long plan, AgentInstallerHealthPhase? phase, long expected)
        => Assert.Equal(expected, AgentUpdateRollbackPolicy.NextFailedInstallSequence(previous, errorCode, plan, phase));

    [Fact]
    public void NextFailedInstallSequence_PipePhasesAndNoAnswerStabilityNeverPinAndEveryOtherPhaseDoes()
    {
        // A local user can hold or squat the control pipe, so those phases retry at the next check; a new phase must be classified here on purpose.
        var unpinned = new[]
        {
            AgentInstallerHealthPhase.BackendContact, AgentInstallerHealthPhase.PipeConnect, AgentInstallerHealthPhase.PipeAuthority,
            AgentInstallerHealthPhase.StatusRequest, AgentInstallerHealthPhase.StatusResponse, AgentInstallerHealthPhase.StabilityNoAnswer,
        };
        foreach (var phase in Enum.GetValues<AgentInstallerHealthPhase>())
            Assert.Equal(unpinned.Contains(phase) ? 3L : 7L, AgentUpdateRollbackPolicy.NextFailedInstallSequence(3, "msi_failed", 7, phase));
    }

    [Fact]
    public void ParsePhase_RoundTripsEveryPhaseFromItsSnakeCaseText()
    {
        foreach (var phase in Enum.GetValues<AgentInstallerHealthPhase>())
            Assert.Equal(phase, AgentUpdateRollbackPolicy.ParsePhase(System.Text.Json.JsonNamingPolicy.SnakeCaseLower.ConvertName(phase.ToString())));
        Assert.Equal(AgentInstallerHealthPhase.BackendContact, AgentUpdateRollbackPolicy.ParsePhase("backend_contact"));
        Assert.Equal(AgentInstallerHealthPhase.StabilityNoAnswer, AgentUpdateRollbackPolicy.ParsePhase("stability_no_answer"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unknown_phase")]
    [InlineData("BackendContact")]
    [InlineData("BACKEND_CONTACT")]
    public void ParsePhase_UnknownOrDifferentlyCasedTextYieldsNull(string? text)
        => Assert.Null(AgentUpdateRollbackPolicy.ParsePhase(text));

    private const string Runtime = @"C:\Program Files\Cerberus\Agent";

    private const string ServiceExe = Runtime + @"\Cerberus.Agent.Service.exe";
    private const string ServiceDll = Runtime + @"\Cerberus.Agent.Service.dll";

    [Theory]
    [InlineData(AgentInstallerHealthPhase.ServiceExecutableHash, ServiceExe, true)]
    [InlineData(AgentInstallerHealthPhase.ServiceExecutableHash, ServiceDll, false)]
    [InlineData(AgentInstallerHealthPhase.ServiceAssemblyHash, ServiceDll, true)]
    [InlineData(AgentInstallerHealthPhase.ServiceAssemblyHash, ServiceExe, false)]
    public void PendingRebootExcuses_EachHashPhaseIsExcusedOnlyByItsOwnBinary(AgentInstallerHealthPhase phase, string entry, bool expected)
        => Assert.Equal(expected, AgentUpdateRollbackPolicy.PendingRebootExcuses(phase, false, [entry], Runtime));

    [Theory]
    [InlineData(AgentInstallerHealthPhase.ServiceExecutableHash)]
    [InlineData(AgentInstallerHealthPhase.ServiceAssemblyHash)]
    public void PendingRebootExcuses_BothBinariesQueuedExcuseBothHashPhases(AgentInstallerHealthPhase phase)
        => Assert.True(AgentUpdateRollbackPolicy.PendingRebootExcuses(phase, false, [ServiceDll, ServiceExe], Runtime));

    [Fact]
    public void PendingRebootExcuses_NoOtherPhaseIsExcusedAndCancellationNeverIs()
    {
        string[] pending = [ServiceExe, ServiceDll];
        var allowed = new[]
        {
            AgentInstallerHealthPhase.ServiceExecutableHash, AgentInstallerHealthPhase.ServiceAssemblyHash,
        };
        foreach (var phase in Enum.GetValues<AgentInstallerHealthPhase>())
        {
            Assert.Equal(allowed.Contains(phase), AgentUpdateRollbackPolicy.PendingRebootExcuses(phase, false, pending, Runtime));
            Assert.False(AgentUpdateRollbackPolicy.PendingRebootExcuses(phase, true, pending, Runtime));
        }
    }

    [Theory]
    [InlineData(@"C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.exe", true)]
    [InlineData(@"C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.dll", true)]
    [InlineData(@"c:\program files\cerberus\agent\CERBERUS.AGENT.SERVICE.DLL", true)]
    [InlineData(@"\??\C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.exe", true)]
    [InlineData(@"!\??\C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.dll", true)]
    [InlineData(@"!C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.exe", true)]
    [InlineData(@"C:\Program Files\Cerberus\Agent\Cerberus.Agent.Updater.exe", false)]
    [InlineData(@"C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.pdb", false)]
    [InlineData(@"C:\Program Files\Cerberus\Agent\Cerberus.Agent.Service.exe.bak", false)]
    [InlineData(@"C:\Program Files\Cerberus\Agent\sub\Cerberus.Agent.Service.exe", false)]
    [InlineData(@"C:\Program Files\Cerberus\Other\Cerberus.Agent.Service.exe", false)]
    [InlineData(@"C:\Program Files\Cerberus\Agent2\Cerberus.Agent.Service.exe", false)]
    [InlineData(@"C:\Program Files\Cerberus\Agent", false)]
    [InlineData(@"C:\Program Files\Cerberus\Agent\", false)]
    [InlineData(@"", false)]
    public void PendingRebootExcuses_RequiresAnExactServiceBinaryEntryUnderTheRuntime(string entry, bool expected)
    {
        var phase = entry.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? AgentInstallerHealthPhase.ServiceAssemblyHash : AgentInstallerHealthPhase.ServiceExecutableHash;
        Assert.Equal(expected, AgentUpdateRollbackPolicy.PendingRebootExcuses(phase, false, [entry], Runtime));
    }

    [Fact]
    public void PendingRebootExcuses_OneMatchingEntryAmongOthersIsEnoughAndAnEmptyListIsNot()
    {
        Assert.True(AgentUpdateRollbackPolicy.PendingRebootExcuses(AgentInstallerHealthPhase.ServiceAssemblyHash, false,
            [@"C:\Windows\x.dll", ServiceDll], Runtime));
        Assert.False(AgentUpdateRollbackPolicy.PendingRebootExcuses(AgentInstallerHealthPhase.ServiceExecutableHash, false, [], Runtime));
    }

    [Fact]
    public void InstallerPackage_ServerHealthGateAndRollbackStartAreWiredAsTheRollbackContractRequires()
    {
        var package = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "Cerberus.Agent.Installer", "Package.wxs"));

        var health = CustomActionElement(package, "CheckServerAgentHealth");
        Assert.Contains("Execute=\"deferred\"", health);
        Assert.Contains("Impersonate=\"no\"", health);
        Assert.Contains("Return=\"check\"", health);
        Assert.Matches("ExeCommand='health [^']*\"\\[CERBERUS_UPDATE_REQUIRE_BACKEND\\]\"'", health);
        Assert.Equal(7, Regex.Matches(Regex.Match(health, "ExeCommand='([^']*)'").Groups[1].Value, "\"[^\"]*\"").Count + 1);

        var rollback = CustomActionElement(package, "EnsureServerAgentRunningOnRollback");
        Assert.Contains("Execute=\"rollback\"", rollback);
        Assert.Contains("Impersonate=\"no\"", rollback);
        Assert.Contains("Return=\"ignore\"", rollback);
        Assert.Matches("ExeCommand='ensure-running ", rollback);

        Assert.Matches(@"<Custom Action=""CheckServerAgentHealth"" After=""StartServices"" Condition=""NOT REMOVE AND WIX_UPGRADE_DETECTED"" />", package);
        Assert.Matches(@"<Custom Action=""EnsureServerAgentRunningOnRollback"" After=""StopServices"" Condition=""NOT REMOVE AND WIX_UPGRADE_DETECTED"" />", package);
        Assert.Matches(@"<Property Id=""CERBERUS_UPDATE_REQUIRE_BACKEND"" Secure=""yes"" />", package);

        // All four live inside a server-profile block, never the desktop one.
        foreach (var marker in new[] { "Id=\"CheckServerAgentHealth\"", "Id=\"EnsureServerAgentRunningOnRollback\"",
            "Action=\"CheckServerAgentHealth\"", "Action=\"EnsureServerAgentRunningOnRollback\"", "Id=\"CERBERUS_UPDATE_REQUIRE_BACKEND\"" })
            Assert.True(InServerBlock(package, package.IndexOf(marker, StringComparison.Ordinal)), marker + " is not in the server profile block.");
    }

    private static string CustomActionElement(string package, string id)
    {
        var match = Regex.Match(package, "<CustomAction\\s+Id=\"" + id + "\"[^>]*?/>", RegexOptions.Singleline);
        Assert.True(match.Success, id + " CustomAction was not found.");
        return match.Value;
    }

    private static bool InServerBlock(string package, int index)
    {
        Assert.True(index >= 0);
        var directive = Regex.Matches(package[..index], @"<\?(if|else|endif)[^?]*\?>").LastOrDefault();
        return directive is not null && directive.Value.Contains("AgentBuildProfile) = server", StringComparison.Ordinal);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx"))) return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate cerberus-windows-agent repository root.");
    }

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
