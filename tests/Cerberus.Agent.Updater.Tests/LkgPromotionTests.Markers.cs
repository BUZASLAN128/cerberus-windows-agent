using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed partial class LkgPromotionTests
{
    [Theory]
    [InlineData("move")]
    [InlineData("identical")]
    [InlineData("different")]
    public void NewPromotionArchivesOnlyExactTrustedMarkerBytesWithoutReplacingAnEntry(string caseName)
    {
        var journal = JournalWithPassedWatch();
        _store.WritePromotion(OlderMarker());
        var exact = File.ReadAllBytes(MarkerPath);
        var stalePath = Path.Combine(_store.Root, "promote.stale-" + Hash(MarkerPath) + ".json");
        var old = CanonicalHashes();
        if (caseName == "identical") File.WriteAllBytes(stalePath, exact);
        if (caseName == "different") File.WriteAllText(stalePath, "different protected fixture bytes");

        if (caseName == "different")
        {
            for (var i = 0; i < 2; i++)
                Assert.False(Create().Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
            Assert.Equal(exact, File.ReadAllBytes(MarkerPath));
            Assert.Equal("different protected fixture bytes", File.ReadAllText(stalePath));
            Assert.Equal(old, CanonicalHashes());
            Assert.Equal(AgentUpdateWatchJournal.CommittedWatch, journal.Read().Phase);
            Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().AlertCode);
            Assert.Equal("earlier-attempt", journal.Read().AlertAttemptId);
            Assert.Single(_logs, code => code == AgentUpdateWatchJournal.LkgPromotionFailed);
            return;
        }

        Assert.True(Create().Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Null(_store.ReadPromotion());
        LkgPromotion.CleanupRetired(_store, AgentUpdateSecurity.ValidateTrustedPath);
        Assert.Equal(exact, File.ReadAllBytes(stalePath));
        Assert.Equal(Path.GetFileName(stalePath), Path.GetFileName(Assert.Single(Directory.EnumerateFiles(_store.Root, "promote.stale-*"))));
    }

    [Theory]
    [InlineData("reparse")]
    [InlineData("hardlink")]
    public async Task MarkerSlotRefusesReparseAndHardLinkWithoutMovingOrDeleting(string link)
    {
        var journal = JournalWithPassedWatch();
        var target = Path.Combine(_temp.FullName, "marker-target");
        var isDirectory = link == "reparse";
        if (isDirectory) Directory.CreateDirectory(target);
        else File.WriteAllText(target, "protected fixture hardlink target");
        using var mklink = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true,
            ArgumentList = { "/d", "/c", "mklink", isDirectory ? "/j" : "/h", MarkerPath, target },
        })!;
        await mklink.WaitForExitAsync();
        Assert.Equal(0, mklink.ExitCode);
        try
        {
            Assert.False(Create().Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
            Assert.Empty(Directory.EnumerateFileSystemEntries(_store.Root, "promote.stale-*"));
            Assert.True(isDirectory ? Directory.Exists(MarkerPath) : File.Exists(MarkerPath));
            if (!isDirectory) Assert.Equal("protected fixture hardlink target", File.ReadAllText(target));
            Assert.Equal(OldVersion, ReadRecordVersion());
        }
        finally
        {
            if (isDirectory && Directory.Exists(MarkerPath)) Directory.Delete(MarkerPath);
        }
    }

    [Theory]
    [InlineData("legacy")]
    [InlineData("stale")]
    [InlineData("malformed")]
    public void NonOwnMarkerDispatchesRollbackAndRetainsExactMarkerBytes(string state)
    {
        var journal = JournalWithPassedWatch();
        journal.Change(j => j with
        {
            Phase = AgentUpdateWatchJournal.RollingBack, RollbackAttemptId = "rollback-attempt",
            RollbackStartedUtc = Now.AddHours(-1),
        });
        if (state == "malformed") File.WriteAllText(MarkerPath, "{invalid fixture marker");
        else _store.WritePromotion(state == "legacy" ? OlderMarker() with { AttemptId = Attempt, StageDir = "stage-" + Attempt }
            : OlderMarker() with { PivotStarted = true, RetryCount = AgentUpdateLkgPromotion.MaxRetries });
        AgentUpdateWatchStore.Write(_store.UpdatesRoot, _watch with { Outcome = AgentUpdateWatchOutcomes.RollbackPending });
        var marker = Hash(MarkerPath);
        var floor = Hash(FloorPath);
        var before = CanonicalHashes();
        var calls = 0;
        Assert.Equal(0, Start(journal, "--scm-failure", Create(), rollback: (context, watch) =>
        {
            calls++;
            Assert.True(LkgRollback.SameAuthority(journal.Read(), context.Journal!, watch.AttemptId));
        }));
        Assert.Equal(1, calls);
        Assert.Equal(marker, Hash(MarkerPath));
        Assert.Equal(before, CanonicalHashes());
        Assert.Equal(floor, Hash(FloorPath));
        Assert.Equal(state == "malformed" ? null : state == "legacy" ? Attempt : "earlier-attempt", journal.Read().AlertAttemptId);
    }

    [Fact]
    public void LegacyMarkerCannotBeReusedAsANewPromotionOfTheSameWatch()
    {
        var journal = JournalWithPassedWatch();
        _store.WritePromotion(OlderMarker() with { AttemptId = Attempt, StageDir = "stage-" + Attempt });
        var exact = Hash(MarkerPath);
        var canonical = CanonicalHashes();

        Assert.Equal(0, Start(journal, "--watch", Create()));
        Assert.Equal(exact, Hash(MarkerPath));
        Assert.Equal(canonical, CanonicalHashes());
        Assert.Equal(AgentUpdateWatchJournal.CommittedWatch, journal.Read().Phase);
        Assert.Equal(Attempt, journal.Read().AlertAttemptId);
        Assert.Empty(Directory.EnumerateFiles(_store.Root, "promote.stale-*"));
    }

    [Theory]
    [InlineData("missing-mode", false)]
    [InlineData("wrong-nonce", false)]
    [InlineData("below", false)]
    [InlineData("above", true)]
    public void PromotionUsesRealProbeProcessOutputAndProtocolChecks(string fixture, bool accepted)
    {
        var script = Path.Combine(_temp.FullName, "fixture-probe.ps1");
        File.WriteAllText(script, "param($Payload)\n[Console]::WriteLine([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)))");
        var output = JsonSerializer.Serialize(new
        {
            schema = LkgProbe.Schema, nonce = fixture == "wrong-nonce" ? "wrong" : "fixture-nonce",
            version = Version, modes = fixture == "missing-mode" ? new[] { "attempt", "watch", "probe" } :
                new[] { "attempt", "watch", "scm-failure", "probe" },
            contract = fixture == "below" ? 1 : 3,
        });
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true,
            ArgumentList = { "-NoProfile", "-NonInteractive", "-File", script, Convert.ToBase64String(Encoding.UTF8.GetBytes(output)) },
        };
        var journal = JournalWithPassedWatch();
        var before = CanonicalHashes();
        var promotion = Create(probe: (_, version) => LkgProbe.Run(start, "fixture-nonce", version, 2, TimeSpan.FromSeconds(10)));
        Assert.Equal(accepted, promotion.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
        if (accepted) Assert.Equal(Version, ReadRecordVersion());
        else
        {
            Assert.Equal(before, CanonicalHashes());
            Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().FailureCode);
        }
        Assert.Null(_store.ReadPromotion());
    }

    private AgentUpdateLkgPromotion OlderMarker() => new("earlier-attempt", Version, _plan.Sha256,
        Hash(_store.HostPath), Hash(_store.HostPath), _plan.ManifestDigest!, "stage-earlier-attempt");
}
