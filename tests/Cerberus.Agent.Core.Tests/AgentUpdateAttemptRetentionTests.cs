using System.Diagnostics;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateAttemptRetentionTests
{
    [Fact]
    public void PrunePayloads_RemovesOnlyInstallerAndRunnerCopiesOfOlderFinishedAttempts()
    {
        var root = NewRoot();
        var oldest = CreateAttempt(root, "a1", DateTime.UtcNow.AddDays(-4));
        var older = CreateAttempt(root, "a2", DateTime.UtcNow.AddDays(-3));
        var newer = CreateAttempt(root, "a3", DateTime.UtcNow.AddDays(-2));
        var newest = CreateAttempt(root, "a4", DateTime.UtcNow.AddDays(-1));
        var active = CreateAttempt(root, "a0", DateTime.UtcNow.AddDays(-10));

        var pruned = AgentUpdateAttemptRetention.PrunePayloads(root,
            new AgentUpdateJournal { AttemptId = "a0", Phase = AgentUpdateStates.Installed });

        Assert.Equal(2, pruned);
        foreach (var directory in new[] { oldest, older })
        {
            Assert.False(File.Exists(Path.Combine(directory, AgentUpdateSecurity.ArtifactFileName)));
            Assert.False(File.Exists(Path.Combine(directory, "runner", "Cerberus.Agent.Updater.exe")));
            Assert.False(Directory.Exists(Path.Combine(directory, "runner", "sub")));
            Assert.True(File.Exists(Path.Combine(directory, "runner", "inventory.json")));
            Assert.True(File.Exists(Path.Combine(directory, AgentUpdateSecurity.PlanFileName)));
            Assert.True(File.Exists(Path.Combine(directory, "bits-job.json")));
            Assert.True(File.Exists(Path.Combine(directory, ".attempt")));
        }
        foreach (var directory in new[] { newer, newest, active })
            AssertPayloadKept(directory);

        Assert.Equal(0, AgentUpdateAttemptRetention.PrunePayloads(root,
            new AgentUpdateJournal { AttemptId = "a0", Phase = AgentUpdateStates.Installed }));
    }

    [Fact]
    public void PrunePayloads_DoesNothingWhileAnAttemptIsUnfinished()
    {
        var root = NewRoot();
        var first = CreateAttempt(root, "a1", DateTime.UtcNow.AddDays(-5));
        CreateAttempt(root, "a2", DateTime.UtcNow.AddDays(-4));
        CreateAttempt(root, "a3", DateTime.UtcNow.AddDays(-3));
        CreateAttempt(root, "a4", DateTime.UtcNow.AddDays(-2));

        Assert.Equal(0, AgentUpdateAttemptRetention.PrunePayloads(root,
            new AgentUpdateJournal { AttemptId = "a4", Phase = AgentUpdateStates.Downloading }));
        AssertPayloadKept(first);
    }

    [Fact]
    public void PrunePayloads_NeverThrowsIntoTheUpdateTick()
        => Assert.Equal(0, AgentUpdateAttemptRetention.PrunePayloads("", new AgentUpdateJournal()));

    [Fact]
    public void PrunePayloads_NeverFollowsALinkOutOfTheRunnerCopy()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var root = NewRoot();
        var outside = Path.Combine(NewRoot(), "outside");
        Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(outside, "keep.txt"), "keep");
        var oldest = CreateAttempt(root, "a1", DateTime.UtcNow.AddDays(-3));
        CreateAttempt(root, "a2", DateTime.UtcNow.AddDays(-2));
        CreateAttempt(root, "a3", DateTime.UtcNow.AddDays(-1));
        var junction = Path.Combine(oldest, "runner", "linked");
        using (var mklink = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{junction}\" \"{outside}\"")
               { CreateNoWindow = true, UseShellExecute = false })!)
            mklink.WaitForExit();
        Assert.True(Directory.Exists(junction));

        Assert.Equal(1, AgentUpdateAttemptRetention.PrunePayloads(root, new AgentUpdateJournal()));

        Assert.True(File.Exists(Path.Combine(outside, "keep.txt")));
        Assert.False(File.Exists(Path.Combine(oldest, AgentUpdateSecurity.ArtifactFileName)));
    }

    private static void AssertPayloadKept(string directory)
    {
        Assert.True(File.Exists(Path.Combine(directory, AgentUpdateSecurity.ArtifactFileName)));
        Assert.True(File.Exists(Path.Combine(directory, "runner", "Cerberus.Agent.Updater.exe")));
        Assert.True(File.Exists(Path.Combine(directory, "runner", "sub", "payload.dll")));
    }

    private static string CreateAttempt(string root, string id, DateTime createdUtc)
    {
        var directory = Path.Combine(root, "attempts", AgentUpdateSecurity.AttemptDirectoryPrefix + id);
        Directory.CreateDirectory(Path.Combine(directory, "runner", "sub"));
        File.WriteAllText(Path.Combine(directory, ".attempt"), id);
        File.WriteAllText(Path.Combine(directory, AgentUpdateSecurity.ArtifactFileName), "msi");
        File.WriteAllText(Path.Combine(directory, AgentUpdateSecurity.PlanFileName), "{}");
        File.WriteAllText(Path.Combine(directory, "bits-job.json"), "{}");
        File.WriteAllText(Path.Combine(directory, "runner", "Cerberus.Agent.Updater.exe"), "exe");
        File.WriteAllText(Path.Combine(directory, "runner", "inventory.json"), "{}");
        File.WriteAllText(Path.Combine(directory, "runner", "sub", "payload.dll"), "dll");
        Directory.SetCreationTimeUtc(directory, createdUtc);
        return directory;
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-retention-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
