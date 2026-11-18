using Cerberus.Agent.App.Actions;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentAccessTokenRemovalTests
{
    [Fact]
    public void StoppedFileOpenRequestsOnlyDeleteAndSynchronize()
    {
        var security = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.Security");
        var removal = File.ReadAllText(Path.Combine(security, "AgentAccessTokenCache.StoppedRemoval.cs"));
        var cache = File.ReadAllText(Path.Combine(security, "AgentAccessTokenCache.cs"));

        Assert.Contains("StoppedFileDeleteAccess = 0x00110000;", removal, StringComparison.Ordinal);
        Assert.Contains("StoppedFileOpenOptions = 0x00204060;", removal, StringComparison.Ordinal);
        Assert.Contains("FileOpen = 1;", removal, StringComparison.Ordinal);
        Assert.Matches(@"NtCreateFile\(out var handle, StoppedFileDeleteAccess, ref attributes, out _,\s*IntPtr\.Zero, 0, FileShare\.Read \| FileShare\.Write, FileOpen, StoppedFileOpenOptions, IntPtr\.Zero, 0\)", removal);
        Assert.Contains("using var handle = OpenStoppedCacheEntry(path);", cache, StringComparison.Ordinal);
        Assert.Contains("OpenForRemoval(_directory, ReadControl, allowMissing: true)", cache, StringComparison.Ordinal);
        Assert.DoesNotContain("SeBackupPrivilege", removal, StringComparison.Ordinal);
    }


    [Fact]
    public void CompiledMachineStateClearBindsTheExactStoppedCacheRemoval()
    {
        // Inspect the production binding without calling SCM or touching the machine store.
        var entry = typeof(AgentServiceLocalState).GetMethod(nameof(AgentServiceLocalState.ClearMachineStateAsync),
            [typeof(CancellationToken)])!;
        var removal = typeof(AgentAccessTokenCache).GetMethod(nameof(AgentAccessTokenCache.ClearForStoppedRemovalAsync),
            [typeof(Action<Action>), typeof(CancellationToken)])!;
        var il = entry.GetMethodBody()!.GetILAsByteArray()!;
        Assert.Contains(Enumerable.Range(0, il.Length - 5), offset => il[offset] == 0xfe && il[offset + 1] == 0x06 &&
            entry.Module.ResolveMethod(BitConverter.ToInt32(il, offset + 2)) == removal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StoppedMachineCleanupFinishesBothExistingClearsBeforeOptionalCache(bool failCache)
    {
        var order = new List<string>();
        var restore = new Action<Action>(action => { order.Add("restore"); action(); });
        Task Run() => AgentServiceLocalState.ClearMachineStateAsync(default, () => order.Add("stopped"),
            () => order.Add("quiesce"), _ =>
            {
                order.Add("credentials");
                return Task.CompletedTask;
            }, () => order.Add("local"),
            (runWithRestore, _) =>
            {
                Assert.Same(restore, runWithRestore);
                runWithRestore(() => order.Add("cache"));
                if (failCache) throw new UnauthorizedAccessException("Fixture cache cannot be removed.");
                return Task.CompletedTask;
            }, restore);

        if (failCache) await Assert.ThrowsAsync<UnauthorizedAccessException>(Run);
        else await Run();
        Assert.Equal(["stopped", "quiesce", "credentials", "local", "restore", "cache"], order);
    }

    [Theory]
    [InlineData("noncanonical")]
    [InlineData("system")]
    [InlineData("not-admin")]
    [InlineData("canceled")]
    [InlineData("lock-denied")]
    [InlineData("allowed")]
    public async Task StoppedRemovalRespectsCacheAuthorityPublicationAccessAndCancellation(string branch)
    {
        var order = new List<string>();
        using var cancellation = new CancellationTokenSource();
        Task Run() => AgentAccessTokenCache.ClearForStoppedRemovalAsync(branch != "noncanonical",
            () => branch == "system", () => branch != "not-admin", token =>
            {
                Assert.Equal(cancellation.Token, token);
                order.Add("lock");
                if (branch == "lock-denied") throw new UnauthorizedAccessException("Fixture lock refused.");
                if (branch == "canceled") cancellation.Cancel();
                return Task.FromResult<IDisposable?>(new Access(order));
            }, () => order.Add("remove"), action =>
            {
                order.Add("privilege");
                action();
            }, cancellation.Token);

        if (branch is "not-admin" or "lock-denied")
            await Assert.ThrowsAsync<UnauthorizedAccessException>(Run);
        else if (branch == "canceled")
            await Assert.ThrowsAnyAsync<OperationCanceledException>(Run);
        else
            await Run();

        string[] expected = branch switch
        {
            "allowed" => ["lock", "privilege", "remove", "release"],
            "canceled" => ["lock", "release"],
            "lock-denied" => ["lock"],
            _ => Array.Empty<string>(),
        };
        Assert.Equal(expected, order);
    }

    [Fact]
    public async Task PublicRemovalForNoncanonicalCacheDoesNotEnterPrivilege()
    {
        var isolated = Directory.CreateTempSubdirectory("cerberus-removal-fixture-");
        try
        {
            var cache = new AgentAccessTokenCache(Path.Combine(isolated.FullName, "token-cache"), production: false);
            await cache.ClearForStoppedRemovalAsync(_ => throw new Xunit.Sdk.XunitException("Noncanonical cache gained removal privilege"), default);
            Assert.Empty(isolated.GetFileSystemInfos());
        }
        finally { isolated.Delete(recursive: true); }
    }

    private sealed class Access(List<string> order) : IDisposable
    {
        public void Dispose() => order.Add("release");
    }
}
