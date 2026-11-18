using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using Xunit.Abstractions;

namespace Cerberus.Agent.Core.Tests;

[CollectionDefinition("TC1 exact native storage", DisableParallelization = true)]
public sealed class Tc1NativeStorageCollection { }

[Collection("TC1 exact native storage")]
public sealed class AgentUpdateStoppedRemovalNativeTests(ITestOutputHelper output)
{
    [AlreadyElevatedTc1Fact]
    public async Task Elevated_administrator_removes_only_the_two_SYSTEM_owned_cache_entries()
    {
        await Tc1RegressionFixture.Run(async tree =>
        {
            var root = tree.Start();
            var cache = tree.Directory(root, "token-cache", Tc1RegressionFixture.ProductionCacheSddl());
            const string systemOnly = "O:SYD:P(A;;FA;;;SY)";
            var primary = tree.File(cache, "access-token.v1.dpapi", systemOnly);
            var second = tree.File(cache, "secondary-access-token.v1.dpapi", systemOnly);
            var canary = tree.File(cache, "non-cache-canary.txt", systemOnly + "(A;;FR;;;BA)",
                "disposable non-cache canary"u8.ToArray());
            using var cacheHold = tree.OpenChecked(cache, StoppedRemovalNativeFile.ReadControl);
            var before = Observe();

            // Bind the exact production validator/child names to Temp. Never call the canonical
            // singleton's acquire delegate. This lease has no live credential-publication side effects.
            var constructor = typeof(AgentAccessTokenCache).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, [typeof(string), typeof(bool), typeof(bool)], modifiers: null)
                ?? throw new InvalidOperationException("The disposable canonical-validation fixture binding changed.");
            var instance = (AgentAccessTokenCache)constructor.Invoke([cache.Path, true, true]);
            using var access = new FixtureLease();
            ExceptionDispatchInfo? removal = null;
            Exception? presence = null;
            try
            {
                await AgentAccessTokenCache.ClearForStoppedRemovalAsync(canonical: true, AgentUpdateSecurity.IsLocalSystem,
                    AlreadyElevatedTc1FactAttribute.IsEligible,
                    _ => Task.FromResult<IDisposable?>(access.Acquire()),
                    () =>
                    {
                        Assert.True(access.Held);
                        instance.RemoveExactCacheFiles();
                    }, StoppedRemovalToken.RunAndVerifyRestoreOnly, CancellationToken.None);
            }
            catch (Exception error) { removal = ExceptionDispatchInfo.Capture(error); }

            try
            {
                // Read exact presence even when product removal throws.
                AgentUpdateStoragePrivilege.Run(() =>
                {
                    tree.ObservePresence(primary);
                    tree.ObservePresence(second);
                });
            }
            catch (Exception error) { presence = error; }
            if (removal is not null && presence is not null)
                throw new AggregateException("Stopped removal and the presence readback both failed.", removal.SourceException, presence);
            removal?.Throw();
            if (presence is not null) ExceptionDispatchInfo.Capture(presence).Throw();

            Assert.Equal(1, access.Acquisitions);
            Assert.False(access.Held);
            Assert.True(primary.Removed, "The exact primary cache file is still present or unreadable.");
            Assert.True(second.Removed, "The exact secondary cache file is still present or unreadable.");
            Assert.Equal(before, Observe());

            (string Directory, string Canary, string CanaryHash) Observe()
            {
                using var directory = tree.OpenChecked(cache, StoppedRemovalNativeFile.ReadControl);
                using var handle = tree.OpenChecked(canary, 0x80000000 | StoppedRemovalNativeFile.ReadControl);
                var canarySddl = StoppedRemovalNativeFile.Descriptor(handle);
                using var stream = new FileStream(handle, FileAccess.Read);
                return (StoppedRemovalNativeFile.Descriptor(directory), canarySddl, Convert.ToHexString(SHA256.HashData(stream)));
            }
        }, output.WriteLine);
    }

    private sealed class FixtureLease : IDisposable
    {
        internal bool Held { get; private set; }
        internal int Acquisitions { get; private set; }

        internal IDisposable Acquire()
        {
            if (Held) throw new InvalidOperationException("The fixture lease is already held.");
            Acquisitions++;
            Held = true;
            return this;
        }

        public void Dispose() => Held = false;
    }
}

internal sealed class AlreadyElevatedTc1FactAttribute : FactAttribute
{
    public AlreadyElevatedTc1FactAttribute()
    {
        if (!IsEligible()) Skip = "Requires an already-elevated non-SYSTEM Windows administrator.";
    }

    internal static bool IsEligible()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var actor = WindowsIdentity.GetCurrent();
        return !actor.IsSystem && new WindowsPrincipal(actor).IsInRole(WindowsBuiltInRole.Administrator)
            && ProcessTokenOwner.ReadElevation(actor.AccessToken);
    }
}

internal static class Tc1RegressionFixture
{
    internal static string ProductionCacheSddl()
        => AgentAccessTokenCache.CreateDirectorySecurity().GetSecurityDescriptorSddlForm(
            AccessControlSections.Owner | AccessControlSections.Access);

    internal static async Task Run(Func<StoppedRemovalFixture, Task> test, Action<string> output)
    {
        using var actor = WindowsIdentity.GetCurrent();
        using var ambient = WindowsIdentity.GetCurrent(ifImpersonating: true);
        Assert.Null(ambient);
        var processBefore = StoppedRemovalToken.Snapshot(actor.AccessToken);
        Assert.False(processBefore.BackupEnabled);
        var tree = new StoppedRemovalFixture((kind, data) => output(System.Text.Json.JsonSerializer.Serialize(new { kind, data })));
        ExceptionDispatchInfo? primary = null;
        Exception? cleanup = null;
        try { await test(tree); }
        catch (Exception error) { primary = ExceptionDispatchInfo.Capture(error); }
        finally
        {
            try { tree.Cleanup(); }
            catch (Exception error) { cleanup = error; }
        }

        try
        {
            using var remaining = WindowsIdentity.GetCurrent(ifImpersonating: true);
            Assert.Null(remaining);
            Assert.Equal(processBefore, StoppedRemovalToken.Snapshot(actor.AccessToken));
        }
        catch (Exception error)
        {
            cleanup = cleanup is null ? error : new AggregateException(cleanup, error);
        }

        if (primary is not null && cleanup is not null)
            throw new AggregateException("The test assertion and qualified fixture teardown both failed.", primary.SourceException, cleanup);
        primary?.Throw();
        if (cleanup is not null) ExceptionDispatchInfo.Capture(cleanup).Throw();
    }
}
