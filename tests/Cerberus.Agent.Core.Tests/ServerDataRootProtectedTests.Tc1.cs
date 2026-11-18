#if CERBERUS_SERVER_PROFILE
using System.Runtime.ExceptionServices;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerDataRootProtectedTests
{
    [AlreadyElevatedTc1Fact]
    public async Task Elevated_administrator_can_verify_the_system_owned_cache_directory_without_listing_it()
    {
        // The production server verifier pins its own process default owner. The test collection
        // must be exclusive and restore the isolated testhost's original owner on any exit.
        var owner = ProcessTokenOwner.Capture();
        Exception? primary = null;
        Exception? ownerRestore = null;
        try
        {
            await Tc1RegressionFixture.Run(tree =>
            {
                var scaffold = tree.Start();
                var data = tree.Directory(scaffold, "data", "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
                Assert.True(ServerDataRoot.EnsureProtected(data.Path));
                var cache = tree.Directory(data, "token-cache", Tc1RegressionFixture.ProductionCacheSddl());

                using var beforeHandle = tree.HoldCacheDirectory(cache);
                var before = StoppedRemovalNativeFile.Descriptor(beforeHandle);
                Assert.True(ServerDataRoot.EnsureProtected(data.Path));
                using var afterHandle = tree.HoldCacheDirectory(cache);
                Assert.Equal(before, StoppedRemovalNativeFile.Descriptor(afterHandle));
                Assert.Throws<UnauthorizedAccessException>(() => new DirectoryInfo(cache.Path).GetFileSystemInfos());
                return Task.CompletedTask;
            }, _tc1Output.WriteLine);
        }
        catch (Exception error) { primary = error; }
        finally
        {
            try { owner.Dispose(); }
            catch (Exception error) { ownerRestore = error; }
        }

        if (primary is not null && ownerRestore is not null)
            throw new AggregateException("The T1 result and testhost token-owner restoration both failed.", primary, ownerRestore);
        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
        if (ownerRestore is not null) ExceptionDispatchInfo.Capture(ownerRestore).Throw();
    }
}
#endif
