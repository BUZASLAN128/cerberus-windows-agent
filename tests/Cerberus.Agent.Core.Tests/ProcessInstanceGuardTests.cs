using Cerberus.Agent.App;
namespace Cerberus.Agent.Core.Tests;

public sealed class ProcessInstanceGuardTests
{
    [Fact]
    public void TryAcquireRejectsSecondOwnerForSameMutex()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var mutexName = $@"Local\CerberusAgent.Tests.{suffix}";
        var pipeName = $"CerberusAgent.Tests.{suffix}";

        using var firstReady = new ManualResetEventSlim(false);
        using var releaseFirst = new ManualResetEventSlim(false);
        Exception? firstOwnerException = null;

        var firstOwnerThread = new Thread(() =>
        {
            try
            {
                Assert.True(ProcessInstanceGuard.TryAcquire(mutexName, pipeName, null, out var first));
                using (first)
                {
                    firstReady.Set();
                    releaseFirst.Wait();
                }
            }
            catch (Exception ex)
            {
                firstOwnerException = ex;
                firstReady.Set();
            }
        });

        firstOwnerThread.Start();
        Assert.True(firstReady.Wait(TimeSpan.FromSeconds(5)));
        Assert.Null(firstOwnerException);

        try
        {
            Assert.False(ProcessInstanceGuard.TryAcquire(mutexName, pipeName, null, out var second));
            Assert.Null(second);
        }
        finally
        {
            releaseFirst.Set();
            Assert.True(firstOwnerThread.Join(TimeSpan.FromSeconds(5)));
        }

        Assert.Null(firstOwnerException);
    }
}
