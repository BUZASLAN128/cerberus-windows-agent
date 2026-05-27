using Cerberus.Agent.App;
using System.Threading.Tasks;

namespace Cerberus.Agent.Core.Tests;

public sealed class ProcessInstanceGuardTests
{
    [Fact]
    public async Task TryAcquireRejectsSecondOwnerForSameMutex()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var mutexName = $@"Local\CerberusAgent.Tests.{suffix}";
        var pipeName = $"CerberusAgent.Tests.{suffix}";

        Assert.True(ProcessInstanceGuard.TryAcquire(mutexName, pipeName, null, out var first));
        using (first)
        {
            var secondThreadResult = await Task.Run(() =>
            {
                var acquired = ProcessInstanceGuard.TryAcquire(mutexName, pipeName, null, out var second);
                return (acquired, second);
            });

            Assert.False(secondThreadResult.acquired);
            Assert.Null(secondThreadResult.second);
        }
    }
}
