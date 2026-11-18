using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed class LkgPromotionLogTests
{
    [Fact]
    public void PromotionFailureEmitsTheExactCodeAcceptedByTheHostLog()
    {
        string? written = null;
        LkgPromotion.LogFailure(code =>
        {
            Assert.True(AgentUpdateErrorCodes.IsCode(code));
            written = code;
        });

        Assert.Equal("lkg_promotion_failed", written);
    }
}
